import os
import time
import json
import signal
import logging
import subprocess
import shutil
from typing import List, Dict, Optional

from core.tracer.ebpf_engine import EBPFTracer
from core.fuzzing.gui.xvfb_display import XvfbDisplay
from core.metadata.extractor import MetadataExtractor
from core.fuzzing.ipc import FeedbackServer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Orchestrator")

class ArtifactDiscoverySession:
    def __init__(self, 
                 target_cmd: List[str], 
                 app_name: str,
                 duration: int = 60, 
                 output_dir: str = "./experiment_data"):
        
        self.target_cmd = target_cmd
        self.app_name = app_name
        self.duration = duration
        self.output_dir = os.path.join(output_dir, f"{app_name}_{int(time.time())}")
        self.chrome_user_dir = f"/tmp/chrome_fuzz_profile_{int(time.time())}_{os.getpid()}"

        self.tracer = EBPFTracer(
            interest_patterns=[
                self.chrome_user_dir,
                "/home", 
                "/tmp"
            ],
            ignore_patterns=[
                "__pycache__", ".so", ".pyc", "/dev/", 
                "/proc/", ".so", "LOCK", "Singleton", "GPUCache"
            ]
        )
        self.extractor = MetadataExtractor()
        self.proc: Optional[subprocess.Popen] = None
        self.fuzzer_proc: Optional[subprocess.Popen] = None
        self.ipc_server = FeedbackServer()
        self.all_events = [] 
        
        os.makedirs(self.output_dir, exist_ok=True)

    def _setup_inputs(self):
        logger.info("[Phase 0] Setting up environment...")
        # Chrome requires a dedicated user data dir to avoid messing up local profiles

        if os.path.exists(self.chrome_user_dir):
            shutil.rmtree(self.chrome_user_dir, ignore_errors=True)
        os.makedirs(self.chrome_user_dir, exist_ok=True)

    def run(self):
        logger.info(f"[*] Starting Discovery Session for {self.app_name}")
        self._setup_inputs()
        self.ipc_server.start()

        # 해상도 확보
        with XvfbDisplay(display_id=99, res="1920x1080x24") as xvfb:
            logger.info("[Phase 1] Initializing eBPF Tracer...")
            
            # Tracer 시작
            self.tracer.start_trace(root_pid=0, target_name="chrome") 
            time.sleep(2) 
            
            # --- Chrome 실행 명령어 구성 ---
            cmd = self.target_cmd.copy()
            
            if any(x in cmd[0] for x in ["google-chrome", "chromium", "chrome"]):
                logger.info("Detected Chrome/Chromium target. Injecting instrumentation flags...")
                cmd.extend([
                    "--no-sandbox", 
                    "--disable-gpu", 
                    "--disable-dev-shm-usage",
                    "--force-renderer-accessibility", 
                    "--window-size=1920,1080",
                    "--start-maximized",
                    "--window-position=0,0",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-infobars",
                    "--disable-session-crashed-bubble",
                    "--disable-popup-blocking",
                    f"--user-data-dir={self.chrome_user_dir}"
                ])

            logger.info(f"[Phase 2] Launching Target: {' '.join(cmd)}")
            
            # 환경변수 설정
            target_env = os.environ.copy()
            target_env["GTK_MODULES"] = "gail:atk-bridge" 
            target_env["NO_AT_BRIDGE"] = "0"
            target_env["PYTHONPATH"] = os.getcwd() # 현재 경로를 파이썬 경로로 추가

            try:
                self.proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setsid,
                    env=target_env
                )
            except FileNotFoundError:
                logger.error(f"Target executable not found: {cmd[0]}")
                self.tracer.stop_trace()
                return

            time.sleep(3)
            if self.proc.poll() is not None:
                logger.error("[-] Target application crashed immediately!")
                self._cleanup()
                return

            logger.info("[Phase 3] Starting Smart Fuzzer (GUI Tester)...")
            
            import sys
            current_python = sys.executable
            
            # 1. 절대 경로 계산
            current_dir = os.path.dirname(os.path.abspath(__file__))

            # 환경 변수 FUZZER_SCRIPT가 설정된 경우 해당 스크립트 사용
            target_script_name = os.environ.get("FUZZER_SCRIPT", "smart_tester.py")
            
            # 2. smart_tester.py 위치 찾기 (우선순위: gui 폴더 내부 -> 현재 폴더)
            fuzzer_script = os.path.join(current_dir, "gui", target_script_name)
            if not os.path.exists(fuzzer_script):
                fuzzer_script = os.path.join(current_dir, target_script_name)
            
            # 3. 디버깅 로그 출력
            logger.info(f"[DEBUG] Final Fuzzer Path: {fuzzer_script}")

            if not os.path.exists(fuzzer_script):
                logger.error(f"[-] FATAL: Fuzzer script NOT found at {fuzzer_script}")
                self._cleanup()
                return

            self.fuzzer_proc = subprocess.Popen(
                [current_python, fuzzer_script, self.app_name, str(self.duration)], 
                env=target_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            logger.info(f"[Phase 3] Fuzzing in progress for {self.duration} seconds...")
            start_time = time.time()
            total_score = 0.0
            total_artifacts_count = 0
            
            try:
                while time.time() - start_time < self.duration:
                    if self.proc.poll() is not None:
                        logger.warning("[-] Target application exited early.")
                        break
                    
                    if self.fuzzer_proc.poll() is not None:
                        logger.error("[-] Fuzzer process died! Check stderr.")
                        out, err = self.fuzzer_proc.communicate()
                        if err: logger.error(f"Fuzzer Stderr: {err.decode()}")
                        break

                    new_events = self.tracer.get_events()
                    if new_events:
                        self.all_events.extend(new_events)
                        total_artifacts_count += len(new_events)

                        batch_score = 0.0
                        for event in new_events:
                            fpath = event['filename']
                            score = self.extractor.calculate_forensic_score(fpath)
                            batch_score += score

                            if score >= 50.0:
                                logger.info(f"[+] High-Value Artifact Detected: {fpath} (Score: {score})")
                        
                        total_score += batch_score

                        if total_artifacts_count % 10 == 0:
                            logger.info(f"[+] Total Artifacts Discovered: {total_artifacts}")
                        self.ipc_server.update_count(int(total_score))

                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Interrupted by user.")

            logger.info("[*] Draining remaining events from tracer...")
            final_events = self.tracer.get_events()
            if final_events:
                self.all_events.extend(final_events)
                total_artifacts_count += len(final_events)
                for event in final_events:
                    total_score += self.extractor.calculate_forensic_score(event['filename'])

                logger.info(f"[+] Final Total Artifacts Discovered: {total_artifacts}")
                self.ipc_server.update_count(int(total_score))

            logger.info("[Phase 4] Stopping experiment...")
            self._cleanup()

        self._analyze_results()

    def _cleanup(self):
        if self.proc:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                self.proc.wait()
            except: pass
        
        # Cleanup Chrome profile to avoid disk bloat
        # if self.chrome_user_dir and os.path.exists(self.chrome_user_dir):
        #    shutil.rmtree(self.chrome_user_dir, ignore_errors=True)

    def _analyze_results(self):
        logger.info("[Phase 5] Analyzing captured artifacts...")
        events = self.all_events
        
        # --- [디버깅 코드 추가됨] Fuzzer 로그 파싱 ---
        actions = []
        log_path = "/tmp/fuzzer_debug.log"
        
        import re
        from datetime import datetime

        print(f"\n[DEBUG] Checking log file at: {log_path}")
        
        if not os.path.exists(log_path):
            logger.error(f"[-] Log file NOT FOUND at {log_path}")
            # 혹시 다른 이름으로 저장되었는지 확인하기 위해 /tmp 목록 출력
            try:
                print(f"[DEBUG] /tmp directory listing: {os.listdir('/tmp')}")
            except: pass
        else:
            try:
                print(f"[DEBUG] Log file found. Size: {os.path.getsize(log_path)} bytes")
                
                with open(log_path, "r", errors='ignore') as f:
                    lines = f.readlines()
                    print(f"[DEBUG] Total lines read: {len(lines)}")
                    
                    for i, line in enumerate(lines):
                        line = line.strip()
                        # '[Action]' 키워드 검색
                        if "[Action]" in line:
                            print(f"[DEBUG] Found Action Line [{i}]: {line}")
                            
                            try:
                                # 타임스탬프 추출 시도 (밀리초 포함/미포함 모두 대응)
                                # 포맷: 2025-11-22 10:56:07,886
                                time_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                                if not time_match:
                                    print(f"    -> [FAIL] Timestamp regex mismatch!")
                                    continue
                                
                                time_str = time_match.group(1)
                                dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                                ts = dt.timestamp()
                                
                                # 행동 설명 추출
                                action_desc = line.split("[Action]")[-1].strip()
                                
                                actions.append({"time": ts, "action": action_desc})
                                print(f"    -> [SUCCESS] Parsed: Time={ts}, Action='{action_desc}'")
                                
                            except Exception as e:
                                print(f"    -> [ERROR] Parsing failed: {e}")
                        
                        # 디버깅을 위해 앞쪽 5줄은 무조건 출력해봄 (포맷 확인용)
                        elif i < 5:
                            print(f"[DEBUG] Sample Line [{i}]: {line}")

                logger.info(f"Parsed {len(actions)} fuzzer actions from log")
                    
            except Exception as e:
                logger.warning(f"Error reading fuzzer log: {e}")

        # 2. 아티팩트 분석 및 Action 매핑 (기존 로직 유지)
        unique_artifacts = {}
        
        # 매핑 디버깅용 카운터
        mapped_count = 0
        
        for e in events:
            fname = e['filename']
            created_time = e['timestamp']
            
            if fname not in unique_artifacts:
                likely_cause = "Unknown (Background)"
                best_gap = 5.0 
                
                if actions:
                    for act in reversed(actions):
                        gap = created_time - act['time']
                        if 0 <= gap < best_gap:
                            likely_cause = act['action']
                            mapped_count += 1 # 매핑 성공 카운트
                            break
                
                unique_artifacts[fname] = {
                    "syscalls": set(), 
                    "processes": set(),
                    "cause_action": likely_cause
                }
            
            unique_artifacts[fname]["syscalls"].add(e['type'])
            unique_artifacts[fname]["processes"].add(e['process_name'])

        print(f"[DEBUG] Total Artifacts: {len(unique_artifacts)}, Mapped Actions: {mapped_count}")

        # 3. 리포트 생성
        report = []
        for filepath, data in unique_artifacts.items():
            exists = os.path.exists(filepath)
            meta = self.extractor.extract(filepath) if exists else "File Deleted or Inaccessible"
            
            artifact_entry = {
                "filepath": filepath,
                "cause_action": data["cause_action"],
                "interactions": list(data["syscalls"]),
                "accessed_by": list(data["processes"]),
                "exists_on_disk": exists,
                "metadata": meta
            }
            report.append(artifact_entry)

        output_json = os.path.join(self.output_dir, "artifact_footprint.json")
        try:
            with open(output_json, "w") as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"[Success] Report saved to {output_json}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

if __name__ == "__main__":
    # Default Config for Chrome
    session = ArtifactDiscoverySession(
        target_cmd=["google-chrome"], 
        app_name="Google Chrome", 
        duration=120
    )
    session.run()
import os
import time
import json
import signal
import logging
import subprocess
import shutil
import sys
from typing import List, Dict, Optional, Set, Any

from core.tracer.ebpf_engine import EBPFTracer
from core.fuzzing.gui.xvfb_display import XvfbDisplay
from core.metadata.extractor import MetadataExtractor
from core.fuzzing.ipc import FeedbackServer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Orchestrator")

class ArtifactDiscoverySession:
    def __init__(self, 
                 target_cmd: List[str], 
                 app_name: str,
                 duration: int = 60, 
                 output_dir: str = "./experiment_data",
                 target_state_file: str = None,
                 config_path: str = "target_config.json"):
        
        self.target_cmd = target_cmd
        self.app_name = app_name
        self.duration = duration
        self.output_dir = os.path.join(output_dir, f"{app_name}_{int(time.time())}")
        
        self.config = self._load_app_config(config_path, app_name)
        
        self.targets_config: List[Any] = []
        self.found_targets: Set[str] = set()
        
        if target_state_file:
            self._load_target_state(target_state_file)

        self.chrome_user_dir = f"/tmp/chrome_fuzz_profile_{int(time.time())}_{os.getpid()}"
        
        target_proc = self.config.get("process_name", "chrome") if self.config else "chrome"
        
        self.tracer = EBPFTracer(
            interest_patterns=[self.chrome_user_dir, "/home", "/tmp"],
            ignore_patterns=["Singleton", "LOCK", ".so", "FontConfig", "dconf", "goutputstream", "__pycache__", "GPUCache"]
        )
        
        self.extractor = MetadataExtractor()
        self.ipc_server = FeedbackServer()
        self.proc: Optional[subprocess.Popen] = None
        self.fuzzer_proc: Optional[subprocess.Popen] = None
        self.all_events = [] 
        
        os.makedirs(self.output_dir, exist_ok=True)

    def _load_app_config(self, path, app_name) -> Dict:
        try:
            if not os.path.exists(path):
                return {}
            with open(path, 'r') as f:
                full_config = json.load(f)
            normalized_name = app_name.lower().replace(" ", "-")
            for key, cfg in full_config.items():
                if key in normalized_name:
                    return cfg
            return {}
        except Exception:
            return {}

    def _load_target_state(self, path):
        try:
            with open(path, 'r') as f:
                self.targets_config = json.load(f)
            logger.info(f"[Target-Mode] Loaded {len(self.targets_config)} target rules.")
        except Exception as e:
            logger.warning(f"[-] Failed to load target state: {e}")
            self.targets_config = []

    def _setup_inputs(self):
        logger.info("[Phase 0] Setting up environment...")
        if os.path.exists(self.chrome_user_dir):
            shutil.rmtree(self.chrome_user_dir, ignore_errors=True)
        os.makedirs(self.chrome_user_dir, exist_ok=True)

    def calculate_reward(self, new_events):
        """
        [FIXED] Robust Reward Calculation
        문자열 리스트와 객체 리스트, 다양한 키 이름에 모두 대응하도록 수정됨.
        """
        total_score = 0.0
        
        for event in new_events:
            fpath = event['filename']
            
            # 1. 기본 가치 점수
            base_score = self.extractor.calculate_forensic_score(fpath)
            
            # 2. 정밀 타겟 매칭
            target_bonus = 0.0
            if self.targets_config:
                meta = self.extractor.extract(fpath)
                
                for target in self.targets_config:
                    # [FIX] 타겟 경로 추출 로직 강화
                    target_path = None
                    
                    if isinstance(target, str):
                        target_path = target
                    elif isinstance(target, dict):
                        # 'path'가 없으면 'path_pattern' 시도
                        target_path = target.get('path') or target.get('path_pattern')
                    
                    # 타겟 경로가 없으면(None) 건너뜀
                    if not target_path: continue

                    # (1) 경로 매칭 (필수)
                    if target_path not in fpath:
                        continue
                        
                    # (2) 추가 조건 검사 (딕셔너리인 경우만)
                    if isinstance(target, dict):
                        if 'min_size' in target:
                            if not meta or meta['size'] < target['min_size']: continue
                        if 'content_key' in target:
                            if not meta: continue
                            summary = str(meta.get('content_summary', {}))
                            if target['content_key'] not in summary: continue

                    # 매칭 성공
                    target_bonus = 500.0
                    if fpath not in self.found_targets:
                        logger.info(f"[★ PRECISE MATCH] {fpath} matches target!")
                        self.found_targets.add(fpath)
                    break
            
            total_score += (base_score + target_bonus)

        return int(total_score)

    def run(self):
        logger.info(f"[*] Starting Session for {self.app_name}")
        self._setup_inputs()
        self.ipc_server.start()

        with XvfbDisplay(display_id=99, res="1920x1080x24") as xvfb:
            logger.info("[Phase 1] Initializing eBPF Tracer...")
            
            target_proc = "chrome"
            if hasattr(self, 'config') and self.config:
                target_proc = self.config.get("process_name", "chrome")
                
            self.tracer.start_trace(root_pid=0, target_name=target_proc) 
            time.sleep(2) 
            
            # ... (명령어 구성 로직 동일) ...
            if hasattr(self, 'config') and self.config:
                cmd = self.config.get("binary_cmd", []).copy()
                user_dir_flag = self.config.get("user_dir_flag", "--user-data-dir")
                if "chrome" in self.app_name.lower():
                    cmd.append(f"{user_dir_flag}={self.chrome_user_dir}")
            else:
                cmd = self.target_cmd.copy()
                if any(x in cmd[0] for x in ["google-chrome", "chromium", "chrome"]):
                    cmd.extend([
                        "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                        "--force-renderer-accessibility", "--window-size=1920,1080",
                        "--start-maximized", "--window-position=0,0", "--no-first-run",
                        "--no-default-browser-check", "--disable-infobars", 
                        "--disable-session-crashed-bubble", "--disable-popup-blocking",
                        f"--user-data-dir={self.chrome_user_dir}"
                    ])

            logger.info(f"[Phase 2] Launching Target: {' '.join(cmd)}")
            
            target_env = os.environ.copy()
            target_env["GTK_MODULES"] = "gail:atk-bridge" 
            target_env["NO_AT_BRIDGE"] = "0"
            target_env["PYTHONPATH"] = os.getcwd()

            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid, env=target_env)
            except FileNotFoundError:
                logger.error("Target executable not found!")
                return

            time.sleep(3)
            
            logger.info("[Phase 3] Starting Smart Fuzzer...")
            fuzzer_script_name = os.environ.get("FUZZER_SCRIPT", "smart_tester.py")
            current_dir = os.path.dirname(os.path.abspath(__file__))
            fuzzer_path = os.path.join(current_dir, "gui", fuzzer_script_name)
            if not os.path.exists(fuzzer_path): 
                fuzzer_path = os.path.join(current_dir, fuzzer_script_name)

            self.fuzzer_proc = subprocess.Popen(
                [sys.executable, fuzzer_path, self.app_name, str(self.duration)], 
                env=target_env, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            
            start_time = time.time()
            total_score = 0.0
            total_artifacts_count = 0
            
            # [DEBUG] 루프 시작 로그
            logger.info(f"[DEBUG] Loop started. Duration: {self.duration}s")
            
            try:
                while True:
                    # 1. 시간 체크
                    if time.time() - start_time >= self.duration:
                        logger.info("[DEBUG] Loop exiting: Duration expired.")
                        break
                        
                    # 2. 프로세스 생존 확인
                    if self.proc.poll() is not None:
                        logger.warning("[-] Target application exited early.")
                        break
                    if self.fuzzer_proc.poll() is not None:
                        # Fuzzer 사망 시 stderr 출력
                        out, err = self.fuzzer_proc.communicate()
                        logger.error(f"[-] Fuzzer process died. Stderr: {err.decode() if err else 'None'}")
                        break

                    # 3. 이벤트 수집
                    new_events = self.tracer.get_events()
                    if new_events:
                        self.all_events.extend(new_events)
                        total_artifacts_count += len(new_events)
                        
                        reward = self.calculate_reward(new_events)
                        total_score += reward
                        self.ipc_server.update_count(int(total_score))
                        
                        # 4. 미션 완료 체크 (절대 break 하지 않음)
                        if self.targets_config and len(self.found_targets) >= len(self.targets_config):
                            # 중복 로그 방지
                            if not hasattr(self, '_mission_logged'):
                                logger.info("[!!!] MISSION COMPLETE: All targets reproduced! (Continuing...)")
                                self._mission_logged = True
                            
                            # [중요] 여기에 break가 없는지 확인하세요!
                            pass 

                    time.sleep(1)
            except KeyboardInterrupt: 
                logger.info("[DEBUG] Loop exiting: KeyboardInterrupt.")
            except Exception as e:
                logger.error(f"[DEBUG] Loop exiting: Unexpected Exception: {e}")

            # Final Drain
            logger.info("[Phase 3.5] Draining remaining events...")
            final_events = self.tracer.get_events()
            if final_events:
                self.all_events.extend(final_events)
                total_artifacts_count += len(final_events)
                total_score += self.calculate_reward(final_events)
                logger.info(f"[+] Final Artifact Count: {total_artifacts_count} | Final Score: {total_score:.1f}")
                self.ipc_server.update_count(int(total_score))

            logger.info("[Phase 4] Stopping experiment...")
            self._cleanup()

        self._analyze_results()

    def _cleanup(self):
        if self.fuzzer_proc: self.fuzzer_proc.terminate()
        self.ipc_server.stop()
        self.tracer.stop_trace()
        if self.proc:
            try: os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except: pass

    def _analyze_results(self):
        logger.info("[Phase 5] Analyzing captured artifacts...")
        events = self.all_events
        
        actions = []
        log_path = "/tmp/fuzzer_debug.log"
        
        import re
        from datetime import datetime
        
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", errors='ignore') as f:
                    for line in f:
                        if "[Action]" in line:
                            try:
                                time_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                                if not time_match: continue
                                dt = datetime.strptime(time_match.group(1), "%Y-%m-%d %H:%M:%S")
                                action_desc = line.split("[Action]")[-1].strip()
                                actions.append({"time": dt.timestamp(), "action": action_desc})
                            except: continue
                logger.info(f"Parsed {len(actions)} fuzzer actions from log")
            except Exception as e:
                logger.warning(f"Error reading fuzzer log: {e}")

        unique_artifacts = {}
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
                            break
                
                unique_artifacts[fname] = {"syscalls": set(), "processes": set(), "cause_action": likely_cause}
            
            unique_artifacts[fname]["syscalls"].add(e['type'])
            unique_artifacts[fname]["processes"].add(e['process_name'])

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
    app = "Google Chrome"
    dur = 120
    target_file = None
    
    if len(sys.argv) > 1: app = sys.argv[1] # 앱 이름 인자로 받기
    if len(sys.argv) > 3: target_file = sys.argv[3]
    
    # 기본 명령어는 의미 없음 (설정 파일에서 덮어씌워짐)
    session = ArtifactDiscoverySession(
        target_cmd=["google-chrome"], 
        app_name=app, 
        duration=dur,
        target_state_file=target_file
    )
    session.run()
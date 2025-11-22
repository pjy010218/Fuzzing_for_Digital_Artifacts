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
            
            # --- [수정된 부분] 경로 계산 및 실행 (중복 코드 제거됨) ---
            import sys
            current_python = sys.executable
            
            # 1. 절대 경로 계산
            current_dir = os.path.dirname(os.path.abspath(__file__))
            
            # 2. smart_tester.py 위치 찾기 (우선순위: gui 폴더 내부 -> 현재 폴더)
            fuzzer_script = os.path.join(current_dir, "gui", "smart_tester.py")
            if not os.path.exists(fuzzer_script):
                fuzzer_script = os.path.join(current_dir, "smart_tester.py")
            
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
            total_artifacts = 0
            
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
                        total_artifacts += len(new_events)
                        if total_artifacts % 10 == 0:
                            logger.info(f"[+] Total Artifacts Discovered: {total_artifacts}")
                        self.ipc_server.update_count(total_artifacts)

                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Interrupted by user.")

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
        # Use accumulated events, not empty queue
        events = self.all_events
        logger.info(f"Captured {len(events)} raw syscall events")

        unique_artifacts = {}
        for e in events:
            fname = e['filename']
            if fname not in unique_artifacts:
                unique_artifacts[fname] = {"syscalls": set(), "processes": set()}
            unique_artifacts[fname]["syscalls"].add(e['type'])
            unique_artifacts[fname]["processes"].add(e['process_name'])

        report = []
        for filepath, data in unique_artifacts.items():
            meta = self.extractor.extract(filepath)
            artifact_entry = {
                "filepath": filepath,
                "interactions": list(data["syscalls"]),
                "accessed_by": list(data["processes"]),
                "exists_on_disk": os.path.exists(filepath),
                "metadata": meta if meta else "File Deleted or Inaccessible"
            }
            report.append(artifact_entry)

        output_json = os.path.join(self.output_dir, "artifact_footprint.json")
        with open(output_json, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"[Success] Report saved to {output_json}")

if __name__ == "__main__":
    # Default Config for Chrome
    session = ArtifactDiscoverySession(
        target_cmd=["google-chrome"], 
        app_name="Google Chrome", 
        duration=120
    )
    session.run()
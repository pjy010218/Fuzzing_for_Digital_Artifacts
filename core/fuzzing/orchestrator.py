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
        
        self.tracer = EBPFTracer()
        self.extractor = MetadataExtractor()
        self.proc: Optional[subprocess.Popen] = None
        self.ipc_server = FeedbackServer()
        self.all_events = [] 
        self.chrome_user_dir = ""
        
        os.makedirs(self.output_dir, exist_ok=True)

    def _setup_inputs(self):
        logger.info("[Phase 0] Setting up environment...")
        # Chrome requires a dedicated user data dir to avoid messing up local profiles
        self.chrome_user_dir = f"/tmp/chrome_fuzz_profile_{int(time.time())}"
        os.makedirs(self.chrome_user_dir, exist_ok=True)

    def run(self):
        logger.info(f"[*] Starting Discovery Session for {self.app_name}")
        self._setup_inputs()
        self.ipc_server.start()

        with XvfbDisplay(display_id=99) as xvfb:
            logger.info("[Phase 1] Initializing eBPF Tracer...")
            # Start tracing, target 'chrome' specifically for filtering
            self.tracer.start_trace(root_pid=0, target_name="chrome") 
            time.sleep(2) 
            
            # Append critical Chrome flags
            cmd = self.target_cmd.copy()
            # Check if command is likely Chrome/Chromium
            if any(x in cmd[0] for x in ["google-chrome", "chromium", "chrome"]):
                cmd.extend([
                    "--no-sandbox", 
                    "--disable-gpu", 
                    "--force-renderer-accessibility", # CRITICAL for Dogtail to see DOM
                    f"--user-data-dir={self.chrome_user_dir}",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-dev-shm-usage" # Fix crashes in containers
                ])

            logger.info(f"[Phase 2] Launching: {' '.join(cmd)}")
            try:
                self.proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid,
                    env=os.environ
                )
            except FileNotFoundError:
                logger.error("Target executable not found!")
                self.tracer.stop_trace()
                return

            logger.info("[Phase 3] Starting Smart Fuzzer...")
            import sys
            current_python = sys.executable
            
            fuzz_thread = subprocess.Popen(
                [current_python, "core/fuzzing/gui/smart_tester.py", self.app_name], 
                env=os.environ.copy(),
                stdout=None,
                stderr=None
            )
            
            logger.info(f"[Phase 3] Fuzzing for {self.duration} seconds...")
            start_time = time.time()
            total_artifacts = 0
            
            while time.time() - start_time < self.duration:
                if self.proc.poll() is not None:
                    logger.warning("Target application crashed or exited early!")
                    break
                
                # Drain events from tracer and store persistently
                new_events = self.tracer.get_events()
                if new_events:
                    self.all_events.extend(new_events)
                    total_artifacts += len(new_events)
                    logger.info(f"[+] Total Artifacts Discovered: {total_artifacts}")
                    self.ipc_server.update_count(total_artifacts)

                time.sleep(1)
            
            logger.info("[Phase 4] Stopping experiment...")
            self.ipc_server.stop()
            self.tracer.stop_trace()
            if fuzz_thread: fuzz_thread.terminate()
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
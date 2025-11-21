import os
import time
import json
import signal
import logging
import subprocess
import shutil
from typing import List, Dict, Optional

# Import our modules
from core.tracer.ebpf_engine import EBPFTracer
from core.fuzzing.gui.xvfb_display import XvfbDisplay
from core.metadata.extractor import MetadataExtractor
# Note: We don't import SmartFuzzer class directly because we run it via subprocess
# to ensure it has a clean accessibility environment.

# Setup Logging
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
        
        os.makedirs(self.output_dir, exist_ok=True)

    def _setup_inputs(self):
        logger.info("[Phase 0] Setting up environment...")

    def run(self):
        logger.info(f"[*] Starting Discovery Session for {self.app_name}")
        self._setup_inputs()

        # 1. Start Virtual Display
        with XvfbDisplay(display_id=99) as xvfb:
            
            # [Phase 1] Start Tracing (BEFORE App Launch)
            logger.info("[Phase 1] Initializing eBPF Tracer...")
            # Start system-wide tracing, filtering for our app
            self.tracer.start_trace(root_pid=0, target_name=self.app_name)
            time.sleep(2) 
            
            # [Phase 2] Launch Target Application
            logger.info(f"[Phase 2] Launching: {' '.join(self.target_cmd)}")
            try:
                self.proc = subprocess.Popen(
                    self.target_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid,
                    env=os.environ # Ensure it gets DISPLAY/:99 and Accessibility Env
                )
            except FileNotFoundError:
                logger.error("Target executable not found!")
                self.tracer.stop_trace()
                return

            # [Phase 3] Start Smart Fuzzing
            logger.info("[Phase 3] Starting Smart Fuzzer (Dogtail)...")
            
            # We run the SmartFuzzer as a subprocess script.
            # This ensures it inherits the correct D-Bus/Accessibility environment from XvfbDisplay
            fuzz_thread = subprocess.Popen(
                ["python3", "core/fuzzing/gui/smart_tester.py", self.app_name], 
                env=os.environ.copy(),
                stdout=None,
                stderr=None
            )
            
            # --- MAIN LOOP ---
            logger.info(f"[Phase 3] Fuzzing for {self.duration} seconds...")
            start_time = time.time()
            while time.time() - start_time < self.duration:
                if self.proc.poll() is not None:
                    logger.warning("Target application crashed or exited early!")
                    break
                time.sleep(1)
            
            # [Phase 4] Teardown
            logger.info("[Phase 4] Stopping experiment...")
            self.tracer.stop_trace()
            if fuzz_thread: 
                fuzz_thread.terminate()
            self._cleanup()

        # 5. Post-Processing
        self._analyze_results()

    def _cleanup(self):
        """Safely kill the target application."""
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                self.proc.wait()
            except ProcessLookupError:
                pass

    def _analyze_results(self):
        logger.info("[Phase 5] Analyzing captured artifacts...")
        
        events = self.tracer.get_events()
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
        
        logger.info(f"[Success] Report saved to {output_json} with {len(report)} entries.")

if __name__ == "__main__":
    # Note: "Mousepad" is the Accessibility Name, "mousepad" is the command
    session = ArtifactDiscoverySession(
        target_cmd=["mousepad"], 
        app_name="Mousepad", 
        duration=15
    )
    session.run()
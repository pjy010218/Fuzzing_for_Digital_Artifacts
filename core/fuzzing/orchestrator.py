import os
import time
import json
import signal
import logging
import subprocess
import shutil
from typing import List, Dict, Optional
from dataclasses import asdict

# Import our modules
from core.tracer.ebpf_engine import EBPFTracer
from core.fuzzing.gui.xvfb_display import XvfbDisplay
from core.fuzzing.gui.monkey_tester import GUIMonkeyTester, FuzzConfig
from core.metadata.extractor import MetadataExtractor

import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.insert(0, PROJECT_ROOT)

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
        
        # Components
        self.tracer = EBPFTracer()
        self.extractor = MetadataExtractor()
        self.proc: Optional[subprocess.Popen] = None
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

    def _setup_inputs(self):
        """
        Hybrid Phase: Use Radamsa here if needed.
        For now, we ensure the app has a clean environment.
        """
        logger.info("[Phase 0] Setting up environment...")
        # In a full implementation, this would mount the OverlayFS
        pass

    def run(self):
        logger.info(f"[*] Starting Discovery Session for {self.app_name}")
        self._setup_inputs()

        # 1. Start Virtual Display
        with XvfbDisplay(display_id=99) as xvfb:
            
            # --- CRITICAL CHANGE: START TRACING BEFORE LAUNCHING APP ---
            logger.info("[Phase 1] Initializing eBPF Tracer (This takes 2-3s)...")
            # Start system-wide tracing immediately.
            # We filter for the app name.
            self.tracer.start_trace(root_pid=0, target_name=self.app_name)
            
            # Give eBPF a moment to actually insert the probes into the kernel
            time.sleep(2) 
            
            # 2. Launch Target Application
            logger.info(f"[Phase 2] Launching: {' '.join(self.target_cmd)}")
            try:
                self.proc = subprocess.Popen(
                    self.target_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setsid,
                    env=os.environ # Ensure it gets DISPLAY/:99
                )
            except FileNotFoundError:
                logger.error("Target executable not found!")
                self.tracer.stop_trace()
                return

            # 3. Start GUI Fuzzing
            fuzz_cfg = FuzzConfig(duration_seconds=self.duration)
            
            # Note: We use app_name (e.g. "Mousepad") for window matching
            monkey = GUIMonkeyTester(target_window_name=self.app_name, config=fuzz_cfg)
            
            # Run Fuzzer in a separate thread/process
            fuzz_thread = subprocess.Popen(
                ["python3", "core/fuzzing/gui/monkey_tester.py", self.app_name], 
                env=os.environ.copy()
            )
            
            # --- MAIN LOOP ---
            logger.info(f"[Phase 3] Fuzzing for {self.duration} seconds...")
            start_time = time.time()
            while time.time() - start_time < self.duration:
                if self.proc.poll() is not None:
                    logger.warning("Target application crashed or exited early!")
                    break
                time.sleep(1)
            
            # 4. Teardown
            logger.info("[Phase 4] Stopping experiment...")
            self.tracer.stop_trace()
            if fuzz_thread: fuzz_thread.terminate()
            self._cleanup()

        # 5. Post-Processing
        self._analyze_results()

    def _cleanup(self):
        """Safely kill the target application."""
        if self.proc and self.proc.poll() is None:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            self.proc.wait()

    def _analyze_results(self):
        logger.info("[Phase 4] Analyzing captured artifacts...")
        
        # Retrieve raw syscall events
        events = self.tracer.get_events()
        logger.info(f"Captured {len(events)} raw syscall events")

        # Deduplicate: Map filenames to "Types" (Write/Open/Delete)
        unique_artifacts = {}
        for e in events:
            fname = e['filename']
            if fname not in unique_artifacts:
                unique_artifacts[fname] = {"syscalls": set(), "processes": set()}
            
            unique_artifacts[fname]["syscalls"].add(e['type'])
            unique_artifacts[fname]["processes"].add(e['process_name'])

        # Extract Metadata for valid files
        report = []
        for filepath, data in unique_artifacts.items():
            # Filter: Only care about files that actually exist on disk now
            # (Unless it was a temporary file that was deleted - different D3FEND category!)
            
            meta = self.extractor.extract(filepath)
            
            artifact_entry = {
                "filepath": filepath,
                "interactions": list(data["syscalls"]),
                "accessed_by": list(data["processes"]),
                "exists_on_disk": os.path.exists(filepath),
                "metadata": meta if meta else "File Deleted or Inaccessible"
            }
            report.append(artifact_entry)

        # Save JSON for the LLM
        output_json = os.path.join(self.output_dir, "artifact_footprint.json")
        with open(output_json, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"[Success] Report saved to {output_json} with {len(report)} entries.")

# --- ENTRY POINT ---
if __name__ == "__main__":
    # Example: Tracing 'gedit' (Linux Text Editor)
    # Note: Must run as Root for eBPF
    if os.geteuid() != 0:
        print("[-] Error: This orchestrator requires root privileges for eBPF.")
        exit(1)

    session = ArtifactDiscoverySession(
        target_cmd=["mousepad"], 
        app_name="Mousepad",
        duration=15
    )
    session.run()
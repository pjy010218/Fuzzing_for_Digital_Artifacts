import os
import time
import subprocess
from typing import Optional

class XvfbDisplay:
    def __init__(self, display_id: int = 99, res: str = "1920x1080x24"):
        self.display_id = f":{display_id}"
        self.res = res
        self.xvfb_proc: Optional[subprocess.Popen] = None
        self.fluxbox_proc: Optional[subprocess.Popen] = None
        self.auth_file = f"/tmp/.Xauthority_xvfb_{display_id}"

    def __enter__(self):
        print(f"[*] Starting Xvfb + Fluxbox on {self.display_id}...")
        
        # Cleanup Locks
        lock_file = f"/tmp/.X{self.display_id.strip(':')}-lock"
        if os.path.exists(lock_file):
            os.remove(lock_file)

        # Setup Dummy Auth
        with open(self.auth_file, 'w') as f: pass
        os.environ["XAUTHORITY"] = self.auth_file
        os.environ["DISPLAY"] = self.display_id

        # --- REMOVED: Manual DBUS launch code (Handled by run_experiment.sh) ---

        # Start Xvfb
        self.xvfb_proc = subprocess.Popen(
            ["Xvfb", self.display_id, "-screen", "0", self.res, "-ac"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1)

        # Start Fluxbox
        try:
            self.fluxbox_proc = subprocess.Popen(
                ["fluxbox"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=os.environ
            )
            time.sleep(1)
        except FileNotFoundError:
            print("[-] Warning: Fluxbox not installed.")
            
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.fluxbox_proc: self.fluxbox_proc.terminate()
        if self.xvfb_proc: self.xvfb_proc.terminate()
        if os.path.exists(self.auth_file): os.remove(self.auth_file)
        print("[*] Display Environment Stopped")
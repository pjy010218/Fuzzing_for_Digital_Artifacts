import os
import time
import subprocess
from typing import Optional

class XvfbDisplay:
    """
    Context Manager: Manages Xvfb (Screen) AND Fluxbox (Window Manager).
    """
    def __init__(self, display_id: int = 99, res: str = "1920x1080x24"):
        self.display_id = f":{display_id}"
        self.res = res
        self.xvfb_proc: Optional[subprocess.Popen] = None
        self.fluxbox_proc: Optional[subprocess.Popen] = None
        self.auth_file = f"/tmp/.Xauthority_xvfb_{display_id}"

    def __enter__(self):
        print(f"[*] Starting Xvfb + Fluxbox on {self.display_id}...")
        
        # 1. Cleanup Locks
        lock_file = f"/tmp/.X{self.display_id.strip(':')}-lock"
        if os.path.exists(lock_file):
            os.remove(lock_file)

        # 2. Setup Dummy Auth (Fixes Xlib crash)
        with open(self.auth_file, 'w') as f:
            pass
        os.environ["XAUTHORITY"] = self.auth_file
        os.environ["DISPLAY"] = self.display_id

        # 3. Start Xvfb (The Screen)
        self.xvfb_proc = subprocess.Popen(
            ["Xvfb", self.display_id, "-screen", "0", self.res, "-ac"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1) # Wait for screen

        # 4. Start Fluxbox (The Window Manager)
        # This allows xdotool to 'activate' and 'focus' windows correctly.
        try:
            self.fluxbox_proc = subprocess.Popen(
                ["fluxbox"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=os.environ # Pass DISPLAY/XAUTHORITY to fluxbox
            )
            time.sleep(1) # Wait for WM to load
        except FileNotFoundError:
            print("[-] Warning: Fluxbox not installed. Focus might fail.")
            
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Kill Fluxbox first
        if self.fluxbox_proc:
            self.fluxbox_proc.terminate()
            
        # Kill Xvfb
        if self.xvfb_proc:
            self.xvfb_proc.terminate()
            self.xvfb_proc.wait()
        
        if os.path.exists(self.auth_file):
            os.remove(self.auth_file)
            
        print("[*] Display Environment Stopped")

    def record_video(self, output_path: str):
        return subprocess.Popen([
            "ffmpeg", "-y", "-f", "x11grab", "-i", self.display_id,
            "-r", "10", output_path
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
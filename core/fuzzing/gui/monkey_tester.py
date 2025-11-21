import time
import random
import subprocess
import logging
from dataclasses import dataclass

# --- LAZY IMPORT FIX ---
# Do NOT import pyautogui here at the top level.
# It will crash because DISPLAY is not set yet.

@dataclass
class FuzzConfig:
    duration_seconds: int = 60
    action_delay: float = 0.1
    grid_step: int = 50
    random_seed: int = 42

class GUIMonkeyTester:
    def __init__(self, target_window_name: str, config: FuzzConfig):
        self.target = target_window_name
        self.cfg = config
        self.running = False
        self.logger = logging.getLogger("fuzzer")
        
        # --- IMPORT HERE ---
        # We import it now, because we know Xvfb is running
        global pyautogui
        import pyautogui
        
        # Now we can safely configure it
        pyautogui.FAILSAFE = False 
        random.seed(self.cfg.random_seed)

    def _focus_window(self):
        try:
            wid = subprocess.check_output(["xdotool", "search", "--onlyvisible", "--name", self.target])
            wid = wid.decode().strip().split('\n')[0]
            subprocess.run(["xdotool", "windowactivate", wid])
            return True
        except subprocess.CalledProcessError:
            self.logger.warning(f"Target window '{self.target}' not found yet...")
            return False

    def _random_click(self, screen_w, screen_h):
        x = random.randint(0, screen_w)
        y = random.randint(0, screen_h)
        pyautogui.click(x, y)

    def _grid_sweep(self, screen_w, screen_h):
        y = random.randint(0, screen_h)
        for x in range(0, screen_w, self.cfg.grid_step):
            if not self.running: break
            pyautogui.click(x, y)
            time.sleep(0.01)

    def _inject_hotkeys(self):
        shortcuts = [
            ['ctrl', 'o'], ['ctrl', 's'], ['ctrl', 'p'],
            ['f12'], ['ctrl', 'shift', 'delete'], ['alt', 'f4']
        ]
        combo = random.choice(shortcuts)
        if combo == ['alt', 'f4'] and random.random() > 0.05: 
            return
        pyautogui.hotkey(*combo)

    def start(self):
        self.running = True
        # Ensure pyautogui is loaded if start is called directly
        if 'pyautogui' not in globals():
            global pyautogui
            import pyautogui
            
        try:
            # Xvfb might take a millisecond to be recognized by Python
            w, h = pyautogui.size()
        except Exception:
            # Fallback if size detection fails in headless
            w, h = 1920, 1080
            
        self.logger.info(f"[*] Starting GUI Fuzzing on {w}x{h} for {self.target}")

        for _ in range(10):
            if self._focus_window(): break
            time.sleep(1)

        start_time = time.time()
        while self.running:
            if time.time() - start_time > self.cfg.duration_seconds:
                break

            dice = random.random()
            if dice < 0.6:
                self._random_click(w, h)
            elif dice < 0.8:
                self._grid_sweep(w, h)
            else:
                self._inject_hotkeys()

            time.sleep(self.cfg.action_delay)
        
        self.logger.info("[*] Fuzzing Session Complete")

if __name__ == "__main__":
    # When running as a script, we assume Xvfb is already handled
    # or we are in a test env.
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "Mousepad"
        
    fuzzer = GUIMonkeyTester(target, FuzzConfig(duration_seconds=10))
    fuzzer.start()
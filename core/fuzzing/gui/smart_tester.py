import time
import random
import logging
import os
import subprocess
from core.fuzzing.ipc import FeedbackClient

class SmartFuzzer:
    def __init__(self, app_name, duration=60):
        self.app_name = app_name
        self.duration = duration
        self.logger = logging.getLogger("SmartFuzzer")
        self.feedback = FeedbackClient()
        self.last_score = 0
        logging.basicConfig(filename='/tmp/fuzzer_debug.log', level=logging.INFO)
        
        self.app_node = None
        self.running = False
        
        global dogtail, config
        import dogtail.tree
        import dogtail.rawinput
        from dogtail.config import config
        
        config.defaultDelay = 1.5
        config.searchCutoffCount = 20
    
    def check_feedback(self, action_name):
        """
        Did the last action cause a kernel event?
        """
        current_score = self.feedback.get_artifact_count()
        delta = current_score - self.last_score
        self.last_score = current_score
        
        if delta > 0:
            self.logger.info(f"[!!!] REWARD: '{action_name}' caused {delta} kernel events!")
            return True
        return False

    def get_window_id(self):
        """
        Robustly finds the Window ID using xdotool.
        Returns the ID as a string, or None if not found.
        """
        try:
            # Search for the window ID
            # We use --name and --class to be sure
            out = subprocess.check_output(
                ["xdotool", "search", "--onlyvisible", "--name", self.app_name],
                stderr=subprocess.DEVNULL
            ).decode().strip()
            
            if not out:
                return None
            
            # If multiple IDs are returned, take the last one (usually the newest/active one)
            return out.split('\n')[-1]
        except:
            return None

    def focus_app(self):
        """
        Safely focuses the app. Prevents BadWindow errors.
        """
        wid = self.get_window_id()
        if wid:
            try:
                subprocess.run(["xdotool", "windowactivate", "--sync", wid], check=False)
                return True
            except: pass
        return False

    def xdo(self, args):
        """Raw X11 interaction helper"""
        try: subprocess.run(["xdotool"] + args, check=False)
        except: pass

    def connect(self):
        self.logger.info(f"[*] SmartFuzzer looking for app: {self.app_name}")
        start_wait = time.time()
        while time.time() - start_wait < 30:
            try:
                # Use Dogtail for connection check
                target_lower = self.app_name.lower()
                for app in dogtail.tree.root.applications():
                    if app.name.lower() == target_lower:
                        self.app_node = app
                        self.logger.info(f"[+] Attached to UI Tree: {app.name}")
                        return True
                time.sleep(1)
            except: time.sleep(1)
        return False

    def populate_content(self):
        try:
            self.logger.info("[Action] Populating content...")
            if self.focus_app():
                # Click center safe zone
                self.xdo(["mousemove", "960", "540", "click", "1"])
                self.xdo(["type", "Forensic Evidence"])
                self.xdo(["key", "Return"])
                time.sleep(1)
        except: pass

    def blind_save_workflow(self):
        """
        Safe Save Workflow that checks for window existence first.
        """
        fname = f"/tmp/artifact_{random.randint(1000,9999)}.txt"
        self.logger.info(f"[Action] Safe Save Workflow for {fname}")

        self.last_score = self.feedback.get_artifact_count()

        # 1. Ensure Focus (CRITICAL FIX)
        if not self.focus_app():
            self.logger.warning("[-] Could not focus app (Window not found). Skipping.")
            return

        # 2. Trigger Save
        self.xdo(["key", "ctrl+s"])
        time.sleep(2.0) 

        if self.check_feedback("Save Workflow"):
            self.logger.info(">> Fuzzer learned that 'CTRL+S' is a valid path!")

        # 3. Type Filename
        self.logger.info("    -> Typing Filename...")
        self.xdo(["type", "--delay", "100", fname])
        time.sleep(1.0)

        # 4. Save & Confirm
        self.logger.info("    -> Pressing Enter...")
        self.xdo(["key", "Return"])
        time.sleep(1.0)
        self.xdo(["key", "Return"])

    def start(self):
        if not self.connect(): return
        self.running = True
        
        self.populate_content()
        
        start_time = time.time()
        while time.time() - start_time < self.duration:
            self.blind_save_workflow()
            time.sleep(5) 

if __name__ == "__main__":
    import sys
    app = sys.argv[1] if len(sys.argv) > 1 else "Mousepad"
    fuzzer = SmartFuzzer(app, duration=40)
    fuzzer.start()
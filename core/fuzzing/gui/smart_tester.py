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

    def xdo(self, args):
        try: subprocess.run(["xdotool"] + args, check=False)
        except: pass

    def get_window_id(self):
        try:
            # Chrome windows usually contain "Google Chrome" in the title
            out = subprocess.check_output(
                ["xdotool", "search", "--onlyvisible", "--name", self.app_name],
                stderr=subprocess.DEVNULL
            ).decode().strip()
            if not out: return None
            # If multiple windows (e.g. tooltips), grab the last created one
            return out.split('\n')[-1]
        except: return None

    def focus_app(self):
        wid = self.get_window_id()
        if wid:
            self.xdo(["windowactivate", "--sync", wid])
            return True
        return False

    def connect(self):
        self.logger.info(f"[*] SmartFuzzer looking for app: {self.app_name}")
        start_wait = time.time()
        while time.time() - start_wait < 30:
            try:
                # Connect via Accessibility Bus
                # Chrome usually registers as "Google Chrome"
                target_lower = self.app_name.lower()
                for app in dogtail.tree.root.applications():
                    if target_lower in app.name.lower():
                        self.app_node = app
                        self.logger.info(f"[+] Attached to UI Tree: {app.name}")
                        return True
                time.sleep(1)
            except: time.sleep(1)
        return False

    def populate_content(self):
        """
        Interacts with the browser page to create history/cache artifacts.
        """
        self.logger.info("[Action] Interacting with Browser Page...")
        if self.focus_app():
            # 1. Click center of page (content area)
            self.xdo(["mousemove", "960", "540", "click", "1"])
            time.sleep(0.5)
            
            # 2. Focus URL Bar (Ctrl+L) and navigate
            self.xdo(["key", "ctrl+l"])
            time.sleep(0.5)
            # Use a data URI to create content without needing internet
            self.xdo(["type", "data:text/html,<h1>Forensic Evidence</h1><p>Test Artifact</p>"])
            self.xdo(["key", "Return"])
            time.sleep(3) # Wait for page load/render

    def blind_save_workflow(self):
        """
        Triggers Ctrl+S to save the webpage.
        """
        fname = f"/tmp/artifact_{random.randint(1000,9999)}.html"
        self.logger.info(f"[Action] Safe Save Workflow for {fname}")
        self.last_score = self.feedback.get_artifact_count()

        if not self.focus_app(): return

        # 1. Trigger Save
        self.xdo(["key", "ctrl+s"])
        time.sleep(2.5) # Chrome dialog might be slower to appear

        # 2. Type Filename (Blindly overwriting default)
        self.logger.info("    -> Typing Filename...")
        self.xdo(["type", "--delay", "100", fname])
        time.sleep(1.0)

        # 3. Save & Confirm
        self.logger.info("    -> Pressing Enter...")
        self.xdo(["key", "Return"])
        time.sleep(1.0)
        self.xdo(["key", "Return"]) # Confirm overwrite

        time.sleep(2) # Wait for download/save
        if self.check_feedback("Save Workflow"):
            self.logger.info(">> Fuzzer confirmed artifacts created!")

    def check_feedback(self, action_name):
        current_score = self.feedback.get_artifact_count()
        delta = current_score - self.last_score
        self.last_score = current_score
        if delta > 0:
            self.logger.info(f"[!!!] REWARD: {action_name} caused {delta} events!")
            return True
        return False

    def start(self):
        if not self.connect(): return
        self.running = True
        
        self.populate_content()
        
        start_time = time.time()
        while time.time() - start_time < self.duration:
            self.blind_save_workflow()
            # Chrome might need more time between saves
            time.sleep(5) 

if __name__ == "__main__":
    import sys
    # Default to Google Chrome if run directly
    app = sys.argv[1] if len(sys.argv) > 1 else "Google Chrome"
    fuzzer = SmartFuzzer(app, duration=60)
    fuzzer.start()
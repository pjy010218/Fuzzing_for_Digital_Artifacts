import time
import random
import logging
import os
import subprocess

class SmartFuzzer:
    def __init__(self, app_name, duration=60):
        self.app_name = app_name
        self.duration = duration
        self.logger = logging.getLogger("SmartFuzzer")
        logging.basicConfig(filename='/tmp/fuzzer_debug.log', level=logging.INFO)
        
        self.app_node = None
        self.running = False
        
        global dogtail, config
        import dogtail.tree
        import dogtail.rawinput
        from dogtail.config import config
        
        config.defaultDelay = 1.0 
        config.searchCutoffCount = 10

    def xdo(self, args):
        """Helper to run xdotool commands"""
        try:
            subprocess.run(["xdotool"] + args, check=False)
        except Exception as e:
            self.logger.error(f"xdotool failed: {e}")

    def connect(self):
        self.logger.info(f"[*] SmartFuzzer looking for app: {self.app_name}")
        start_wait = time.time()
        while time.time() - start_wait < 30:
            try:
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
        """Use xdotool to click center and type"""
        self.logger.info("[Action] Populating content via xdotool...")
        # 1. Activate Window
        self.xdo(["search", "--onlyvisible", "--name", self.app_name, "windowactivate"])
        time.sleep(1)
        
        # 2. Click Center (Assuming 1920x1080 resolution from Xvfb)
        self.xdo(["mousemove", "960", "540", "click", "1"])
        
        # 3. Type
        self.xdo(["type", "Forensic Artifact Data"])
        self.xdo(["key", "Return"])

    def blind_save_workflow(self):
        """
        Aggressive Save using raw X11 keystrokes.
        """
        fname = f"/tmp/artifact_{random.randint(1000,9999)}.txt"
        self.logger.info(f"[Action] XDO Save Workflow for {fname}")

        # 1. Ensure Focus
        self.xdo(["search", "--onlyvisible", "--name", self.app_name, "windowactivate"])
        time.sleep(0.5)

        # 2. Send Ctrl+S (Save)
        # We try both 'ctrl+s' and 'ctrl+shift+s' to be sure
        self.xdo(["key", "ctrl+s"])
        time.sleep(2.0) # Wait for Dialog Animation

        # 3. Type Path (Blindly overwrites whatever field is focused)
        # We type slowly to ensure the dialog catches it
        self.xdo(["type", "--delay", "100", fname])
        time.sleep(1.0)

        # 4. Press Enter to Save
        self.logger.info("    -> Pressing Enter...")
        self.xdo(["key", "Return"])
        
        # 5. Confirm Overwrite (Just in case)
        time.sleep(1.0)
        self.xdo(["key", "Return"])

    def start(self):
        if not self.connect(): return
        self.running = True
        
        self.populate_content()
        
        start_time = time.time()
        while time.time() - start_time < self.duration:
            self.blind_save_workflow()
            time.sleep(5) # Wait for disk write

if __name__ == "__main__":
    import sys
    app = sys.argv[1] if len(sys.argv) > 1 else "Mousepad"
    fuzzer = SmartFuzzer(app, duration=40)
    fuzzer.start()
import time
import random
import logging
import os
import subprocess
from core.fuzzing.ipc import FeedbackClient

# Dogtail 라이브러리 안전 로딩
try:
    import dogtail.tree
    import dogtail.rawinput
    from dogtail.config import config
except ImportError:
    pass

class SmartFuzzer:
    def __init__(self, app_name, duration=60):
        self.app_name = app_name
        self.duration = duration
        self.logger = logging.getLogger("SmartFuzzer")
        self.feedback = FeedbackClient()
        self.last_score = 0
        
        # 로깅 설정
        logging.basicConfig(
            filename='/tmp/fuzzer_debug.log', 
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        self.app_node = None
        self.running = False
        
        # Dogtail 설정
        if 'dogtail' in globals():
            config.defaultDelay = 0.5
            config.searchCutoffCount = 10

    def xdo(self, args):
        try: subprocess.run(["xdotool"] + args, check=False)
        except: pass

    def connect(self):
        self.logger.info(f"[*] SmartFuzzer looking for app: {self.app_name}")
        start_wait = time.time()
        while time.time() - start_wait < 30:
            try:
                target_lower = self.app_name.lower()
                for app in dogtail.tree.root.applications():
                    if target_lower in app.name.lower():
                        self.app_node = app
                        self.logger.info(f"[+] Attached to UI Tree: {app.name}")
                        return True
                time.sleep(1)
            except: time.sleep(1)
        return False

    def robust_save_workflow(self):
        fname = f"/tmp/artifact_{random.randint(1000,9999)}.html"
        self.logger.info(f"[Action] Robust Save Workflow for {fname}")
        self.last_score = self.feedback.get_artifact_count()

        try:
            # 1. 저장 단축키 (Ctrl+S)
            self.xdo(["key", "ctrl+s"])
            
            # 2. 대화상자 대기
            save_dialog = self.app_node.child(roleName="dialog", retry=True)
            if not save_dialog: return

            # 3. 파일명 입력
            text_entry = save_dialog.child(roleName="text", retry=False)
            text_entry.text = fname
            time.sleep(0.5)

            # 4. 저장 버튼 클릭
            save_dialog.child(roleName="push button", name="Save").click()
            
            # 5. 덮어쓰기 팝업 처리
            time.sleep(1)
            try:
                confirm = self.app_node.child(roleName="alert", retry=False)
                if confirm: confirm.button("Replace").click()
            except: pass

            time.sleep(2)
            self.check_feedback("Save Workflow")

        except Exception as e:
            self.logger.error(f"[-] Workflow Failed: {e}")
            self.xdo(["key", "Escape"])

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
        
        # 초기 콘텐츠 생성
        self.xdo(["key", "ctrl+l"])
        time.sleep(0.5)
        self.xdo(["type", "data:text/html,<h1>Test</h1>"])
        self.xdo(["key", "Return"])
        time.sleep(2)

        start_time = time.time()
        while time.time() - start_time < self.duration:
            self.robust_save_workflow()
            time.sleep(3) 

if __name__ == "__main__":
    import sys
    
    # 1. 앱 이름 받기
    app = sys.argv[1] if len(sys.argv) > 1 else "Google Chrome"
    
    # 2. [수정] 지속 시간(Duration) 받기
    try:
        duration_arg = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    except ValueError:
        duration_arg = 60
        
    # Dogtail 초기화
    import dogtail.tree
    import dogtail.rawinput
    from dogtail.config import config
    
    # 전달받은 시간으로 실행
    fuzzer = SmartFuzzer(app, duration=duration_arg)
    fuzzer.start()
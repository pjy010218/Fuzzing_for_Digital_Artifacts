import time
import random
import logging
import subprocess
import sys

# Dogtail 로딩
try:
    import dogtail.tree
    import dogtail.rawinput
    from dogtail.config import config
except ImportError: pass

class RandomFuzzer:
    def __init__(self, app_name, duration=60):
        self.app_name = app_name
        self.duration = duration
        self.logger = logging.getLogger("RandomFuzzer")
        self.running = False
        
        # [비교를 위한 상태 추적 변수 추가]
        self.visited_states = set()
        self.app_node = None 

        # 로깅 설정
        logging.basicConfig(
            filename='/tmp/fuzzer_debug.log', 
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        if 'dogtail' in globals():
            config.defaultDelay = 0.5
            config.searchCutoffCount = 10

    def xdo(self, args):
        try: subprocess.run(["xdotool"] + args, check=False)
        except: pass

    def connect(self):
        self.logger.info(f"[*] Connecting to App: {self.app_name}")
        start_wait = time.time()
        while time.time() - start_wait < 30:
            try:
                target_lower = self.app_name.lower()
                for app in dogtail.tree.root.applications():
                    if target_lower in app.name.lower():
                        self.app_node = app # 상태 확인을 위해 노드 저장
                        self.logger.info(f"[+] Connected to UI Tree: {app.name}")
                        return True
                time.sleep(1)
            except: time.sleep(1)
        return False

    # --- [측정용] UI State Identification (RL Fuzzer와 동일한 로직 사용) ---
    def get_current_ui_state(self):
        """
        현재 UI 상태를 식별 (단, Random Fuzzer는 이를 행동 결정에 쓰지 않고 기록만 함)
        """
        try:
            # xdotool로 윈도우 타이틀 가져오기
            win_title = subprocess.check_output(["xdotool", "getactivewindow", "getwindowname"], stderr=subprocess.DEVNULL).decode().strip()
            state_hash = f"WIN:[{win_title}]"
            return state_hash
        except:
            return "STATE_UNKNOWN"

    def act_random_click(self):
        """완전 무작위 클릭"""
        w, h = 1920, 1080
        x = random.randint(0, w)
        y = random.randint(0, h)
        self.xdo(["mousemove", str(x), str(y), "click", "1"])
        self.logger.info(f"[Action] Random Click at ({x}, {y})")

    def start(self):
        if not self.connect(): return
        self.running = True
        
        self.logger.info("[Baseline] Random Fuzzer Started (No Knowledge, No RL)")
        
        # 초기화
        self.xdo(["key", "ctrl+l"])
        time.sleep(0.5)
        self.xdo(["type", "data:text/html,<h1>Random Baseline</h1>"])
        self.xdo(["key", "Return"])
        time.sleep(2)

        start_time = time.time()
        while time.time() - start_time < self.duration:
            
            # 1. [상태 측정] 현재 상태가 무엇인지 기록 (Metric 수집용)
            current_state = self.get_current_ui_state()
            if current_state != "STATE_UNKNOWN":
                self.visited_states.add(current_state)
            
            # 2. [무작위 행동] 상태와 상관없이 그냥 클릭 (Baseline의 본질)
            self.act_random_click()
            
            # 3. [로그 기록] 비교 그래프를 그리기 위한 핵심 로그
            self.logger.info(f"[State-Metric] Total Visited States: {len(self.visited_states)}")
            
            time.sleep(2)

if __name__ == "__main__":
    import sys
    app = sys.argv[1] if len(sys.argv) > 1 else "Google Chrome"
    try:
        duration_arg = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    except ValueError:
        duration_arg = 60
        
    import dogtail.tree
    import dogtail.rawinput
    from dogtail.config import config
    
    fuzzer = RandomFuzzer(app, duration=duration_arg)
    fuzzer.start()
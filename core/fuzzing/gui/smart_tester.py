import time
import random
import logging
import os
import subprocess
import sys
from core.fuzzing.ipc import FeedbackClient

# Dogtail 로딩
try:
    import dogtail.tree
    import dogtail.rawinput
    from dogtail.config import config
except ImportError: pass

class IntelligentFuzzer:
    def __init__(self, app_name, duration=60):
        self.app_name = app_name
        self.duration = duration
        self.logger = logging.getLogger("SmartFuzzer")
        self.feedback = FeedbackClient()
        
        # [RL State]
        self.last_score = 0
        self.last_action = None
        
        # [UI State Tracking] - 여기가 핵심입니다.
        self.visited_states = set()  # 방문한 상태들의 집합 (해시 저장)
        self.current_ui_hash = "INIT"
        
        # Q-Table (행동 확장됨)
        self.q_values = {
            "targeted_click": 10.0,
            "random_click": 2.0,
            "nav_tab": 5.0,       # [NEW] 탭 이동 (탐험용)
            "nav_escape": 5.0,    # [NEW] 뒤로 가기 (탈출용)
            "hotkey_save": 5.0,
            "hotkey_print": 5.0,
            "hotkey_history": 5.0,
            "hotkey_download": 5.0,
            "hotkey_clear_data": 5.0,
            "hotkey_devtools": 2.0
        }
        
        self.epsilon = 0.3 
        self.alpha = 0.5
        
        self.knowledge_base = set()
        self.app_node = None
        self.running = False
        
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

    def _learn_from_dpkg(self):
        # (기존 dpkg 로직 유지 - 생략하지 말고 그대로 두세요)
        self.logger.info("[RL-Init] Learning from Static Analysis (dpkg)...")
        try:
            pkg_name = "google-chrome-stable" if "chrome" in self.app_name.lower() else self.app_name.lower()
            cmd = ["dpkg", "-L", pkg_name]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            for line in out.splitlines():
                basename = os.path.basename(line)
                name, _ = os.path.splitext(basename)
                if len(name) > 4 and "/" not in name:
                    self.knowledge_base.add(name.lower())
            self.knowledge_base.update(["save", "download", "print", "log", "cache", "history", "settings", "clear"])
            self.logger.info(f"[RL-Init] Knowledge Base loaded with {len(self.knowledge_base)} keywords.")
        except: pass

    def connect(self):
        # (기존 connect 로직 유지)
        start_wait = time.time()
        while time.time() - start_wait < 30:
            try:
                target_lower = self.app_name.lower()
                for app in dogtail.tree.root.applications():
                    if target_lower in app.name.lower():
                        self.app_node = app
                        self.logger.info(f"[+] Connected to UI Tree: {app.name}")
                        return True
                time.sleep(1)
            except: time.sleep(1)
        return False

    # --- [NEW] UI State Identification ---
    def get_current_ui_state(self):
        """
        현재 UI 상태를 식별하는 고유 문자열(Hash)을 반환합니다.
        정의: [활성 윈도우 이름] :: [포커스된 요소의 역할]
        """
        try:
            # 1. 현재 활성화된 윈도우/다이얼로그 찾기
            active_window = "UnknownWindow"
            # Dogtail로 최상위 윈도우 스캔
            for child in self.app_node.children:
                if child.roleName in ['frame', 'dialog', 'alert'] and child.showing:
                    active_window = child.name
                    break
            
            # 2. 포커스된 요소 찾기 (너무 깊게 탐색하면 느려지므로 주의)
            # 간단하게 xdotool로 윈도우 타이틀만 가져오는게 빠를 수 있음
            win_title = subprocess.check_output(["xdotool", "getactivewindow", "getwindowname"], stderr=subprocess.DEVNULL).decode().strip()
            
            # 상태 정의: 윈도우 제목만으로도 충분히 강력한 State 구분이 됨
            # (예: "Settings - Chrome", "Save File", "Print")
            state_hash = f"WIN:[{win_title}]"
            return state_hash
            
        except:
            return "STATE_UNKNOWN"

    # --- Expanded Actions ---

    def act_navigation(self):
        """[NEW] 탭 키를 눌러 포커스를 이동 (새로운 요소 탐색)"""
        keys = ["Tab", "Right", "Down"]
        k = random.choice(keys)
        self.xdo(["key", k])
        self.logger.info(f"[Action] Navigation -> {k}")
        return True

    def act_escape(self):
        """[NEW] Esc 키를 눌러 팝업 닫기 (State 탈출)"""
        self.xdo(["key", "Escape"])
        self.logger.info(f"[Action] Escape State")
        return True

    def act_targeted_click(self):
        # (기존 코드 유지)
        targets = []
        if not self.app_node: return False
        try:
            for child in self.app_node.findChildren(recursive=True):
                if child.roleName in ["push button", "menu", "menu item", "page tab"]:
                    name = child.name.lower() if child.name else ""
                    if any(k in name for k in self.knowledge_base):
                        targets.append(child)
        except: pass
        if targets:
            t = random.choice(targets)
            try:
                t.click()
                self.logger.info(f"[Action] Targeted Click -> '{t.name}'")
                return True
            except: return False
        return False

    def act_random_click(self):
        # (기존 코드 유지)
        w, h = 1920, 1080
        self.xdo(["mousemove", str(random.randint(0, w)), str(random.randint(0, h)), "click", "1"])
        return True

    def act_hotkey(self, key_type):
        # (기존 코드 유지)
        key_map = {
            "hotkey_save": (['ctrl', 's'], "Save"),
            "hotkey_print": (['ctrl', 'p'], "Print"),
            "hotkey_history": (['ctrl', 'h'], "History"),
            "hotkey_download": (['ctrl', 'j'], "Downloads"),
            "hotkey_clear_data": (['ctrl', 'shift', 'delete'], "Clear Data"),
            "hotkey_devtools": (['f12'], "DevTools")
        }
        if key_type not in key_map: return False
        combo, desc = key_map[key_type]
        self.xdo(["key"] + ([f"{'+'.join(combo)}"]))
        self.logger.info(f"[Action] Hotkey Injection -> {desc}")
        time.sleep(1.0)
        if 's' in combo or 'p' in combo or 'delete' in combo:
            self.xdo(["key", "Return"])
            time.sleep(0.5)
            self.xdo(["key", "Return"])
        return True

    # --- RL Logic (Modified) ---

    def choose_action(self):
        if random.random() < self.epsilon:
            action = random.choice(list(self.q_values.keys()))
            self.logger.info(f"[RL-Policy] Exploring... ({action})")
            return action
        
        sorted_actions = sorted(self.q_values.items(), key=lambda item: item[1], reverse=True)
        best_action = sorted_actions[0][0]
        self.logger.info(f"[RL-Policy] Exploiting: {best_action} (Score: {self.q_values[best_action]:.1f})")
        return best_action

    def update_q_table(self, reward, state_bonus=0):
        """
        [Novelty] 보상 = 아티팩트 생성 + 새로운 상태 발견 보너스
        """
        if not self.last_action: return
        
        old_q = self.q_values.get(self.last_action, 0.0)
        
        # 총 보상 계산
        total_reward = (reward * 10.0) + state_bonus
        
        new_q = old_q + self.alpha * total_reward
        self.q_values[self.last_action] = new_q
        
        self.logger.info(f"[RL-Learn] {self.last_action} -> Reward: {total_reward} (New Q: {new_q:.1f})")

    def perform_action(self, action_name):
        if action_name == "targeted_click":
            if not self.act_targeted_click(): self.act_random_click()
        elif action_name == "random_click":
            self.act_random_click()
        elif action_name == "nav_tab":
            self.act_navigation()
        elif action_name == "nav_escape":
            self.act_escape()
        else:
            self.act_hotkey(action_name)

    def start(self):
        if not self.connect(): return
        self.running = True
        self._learn_from_dpkg()
        
        # 초기화
        self.xdo(["key", "ctrl+l"])
        time.sleep(0.5)
        self.xdo(["type", "data:text/html,<h1>RL State Fuzzing</h1>"])
        self.xdo(["key", "Return"])
        time.sleep(2)

        start_time = time.time()
        while time.time() - start_time < self.duration:
            
            # 1. 현재 상태 파악
            current_state = self.get_current_ui_state()
            state_bonus = 0.0
            
            # [Research Value] 새로운 상태 발견 시 강력한 보상 제공
            if current_state != "STATE_UNKNOWN" and current_state not in self.visited_states:
                self.logger.info(f"[!!!] NEW STATE DISCOVERED: {current_state}")
                self.visited_states.add(current_state)
                state_bonus = 50.0 # 아티팩트 5개분량의 보상
            
            # 2. 아티팩트 보상 계산
            current_score = self.feedback.get_artifact_count()
            delta = current_score - self.last_score
            self.last_score = current_score
            
            if delta > 0:
                self.logger.info(f"[!!!] I/O REWARD: +{delta} Artifacts")
            
            # 3. 학습 (아티팩트 + 상태 보너스)
            if delta > 0 or state_bonus > 0:
                self.update_q_table(delta, state_bonus)
            
            # 4. 행동 수행
            action = self.choose_action()
            self.last_action = action
            self.perform_action(action)
            
            # 5. 상태 기록용 로그 (나중에 그래프 그리기 위함)
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
    
    fuzzer = IntelligentFuzzer(app, duration=duration_arg)
    fuzzer.start()
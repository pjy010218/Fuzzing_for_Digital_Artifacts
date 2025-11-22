import time
import random
import logging
import os
import subprocess
import sys
import json
from collections import defaultdict
from core.fuzzing.ipc import FeedbackClient

# Dogtail 라이브러리 안전 로딩
try:
    import dogtail.tree
    import dogtail.rawinput
    from dogtail.config import config
except ImportError:
    pass

class IntelligentFuzzer:
    def __init__(self, app_name, duration=60, config_path="target_config.json"):
        self.app_name = app_name
        self.duration = duration
        self.logger = logging.getLogger("SmartFuzzer")
        self.feedback = FeedbackClient()
        
        # [RL State]
        self.last_score = 0
        self.last_action = None
        self.state_visits = defaultdict(int)
        self.current_ui_hash = "INIT"
        
        # [Config] 설정 로드
        self.target_config = {}
        self._load_config(config_path)
        
        # Q-Table 초기화
        # 기본 행동 + 설정 파일에 정의된 핫키들
        self.q_values = {
            "targeted_click": 10.0,
            "random_click": 2.0,
            "nav_tab": 5.0,
            "nav_escape": 5.0
        }
        if self.target_config:
            for action_name in self.target_config.get("actions", {}):
                self.q_values[action_name] = 5.0

        # 학습 파라미터
        self.epsilon = 0.3 
        self.alpha = 0.5
        
        self.knowledge_base = set()
        self.app_node = None
        self.running = False
        
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

    def _load_config(self, path):
        """설정 파일 로드"""
        try:
            if not os.path.exists(path):
                # 현재 디렉토리에 없으면 상위 디렉토리도 검색
                path = os.path.join(os.path.dirname(__file__), "../../../", path)
            
            if os.path.exists(path):
                with open(path, 'r') as f:
                    full_config = json.load(f)
                # 앱 이름 매칭 (Google Chrome -> google-chrome)
                normalized_name = self.app_name.lower().replace(" ", "-")
                for key, cfg in full_config.items():
                    if key in normalized_name:
                        self.target_config = cfg
                        self.logger.info(f"[Config] Loaded profile for {key}")
                        break
            else:
                self.logger.warning(f"[Config] File not found: {path}")
        except Exception as e:
            self.logger.error(f"[-] Config load failed: {e}")

    def _learn_from_dpkg(self):
        self.logger.info("[RL-Init] Learning from Static Analysis (dpkg)...")
        try:
            # 설정에서 패키지명 가져오기 (없으면 앱 이름 사용)
            pkg_name = self.target_config.get("package_name", self.app_name.lower())
            
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

    def get_current_ui_state(self):
        try:
            win_title = subprocess.check_output(["xdotool", "getactivewindow", "getwindowname"], stderr=subprocess.DEVNULL).decode().strip()
            state_hash = f"WIN:[{win_title}]"
            return state_hash
        except:
            return "STATE_UNKNOWN"

    # --- Actions ---
    def act_navigation(self):
        keys = ["Tab", "Right", "Down"]
        k = random.choice(keys)
        self.xdo(["key", k])
        self.logger.info(f"[Action] Navigation -> {k}")
        return True

    def act_escape(self):
        self.xdo(["key", "Escape"])
        self.logger.info(f"[Action] Escape State")
        return True

    def act_targeted_click(self):
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
        w, h = 1920, 1080
        self.xdo(["mousemove", str(random.randint(0, w)), str(random.randint(0, h)), "click", "1"])
        return True

    def act_hotkey(self, action_name):
        """설정 파일 기반 핫키 주입"""
        actions = self.target_config.get("actions", {})
        if action_name not in actions:
            return False
        
        combo_data = actions[action_name] # [["ctrl", "s"], "Description"]
        keys = combo_data[0]
        desc = combo_data[1]
        
        self.xdo(["key"] + ([f"{'+'.join(keys)}"]))
        self.logger.info(f"[Action] Hotkey Injection -> {desc}")
        
        time.sleep(1.0)
        # 팝업 승인 (엔터)
        if 's' in keys or 'p' in keys or 'delete' in keys:
            self.xdo(["key", "Return"])
            time.sleep(0.5)
            self.xdo(["key", "Return"])
        return True

    # --- RL Logic ---
    def choose_action(self):
        if random.random() < self.epsilon:
            action = random.choice(list(self.q_values.keys()))
            self.logger.info(f"[RL-Policy] Exploring... ({action})")
            return action
        
        sorted_actions = sorted(self.q_values.items(), key=lambda item: item[1], reverse=True)
        best_action = sorted_actions[0][0]
        self.logger.info(f"[RL-Policy] Exploiting: {best_action} (Score: {self.q_values[best_action]:.1f})")
        return best_action

    def update_q_table(self, reward):
        if not self.last_action: return
        old_q = self.q_values.get(self.last_action, 0.0)
        new_q = old_q + self.alpha * reward
        self.q_values[self.last_action] = new_q
        self.logger.info(f"[RL-Learn] {self.last_action} -> Reward: {reward:.1f} (New Q: {new_q:.1f})")

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
        self.xdo(["type", "data:text/html,<h1>Forensic Re-enactor</h1>"])
        self.xdo(["key", "Return"])
        time.sleep(2)

        self.last_score = self.feedback.get_artifact_count()
        self.logger.info(f"[Init] Baseline Score Synced: {self.last_score}")

        start_time = time.time()
        while time.time() - start_time < self.duration:
            
            # 1. 상태 파악 & 보상 계산
            current_state = self.get_current_ui_state()
            self.state_visits[current_state] += 1
            visit_count = self.state_visits[current_state]
            
            state_reward = 0.0
            if current_state != "STATE_UNKNOWN":
                if visit_count == 1:
                    self.logger.info(f"[!!!] NEW STATE DISCOVERED: {current_state}")
                    state_reward = 50.0 
                else:
                    state_reward = -1.0 * (visit_count - 1) # Decay
            
            current_score = self.feedback.get_artifact_count()
            delta = current_score - self.last_score
            self.last_score = current_score
            
            artifact_reward = 0.0
            if delta > 0:
                self.logger.info(f"[!!!] I/O REWARD: +{delta} Artifacts (Weighted)")
                # Orchestrator가 이미 가중치를 적용한 점수를 보내주므로 그대로 사용
                artifact_reward = delta 
            else:
                artifact_reward = -2.0 
            
            total_reward = artifact_reward + state_reward
            self.update_q_table(total_reward)
            
            # 2. 행동 수행
            action = self.choose_action()
            self.last_action = action
            self.perform_action(action)
            
            self.logger.info(f"[State-Metric] Total Visited States: {len(self.state_visits)}")
            time.sleep(2)

if __name__ == "__main__":
    app = sys.argv[1] if len(sys.argv) > 1 else "Google Chrome"
    try:
        duration_arg = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    except ValueError:
        duration_arg = 60
        
    # Config 파일 경로를 3번째 인자로 받을 수도 있도록 처리 (옵션)
    # 현재 Orchestrator는 3번째 인자로 duration을, 4번째로 target_file을 씀.
    # SmartTester는 app, duration만 받으면 됨. Config는 기본값 사용.
    
    import dogtail.tree
    import dogtail.rawinput
    from dogtail.config import config
    
    fuzzer = IntelligentFuzzer(app, duration=duration_arg)
    fuzzer.start()
import time
import random
import logging
import os
import hashlib
import subprocess
import sys
import traceback

def exception_handler(type, value, tb):
    print("".join(traceback.format_exception(type, value, tb)), file=sys.stderr)

sys.excepthook = exception_handler

import json
from collections import defaultdict
from core.fuzzing.ipc import FeedbackClient

# [Check] 디렉토리 구조가 core/fuzzing/gui/actions/library.py 인지 확인 필요
from core.fuzzing.gui.actions.library import FuzzerActions

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
        self.interacted_elements = set()
        self.current_ui_hash = "INIT"

        # [Logic] 행동 반복 횟수 추적 (지루함 구현용)
        self.action_counts = defaultdict(int)
        self.consecutive_repeats = 0 # 연속 반복 횟수

        # [Config]
        self.target_config = {}
        self._load_config(config_path)
        
        # [Library] 행동 라이브러리 연결
        self.actions = FuzzerActions(self)
        
        # Q-Table (초기값 조정: UI 탐색에 더 높은 기대값 부여)
        self.q_values = {
            "ui_crawl": 20.0,       # [Up] 10.0 -> 20.0 (탐색 장려)
            "ui_input": 15.0,       # [Up] 8.0 -> 15.0
            "menu_exploration": 25.0, # [Up] 메뉴는 매우 중요함
            "dialog_handler": 30.0, # [Priority] 대화상자는 무조건 처리
            "nav_tab": 5.0,
            "nav_escape": 5.0,
            "random_click": 2.0
        }
        if self.target_config:
            for action_name in self.target_config.get("actions", {}):
                # 핫키는 너무 남발하지 않도록 초기값 유지
                self.q_values[action_name] = 5.0

        self.epsilon = 0.5 
        self.alpha = 0.4
        self.knowledge_base = set()
        self.app_node = None
        self.running = False
        
        log_path = os.environ.get("FUZZER_LOG_PATH", f"/tmp/fuzzer_debug_{os.getpid()}.log")
        logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        
        if 'dogtail' in globals():
            config.defaultDelay = 0.5
            config.searchCutoffCount = 10

    def _load_config(self, path):
        try:
            if not os.path.exists(path):
                path = os.path.join(os.path.dirname(__file__), "../../../", path)
            if os.path.exists(path):
                with open(path, 'r') as f:
                    full_config = json.load(f)
                normalized_name = self.app_name.lower().replace(" ", "-")
                for key, cfg in full_config.items():
                    if key in normalized_name:
                        self.target_config = cfg
                        self.logger.info(f"[Config] Loaded profile for {key}")
                        break
        except Exception as e:
            self.logger.error(f"[-] Config load failed: {e}")

    def _learn_from_dpkg(self):
        self.logger.info("[RL-Init] Learning from Static Analysis (dpkg)...")
        try:
            pkg_name = self.target_config.get("package_name", self.app_name.lower())
            cmd = ["dpkg", "-L", pkg_name]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            for line in out.splitlines():
                basename = os.path.basename(line)
                name, _ = os.path.splitext(basename)
                if len(name) > 4 and "/" not in name:
                    self.knowledge_base.add(name.lower())
            self.knowledge_base.update(["save", "download", "print", "log", "cache", "history", "settings", "clear"])
        except: pass

    def connect(self):
        self.logger.info(f"[*] SmartFuzzer looking for app: {self.app_name}")
        start_wait = time.time()
        target_pkg = self.target_config.get("package_name", self.app_name).lower()
        
        while time.time() - start_wait < 30:
            try:
                for app in dogtail.tree.root.applications():
                    name_match = self.app_name.lower() in app.name.lower()
                    pkg_match = target_pkg in app.name.lower()
                    if name_match or pkg_match:
                        self.app_node = app
                        self.logger.info(f"[+] Connected to UI Tree: {app.name}")
                        return True
                time.sleep(1)
            except: time.sleep(1)
        
        self.logger.error(f"[-] Failed to find app '{self.app_name}' in UI tree.")
        print(f"[-] TIMEOUT: Could not find '{self.app_name}'.", file=sys.stderr)
        return False

    def get_current_ui_state(self):
        try:
            win_title = subprocess.check_output(["xdotool", "getactivewindow", "getwindowname"], stderr=subprocess.DEVNULL).decode().strip()
            return hashlib.md5(f"WIN:[{win_title}]".encode()).hexdigest()
        except: return "STATE_UNKNOWN"

    def wait_for_state_change(self, old_state_hash, timeout=2.0):
        start = time.time()
        while time.time() - start < timeout:
            current_hash = self.get_current_ui_state()
            if current_hash != old_state_hash:
                time.sleep(0.2)
                return current_hash
            time.sleep(0.5)
        return old_state_hash

    def verify_login_state(self):
        # [FIX] 긍정 검증(버튼 찾기) 대신 부정 검증(로그인 화면 아님) 사용
        self.logger.info("[Check] Verifying login state (Negative Check)...")
        print("[DEBUG] verify_login_state: Started.", file=sys.stderr)
        
        start = time.time()
        while time.time() - start < 30:
            try:
                # 현재 활성 윈도우 제목 가져오기
                # Discord는 로그인 전에는 "Discord", 로그인 후에는 "친구 - Discord" 또는 "채널명 - Discord"로 바뀜
                win_title = subprocess.check_output(["xdotool", "getactivewindow", "getwindowname"], stderr=subprocess.DEVNULL).decode().strip()
                print(f"[DEBUG] Current Window Title: {win_title}", file=sys.stderr)
                
                # 로그인 화면의 특징이 보이면 실패
                # (로그인 화면에는 보통 'Welcome back!' 텍스트가 있음 -> dogtail로 확인 가능하지만 느림)
                # 윈도우 제목으로 1차 필터링
                
                if "Discord" in win_title:
                    # 로그인 성공 시 제목이 바뀜 (친구, 채널명 등)
                    # "Discord"만 딱 있으면 로그인 화면일 수도 있고 로딩일 수도 있음
                    # 하지만 "친구"나 "General" 같은 단어가 포함되면 확실히 로그인 된 것임
                    
                    # [조건] "Discord" 단독이 아니고, 다른 단어가 포함되어 있으면 성공으로 간주
                    if len(win_title) > 7 and win_title != "Discord":
                         self.logger.info(f"[Check] Login Verified by Title: {win_title}")
                         return True

                # [Backup] UI 요소 검색 (Login 버튼이 없는지 확인)
                # 로그인 화면에는 'Log In' 버튼이 있음. 이게 없으면 로그인 된 것으로 간주.
                login_btn = self.app_node.findChild(lambda x: "Log In" in x.name, recursive=True, retry=False)
                if not login_btn:
                    self.logger.info("[Check] 'Log In' button NOT found. Assuming logged in.")
                    return True
                    
            except Exception as e:
                # 에러 나면 아직 로딩 중일 수 있으니 대기
                pass
            
            time.sleep(1)
            
        self.logger.error("[Check] Login Verification FAILED (Timeout).")
        return False

    # --- [NEW] Improved RL Logic ---

    def choose_action(self):
        """
        [Smart Selection]
        단순 Q-Value 비교가 아니라, '반복 횟수(Fatigue)'를 패널티로 적용하여
        다양한 행동을 시도하도록 유도합니다.
        """
        # 1. 탐험 (Epsilon)
        if random.random() < self.epsilon:
            return random.choice(list(self.q_values.keys()))
        
        # 2. 활용 (Exploitation with Fatigue Penalty)
        candidates = []
        for action, q_val in self.q_values.items():
            # [Logic] 같은 행동을 많이 할수록 가중치(Effective Q)를 깎음
            # 예: hotkey_print를 10번 했으면 -5점 패널티
            penalty = self.action_counts[action] * 0.5
            
            # 연속으로 같은 걸 하려 하면 패널티 2배
            if action == self.last_action:
                penalty += (self.consecutive_repeats * 2.0)
                
            effective_q = q_val - penalty
            candidates.append((action, effective_q))
        
        # 점수 높은 순 정렬
        candidates.sort(key=lambda x: x[1], reverse=True)
        
        best_action = candidates[0][0]
        best_q = candidates[0][1]
        
        self.logger.info(f"[RL-Select] Best: {best_action} (Eff-Q: {best_q:.1f})")
        return best_action

    def update_q_table(self, reward, action_success=True):
        if not self.last_action: return
        
        # 행동 카운트 갱신
        self.action_counts[self.last_action] += 1
        
        # [Logic] 행동 수행 실패(예: 클릭할 게 없음) 시 큰 패널티
        if not action_success:
            reward -= 5.0
        
        old_q = self.q_values.get(self.last_action, 0.0)
        new_q = old_q + self.alpha * reward
        self.q_values[self.last_action] = new_q
        
        self.logger.info(f"[RL-Learn] {self.last_action} -> R:{reward:.1f} / Q:{new_q:.1f} (Count: {self.action_counts[self.last_action]})")

    def perform_action(self, action_name):
        success = False
        
        # 연속 실행 체크
        if action_name == self.last_action:
            self.consecutive_repeats += 1
        else:
            self.consecutive_repeats = 0
            
        if action_name == "targeted_click":
            success = self.actions.act_targeted_click()
        elif action_name == "random_click":
            success = self.actions.act_random_click()
        elif action_name == "nav_tab":
            success = self.actions.act_navigation()
        elif action_name == "nav_escape":
            success = self.actions.act_escape()
        elif action_name == "ui_crawl":
            success = self.actions.act_ui_crawl() # [중요] library.py가 True/False 반환해야 함
        elif action_name == "ui_input":
            success = self.actions.act_ui_input()
        elif action_name == "menu_exploration":
            success = self.actions.act_menu_exploration()
        elif action_name == "dialog_handler":
            success = self.actions.act_dialog_handler()
        else:
            success = self.actions.act_hotkey(action_name)
            
        return success

    def start(self):
        if not self.connect(): return
        if not self.verify_login_state():
            self.logger.error("[-] ABORTING: Target app is not in logged-in state.")
            return

        self.running = True
        print("[DEBUG] start: Learning dpkg...", file=sys.stderr)
        self._learn_from_dpkg()
        
        # 초기화
        self.actions.xdo(["key", "ctrl+l"]) # xdo도 라이브러리 통해 호출 권장
        time.sleep(0.5)
        self.actions.xdo(["type", "data:text/html,<h1>Target-Driven AI</h1>"])
        self.actions.xdo(["key", "Return"])
        time.sleep(2)

        self.last_score = self.feedback.get_artifact_count()
        self.logger.info(f"[Init] Score Synced: {self.last_score}")

        print("[DEBUG] start: Initializing loop...", file=sys.stderr)
        start_time = time.time()
        current_state = self.get_current_ui_state()
        print(f"[DEBUG] start: Initial State = {current_state}", file=sys.stderr)

        initial_epsilon = 0.5
        min_epsilon = 0.05
        
        while time.time() - start_time < self.duration:
            elapsed = time.time() - start_time
            progress = elapsed / self.duration
            self.epsilon = max(min_epsilon, initial_epsilon - ((initial_epsilon - min_epsilon) * progress))

            # 1. 상태 보상
            current_state = self.get_current_ui_state()
            self.state_visits[current_state] += 1
            visit_count = self.state_visits[current_state]
            
            state_reward = 0.0
            if current_state != "STATE_UNKNOWN":
                if visit_count == 1:
                    self.logger.info(f"[!!!] NEW STATE: {current_state}")
                    state_reward = 50.0
                else:
                    state_reward = -1.0 # 방문할수록 매력 감소

            # 2. 아티팩트 보상
            current_score = self.feedback.get_artifact_count()
            delta = current_score - self.last_score
            self.last_score = current_score
            
            artifact_reward = 0.0
            if delta > 0:
                self.logger.info(f"[!!!] REWARD: +{delta}")
                artifact_reward = delta * 10.0
            
            # [Logic] 내적 동기 (Intrinsic Motivation)
            # 아티팩트가 없어도(delta=0), 행동 자체가 성공(UI 클릭 등)했으면 작은 보상
            
            # 3. 행동 선택 및 수행
            print("[DEBUG] start: Choosing action...", file=sys.stderr)
            action = self.choose_action()
            
            # 이전 행동에 대한 학습은 '지금' 함 (Reward가 이제야 확정되었으므로)
            # (맨 처음 루프에서는 last_action이 None이라 학습 안함)
            self.update_q_table(artifact_reward + state_reward, action_success=True) # 성공 여부는 일단 True 가정

            print(f"[DEBUG] start: Performing action '{action}'...", file=sys.stderr)
            action_success = self.perform_action(action)
            
            # 실패했으면 즉시 패널티 (다음 턴 학습에 반영하거나 즉시 반영)
            if not action_success:
                # 즉시 가벼운 패널티 학습
                self.last_action = action
                self.update_q_table(-2.0, action_success=False)
            
            self.last_action = action
            
            print("[DEBUG] start: Action performed. Waiting...", file=sys.stderr)
            time.sleep(0.5)
            
            self.logger.info(f"[Stats] States: {len(self.state_visits)} | Nodes: {len(self.interacted_elements)}")
            
            current_state = self.wait_for_state_change(current_state, timeout=2.0)

if __name__ == "__main__":
    import sys
    app = sys.argv[1] if len(sys.argv) > 1 else "Google Chrome"
    dur = 60
    config_path = "target_config.json"
    
    if len(sys.argv) > 2: 
        try: dur = int(sys.argv[2])
        except: pass
    if len(sys.argv) > 3: config_path = sys.argv[3]
    
    fuzzer = IntelligentFuzzer(app, duration=dur, config_path=config_path)
    fuzzer.start()
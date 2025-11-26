import time
import random
import logging
import os
import hashlib
import subprocess
import sys
import json
from collections import defaultdict
from core.fuzzing.ipc import FeedbackClient

from core.fuzzing.gui.actions.library import FuzzerActions

# Dogtail 라이브러리 안전 로딩
try:
    import dogtail.tree
    import dogtail.rawinput
    from dogtail.config import config
    from dogtail.predicate import GenericPredicate
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

        # [Config]
        self.target_config = {}
        self._load_config(config_path)
        
        # [Refactor] Initialize Actions Library
        self.actions = FuzzerActions(self)
        
        # Q-Table (행동 확장)
        self.q_values = {
            "ui_crawl": 10.0,      # [NEW] UI 요소 탐색 및 클릭
            "ui_input": 8.0,       # [NEW] 텍스트 입력 시도
            "menu_exploration": 12.0,# [NEW] 메뉴 열기 및 항목 클릭
            "nav_tab": 5.0,
            "nav_escape": 5.0,
            "random_click": 3.0
        }
        # 핫키 추가
        if self.target_config:
            for action_name in self.target_config.get("actions", {}):
                self.q_values[action_name] = 5.0

        self.epsilon = 0.5 
        self.alpha = 0.4
        self.knowledge_base = set()
        self.app_node = None
        self.running = False
        
        log_path = os.environ.get("FUZZER_LOG_PATH", f"/tmp/fuzzer_debug_{os.getpid()}.log")
        logging.basicConfig(
            filename=log_path, 
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        if 'dogtail' in globals():
            config.defaultDelay = 0.5
            config.searchCutoffCount = 10

    def xdo(self, args):
        # Proxy to actions library for compatibility if needed, or remove if unused internally
        self.actions.xdo(args)

    def _load_config(self, path):
        """설정 파일 로드"""
        try:
            if not os.path.exists(path):
                # 현재 디렉토리에 없으면 상위 디렉토리도 검색
                path = os.path.join(os.path.dirname(__file__), "../../../", path)
            
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        full_config = json.load(f)
                except json.JSONDecodeError:
                    self.logger.error(f"[-] Invalid JSON in config: {path}")
                    return
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
        if 'dogtail' not in globals():
            self.logger.error("[-] Dogtail library not loaded. Cannot connect to UI.")
            return False

        self.logger.info(f"[*] SmartFuzzer looking for app: {self.app_name}")
        
        # [DEBUG] 찾고자 하는 이름 출력
        print(f"[DEBUG] Searching for target: '{self.app_name}'", file=sys.stderr)
        
        start_wait = time.time()
        
        # 설정에서 패키지명 가져오기
        target_pkg = self.target_config.get("package_name", self.app_name).lower()
        
        while time.time() - start_wait < 30:
            try:
                apps = dogtail.tree.root.applications()
                
                # [DEBUG] 현재 감지된 모든 앱 이름 출력 (5초마다 한 번씩만 출력하여 로그 폭주 방지)
                if int(time.time()) % 5 == 0:
                    visible_apps = [app.name for app in apps]
                    print(f"[DEBUG] Currently visible apps (AT-SPI): {visible_apps}", file=sys.stderr)

                for app in apps:
                    # 1. 이름 매칭
                    name_match = self.app_name.lower() in app.name.lower()
                    # 2. 패키지명 매칭
                    pkg_match = target_pkg in app.name.lower()
                    
                    if name_match or pkg_match:
                        self.app_node = app
                        self.logger.info(f"[+] Connected to UI Tree: {app.name}")
                        print(f"[DEBUG] SUCCESS: Connected to '{app.name}'", file=sys.stderr)
                        return True
                time.sleep(1)
            except Exception as e:
                # 접근성 트리 접근 실패 시 에러 출력
                # print(f"[DEBUG] AT-SPI Tree Error: {e}", file=sys.stderr) 
                time.sleep(1)
            
        self.logger.error(f"[-] Failed to find app '{self.app_name}' in UI tree.")
        if 'visible_apps' in locals():
            print(f"[-] TIMEOUT: Could not find '{self.app_name}'. Last seen apps: {visible_apps}", file=sys.stderr)
        return False

    def get_current_ui_state(self):
        state_str = ""
        try:
            # 1. 윈도우 제목
            win_title = subprocess.check_output(["xdotool", "getactivewindow", "getwindowname"], stderr=subprocess.DEVNULL).decode().strip()
            state_str += f"TITLE:{win_title}|"
            
            # 2. UI 트리 해싱 (성능 고려하여 깊이 제한)
            if self.app_node:
                active_window = self.app_node.child(roleName='frame', recursive=False)
                if not active_window: active_window = self.app_node
                
                elements = []
                # 메뉴나 팝업이 떠있는지 확인하는 것이 중요
                for node in active_window.findChildren(lambda x: x.roleName in ['menu', 'dialog', 'alert'] and x.showing, recursive=True):
                    elements.append(f"{node.roleName}:{node.name}")
                
                elements.sort()
                state_str += "|".join(elements)
                
            return hashlib.md5(state_str.encode('utf-8')).hexdigest()
        except:
            return "STATE_UNKNOWN"

    def wait_for_state_change(self, old_state_hash, timeout=2.0):
        """
        [Dynamic Wait]
        이전 상태 해시(old_state_hash)와 현재 상태 해시를 비교하여,
        화면이 바뀌었으면 즉시 리턴하고, 안 바뀌었으면 최대 timeout까지 기다립니다.
        """
        start_time = time.time()
        check_interval = 0.5 # UI 트리 탐색 부하를 고려해 간격을 0.5초로 설정
        
        while time.time() - start_time < timeout:
            current_hash = self.get_current_ui_state()
            
            if current_hash != old_state_hash:
                # 상태 변화 감지! 
                # UI가 안정화될 시간을 아주 조금만 더 줍니다 (렌더링 완료 대기)
                time.sleep(0.2)
                return current_hash
            
            time.sleep(check_interval)
        
        # 타임아웃: 상태가 변하지 않음 (변화가 없는 행동이었거나 로딩이 매우 느림)
        return old_state_hash

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
            if not self.actions.act_targeted_click(): self.actions.act_random_click()
        elif action_name == "random_click":
            self.actions.act_random_click()
        elif action_name == "nav_tab":
            self.actions.act_navigation()
        elif action_name == "nav_escape":
            self.actions.act_escape()
        elif action_name == "ui_crawl":
            if not self.actions.act_ui_crawl(): self.actions.act_random_click()
        elif action_name == "ui_input":
            if not self.actions.act_ui_input(): self.actions.act_random_click()
        elif action_name == "menu_exploration":
            if not self.actions.act_menu_exploration(): self.actions.act_random_click()
        else:
            self.actions.act_hotkey(action_name)

    def start(self):
        if not self.connect(): return
        self.running = True
        self._learn_from_dpkg()
        
        # 초기화
        self.xdo(["key", "ctrl+l"])
        time.sleep(0.5)
        self.xdo(["type", "data:text/html,<h1>Autonomous Mode</h1>"])
        self.xdo(["key", "Return"])
        time.sleep(2)

        self.last_score = self.feedback.get_artifact_count()
        self.logger.info(f"[Init] Score Synced: {self.last_score}")

        start_time = time.time()
        current_state = self.get_current_ui_state()
        
        # [RL Parameter] 초기값 및 최소값 설정
        initial_epsilon = 0.5
        min_epsilon = 0.05
        
        while time.time() - start_time < self.duration:
            # -------------------------------------------------------
            # [NEW] Adaptive Epsilon: 시간에 따라 선형 감소 (Linear Decay)
            # -------------------------------------------------------
            elapsed = time.time() - start_time
            progress = elapsed / self.duration  # 0.0 (시작) ~ 1.0 (종료)
            
            # 공식: 시작할 때 0.5 -> 끝날 때 0.05로 서서히 감소
            self.epsilon = max(min_epsilon, initial_epsilon - ((initial_epsilon - min_epsilon) * progress))
            
            # 디버깅용: 현재 엡실론 값 로깅 (선택 사항)
            # self.logger.info(f"[RL-Param] Epsilon: {self.epsilon:.2f}")
            # -------------------------------------------------------

            # 1. 상태 방문 체크 및 보상
            self.state_visits[current_state] += 1
            visit_count = self.state_visits[current_state]
            
            state_reward = 0.0
            if current_state != "STATE_UNKNOWN":
                if visit_count == 1:
                    self.logger.info(f"[!!!] NEW STATE: {current_state}")
                    state_reward = 50.0
                else:
                    state_reward = -1.0 * (visit_count - 1)

            # 2. 아티팩트 보상
            current_score = self.feedback.get_artifact_count()
            delta = current_score - self.last_score
            self.last_score = current_score
            
            artifact_reward = delta * 10.0 if delta > 0 else -2.0
            if delta > 0: self.logger.info(f"[!!!] REWARD: +{delta}")
            
            self.update_q_table(artifact_reward + state_reward)
            
            # 3. 행동 수행
            action = self.choose_action()
            self.last_action = action
            self.perform_action(action)
            
            self.logger.info(f"[Stats] States: {len(self.state_visits)} | Nodes: {len(self.interacted_elements)}")
            
            # 4. 스마트 대기
            current_state = self.wait_for_state_change(current_state, timeout=2.0)

if __name__ == "__main__":
    # (기존과 동일한 인자 처리)
    app = "Google Chrome"
    dur = 60
    config_path = "target_config.json"
    
    if len(sys.argv) > 1: app = sys.argv[1]
    if len(sys.argv) > 2: 
        try: dur = int(sys.argv[2])
        except: pass
    if len(sys.argv) > 3: config_path = sys.argv[3]
    
    fuzzer = IntelligentFuzzer(app, duration=dur, config_path=config_path)
    fuzzer.start()
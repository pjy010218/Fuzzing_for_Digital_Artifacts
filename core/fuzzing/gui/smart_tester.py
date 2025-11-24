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
        
        # [UI Exploration Memory]
        # 방문한 요소의 해시를 저장하여 중복 클릭 방지 (Exploration 유도)
        self.interacted_elements = set()
        
        # [Config]
        self.target_config = {}
        self._load_config(config_path)
        
        # Q-Table (행동 확장)
        self.q_values = {
            "ui_crawl": 10.0,      # [NEW] UI 요소 탐색 및 클릭
            "ui_input": 8.0,       # [NEW] 텍스트 입력 시도
            "nav_tab": 5.0,
            "nav_escape": 5.0,
            "random_click": 2.0
        }
        # 핫키 추가
        if self.target_config:
            for action_name in self.target_config.get("actions", {}):
                self.q_values[action_name] = 5.0

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
        print(f"[-] TIMEOUT: Could not find '{self.app_name}'. Last seen apps: {visible_apps}", file=sys.stderr)
        return False
            
        self.logger.error(f"[-] Failed to find app '{self.app_name}' in UI tree.")
        return False

    def get_current_ui_state(self):
        try:
            win_title = subprocess.check_output(["xdotool", "getactivewindow", "getwindowname"], stderr=subprocess.DEVNULL).decode().strip()
            return f"WIN:[{win_title}]"
        except: return "STATE_UNKNOWN"

    def _get_interactable_elements(self):
        """현재 화면에서 클릭/입력 가능한 모든 요소를 수집하고 점수를 매깁니다."""
        candidates = []
        if not self.app_node: return []

        try:
            # 현재 활성화된 윈도우/다이얼로그 하위만 검색 (성능 최적화)
            active_window = self.app_node.child(roleName='frame', recursive=False) # 메인 프레임
            # 팝업이 있으면 팝업 우선
            for child in self.app_node.children:
                if child.roleName == 'dialog' and child.showing:
                    active_window = child
                    break
            
            if not active_window: active_window = self.app_node

            # 재귀 검색 (깊이 제한 필요할 수 있음)
            # Dogtail의 findChildren은 느릴 수 있으므로 roleName으로 필터링
            # 관심 Role: menu, push button, page tab, text, combo box, check box
            interesting_roles = ['menu', 'push button', 'page tab', 'text', 'combo box', 'check box', 'menu item']
            
            for node in active_window.findChildren(lambda x: x.roleName in interesting_roles and x.showing, recursive=True):
                name = node.name.lower() if node.name else ""
                role = node.roleName
                
                # 점수 계산 (Scoring)
                score = 1.0
                
                # 1. Knowledge Base 매칭 (높은 점수)
                if any(k in name for k in self.knowledge_base):
                    score += 10.0
                
                # 2. Action Verb 매칭 (중간 점수)
                if any(v in name for v in ["save", "ok", "apply", "next", "yes", "print"]):
                    score += 5.0
                
                # 3. Novelty (처음 보는 요소면 가산점)
                node_hash = f"{name}_{role}_{node.position}"
                if node_hash not in self.interacted_elements:
                    score += 5.0
                else:
                    score -= 2.0 # 이미 눌러본 건 감점

                candidates.append((node, score, node_hash))
                
        except: pass
        
        # 점수 높은 순 정렬
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates

    def act_ui_crawl(self):
        """[NEW] 화면 분석 후 가장 유망한 요소 클릭"""
        candidates = self._get_interactable_elements()
        
        if not candidates:
            self.logger.info("[Crawl] No interactable elements found.")
            return False
        
        # Top 3 중 하나 랜덤 선택 (탐험성 유지)
        target, score, node_hash = random.choice(candidates[:3])
        
        try:
            self.logger.info(f"[Action] UI Crawl -> Clicking '{target.name}' ({target.roleName}) [Score: {score}]")
            
            # 클릭 수행
            target.click()
            self.interacted_elements.add(node_hash)
            
            # 메뉴 아이템이었다면 닫힐 때까지 잠시 대기
            if target.roleName == 'menu':
                time.sleep(0.5)
                
            return True
        except Exception as e:
            self.logger.warning(f"[Crawl] Interaction failed: {e}")
            return False

    def act_ui_input(self):
        """[NEW] 입력창을 찾아 포렌식적으로 유의미한 텍스트 주입"""
        try:
            # 텍스트 필드 찾기
            text_fields = self.app_node.findChildren(lambda x: x.roleName == 'text' and x.showing, recursive=True)
            if not text_fields: return False
            
            target = random.choice(text_fields)
            self.logger.info(f"[Action] UI Input -> Typing into '{target.name}'")
            
            # 포커스 후 입력
            target.grabFocus()
            time.sleep(0.2)
            
            # 입력할 문자열 (URL, 검색어 등)
            payloads = ["file:///etc/passwd", "search_history", "http://malicious.com", "secret_password"]
            text = random.choice(payloads)
            
            self.xdo(["type", text])
            self.xdo(["key", "Return"])
            return True
        except: return False

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
        self.xdo(["type", "data:text/html,<h1>Autonomous Mode</h1>"])
        self.xdo(["key", "Return"])
        time.sleep(2)

        self.last_score = self.feedback.get_artifact_count()
        self.logger.info(f"[Init] Score Synced: {self.last_score}")

        start_time = time.time()
        while time.time() - start_time < self.duration:
            current_state = self.get_current_ui_state()
            self.state_visits[current_state] += 1
            visit_count = self.state_visits[current_state]
            
            state_reward = 0.0
            if current_state != "STATE_UNKNOWN":
                if visit_count == 1:
                    self.logger.info(f"[!!!] NEW STATE: {current_state}")
                    state_reward = 50.0
                else:
                    state_reward = -1.0 * (visit_count - 1)

            current_score = self.feedback.get_artifact_count()
            delta = current_score - self.last_score
            self.last_score = current_score
            
            artifact_reward = delta * 10.0 if delta > 0 else -2.0
            if delta > 0: self.logger.info(f"[!!!] REWARD: +{delta}")
            
            self.update_q_table(artifact_reward + state_reward)
            
            action = self.choose_action()
            self.last_action = action
            self.perform_action(action)
            
            self.logger.info(f"[Stats] States: {len(self.state_visits)} | Explored Nodes: {len(self.interacted_elements)}")
            
            time.sleep(2)

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
import time
import random
import logging
import os
import subprocess
import sys
from core.fuzzing.ipc import FeedbackClient

# Dogtail 라이브러리 안전 로딩
try:
    import dogtail.tree
    import dogtail.rawinput
    from dogtail.config import config
except ImportError:
    pass

class IntelligentFuzzer:
    def __init__(self, app_name, duration=60):
        self.app_name = app_name
        self.duration = duration
        self.logger = logging.getLogger("SmartFuzzer")
        self.feedback = FeedbackClient()
        
        # [RL] 상태 및 학습 변수
        self.last_score = 0
        self.last_action = None  # 직전에 수행한 행동 이름
        
        # Q-Table: 행동별 점수 (초기값 부여)
        # 점수가 높을수록 아티팩트를 많이 생성하는 행동임
        self.q_values = {
            "targeted_click": 10.0, # 신뢰도 높음
            "random_click": 2.0,    # 신뢰도 낮음
            "hotkey_save": 5.0,
            "hotkey_print": 5.0,
            "hotkey_history": 5.0,
            "hotkey_download": 5.0,
            "hotkey_clear_data": 5.0,
            "hotkey_devtools": 2.0
        }
        
        # 학습 파라미터
        self.epsilon = 0.3      # 탐험 확률 (30%는 딴짓하기)
        self.alpha = 0.5        # 학습률 (최근 결과 반영 비율)
        
        # 지식 베이스 (정적 분석)
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

    def _learn_from_dpkg(self):
        """
        [Knowledge] 정적 분석을 통해 앱의 파일 구조 학습
        """
        self.logger.info("[RL-Init] Learning from Static Analysis (dpkg)...")
        try:
            pkg_name = "google-chrome-stable" if "chrome" in self.app_name.lower() else self.app_name.lower()
            cmd = ["dpkg", "-L", pkg_name]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            
            count = 0
            for line in out.splitlines():
                basename = os.path.basename(line)
                name, _ = os.path.splitext(basename)
                if len(name) > 4 and "/" not in name:
                    self.knowledge_base.add(name.lower())
                    count += 1
            
            # 필수 키워드 보강
            self.knowledge_base.update(["save", "download", "print", "log", "cache", "history", "settings", "clear"])
            self.logger.info(f"[RL-Init] Knowledge Base loaded with {len(self.knowledge_base)} keywords.")
            
        except Exception as e:
            self.logger.warning(f"[RL-Init] Static Analysis failed: {e}")

    def connect(self):
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

    # --- [RL] 행동 정의 (Action Definitions) ---

    def act_targeted_click(self):
        """지식 기반 클릭"""
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
        """무작위 탐색"""
        w, h = 1920, 1080
        self.xdo(["mousemove", str(random.randint(0, w)), str(random.randint(0, h)), "click", "1"])
        return True

    def act_hotkey(self, key_type):
        """의미론적 단축키 주입"""
        # 매핑 테이블
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
        # 팝업 승인 (엔터 연타)
        if 's' in combo or 'p' in combo or 'delete' in combo:
            self.xdo(["key", "Return"])
            time.sleep(0.5)
            self.xdo(["key", "Return"])
        
        return True

    # --- [RL] 핵심 로직 (Core Logic) ---

    def choose_action(self):
        """
        Epsilon-Greedy 정책으로 행동 선택
        """
        # 1. Exploration (탐험): 무작위 선택
        if random.random() < self.epsilon:
            action = random.choice(list(self.q_values.keys()))
            self.logger.info(f"[RL-Policy] Exploring... ({action})")
            return action
        
        # 2. Exploitation (활용): 점수 높은 것 선택
        # 점수 기준으로 내림차순 정렬 후 상위권 선택
        sorted_actions = sorted(self.q_values.items(), key=lambda item: item[1], reverse=True)
        best_action = sorted_actions[0][0]
        self.logger.info(f"[RL-Policy] Exploiting Best Strategy: {best_action} (Score: {self.q_values[best_action]:.1f})")
        return best_action

    def update_q_table(self, reward):
        """
        보상(Reward)을 받아 Q-Value 업데이트
        공식: Q_new = Q_old + alpha * (Reward)
        """
        if not self.last_action: return
        
        old_q = self.q_values.get(self.last_action, 0.0)
        # 아티팩트 1개당 10점 부여 (가중치 강화)
        boosted_reward = reward * 10.0
        
        new_q = old_q + self.alpha * boosted_reward
        self.q_values[self.last_action] = new_q
        
        self.logger.info(f"[RL-Learn] Updated {self.last_action}: {old_q:.1f} -> {new_q:.1f}")

    def perform_action(self, action_name):
        """이름에 맞는 행동 실행"""
        if action_name == "targeted_click":
            success = self.act_targeted_click()
            # 타겟 클릭 실패 시 랜덤 클릭으로 대체 (Fallback)
            if not success: self.act_random_click()
        elif action_name == "random_click":
            self.act_random_click()
        else:
            self.act_hotkey(action_name)

    def start(self):
        if not self.connect(): return
        self.running = True
        
        # 정적 분석 수행
        # self._learn_from_dpkg()
        self.logger.info("[Baseline] Random Fuzzer Started. (No Knowledge Base, No RL Used)")
        
        # 초기 콘텐츠 생성
        self.xdo(["key", "ctrl+l"])
        time.sleep(0.5)
        self.xdo(["type", "data:text/html,<h1>RL Fuzzing</h1>"])
        self.xdo(["key", "Return"])
        time.sleep(2)

        start_time = time.time()
        while time.time() - start_time < self.duration:
            
            # 1. 이전 행동에 대한 보상 계산
            # current_score = self.feedback.get_artifact_count()
            # delta = current_score - self.last_score
            
            # if delta > 0:
            #     self.logger.info(f"[!!!] REWARD: +{delta} Artifacts created!")
            #     self.update_q_table(delta)
            
            # self.last_score = current_score
            
            # 2. 다음 행동 선택 (RL)
            # action = self.choose_action()
            # self.last_action = action
            
            # 3. 행동 수행
            # self.perform_action(action)

            self.act_random_click()
            self.logger.info("[Action] Random Click (Baseline Mode)")
            time.sleep(2) # 반응 대기

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
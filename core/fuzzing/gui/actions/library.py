import time
import random
import subprocess
import logging
import sys

class FuzzerActions:
    def __init__(self, fuzzer_instance):
        self.fuzzer = fuzzer_instance
        self.logger = logging.getLogger("FuzzerActions")

    def xdo(self, args):
        try: subprocess.run(["xdotool"] + args, check=False)
        except: pass

    def _get_interactable_elements(self):
        """[Ultra-Safe] BFS 탐색 (Recursive 제거)"""
        candidates = []
        if not self.fuzzer.app_node: 
            self.logger.warning("[Crawl-Debug] App node is None!")
            return []

        try:
            # 1. 시작점: 활성 윈도우 찾기 (직계 자식만 검색)
            print("[DEBUG-LIB] Finding active window...", file=sys.stderr)
            active_window = self.fuzzer.app_node
            for child in self.fuzzer.app_node.children:
                if child.roleName == 'frame':
                    active_window = child
                    break
            
            print(f"[DEBUG-LIB] Active window: {active_window.name if active_window else 'None'}", file=sys.stderr)

            # 2. 수동 BFS (recursive=True 사용 안 함)
            queue = [(active_window, 0)]
            visited = set()
            
            # Electron 앱에서 유효한 Role들
            target_roles = {'push button', 'menu', 'page tab', 'entry', 'link', 'document web', 'section', 'toggle button'}
            
            scan_limit = 100 # 더 줄임 (안전 제일)
            scanned_count = 0

            print("[DEBUG-LIB] Starting BFS loop...", file=sys.stderr)
            while queue and scanned_count < scan_limit:
                curr_node, depth = queue.pop(0)
                
                # 노드 식별자 생성 (Hashable하게)
                try:
                    node_id = (curr_node.name, curr_node.roleName, str(curr_node.position))
                    if node_id in visited: continue
                    visited.add(node_id)
                except: continue
                
                scanned_count += 1

                # 후보 등록
                try:
                    role = curr_node.roleName
                    if role in target_roles:
                        # 좌표 유효성 체크
                        x, y = curr_node.position
                        w, h = curr_node.size
                        if w > 0 and h > 0 and 0 <= x <= 1920 and 0 <= y <= 1080:
                            name = curr_node.name.lower() if curr_node.name else ""
                            score = 1.0
                            if any(k in name for k in self.fuzzer.knowledge_base): score += 10.0
                            
                            candidates.append((curr_node, score, f"{name}_{role}_{x}_{y}"))
                except: pass # 개별 노드 에러 무시

                # 자식 노드 큐에 추가 (최대 깊이 3)
                if depth < 3:
                    try:
                        # children 속성 접근 자체가 느릴 수 있으므로 타임아웃 고려 (여기선 try-except로 방어)
                        for child in curr_node.children:
                            queue.append((child, depth + 1))
                    except: pass
            
            print(f"[DEBUG-LIB] Scan finished. Found {len(candidates)} candidates.", file=sys.stderr)
                    
        except Exception as e:
            print(f"[DEBUG-LIB] Critical Error: {e}", file=sys.stderr)
            self.logger.error(f"UI Scan Critical Error: {e}")
        
        # 결과 반환
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates

    def act_drag_and_drop(self):
        """
        [New Action] 요소를 클릭한 상태로 다른 위치로 드래그합니다.
        파일 이동, 슬라이더 조작, 텍스트 블록 선택 등의 효과를 냅니다.
        """
        candidates = self._get_interactable_elements()
        if not candidates: return False
        
        # 드래그 시작점 (Source) 선택
        target, score, node_hash = random.choice(candidates[:5]) if len(candidates) > 5 else random.choice(candidates)
        
        try:
            # 1. 시작 좌표 계산
            x1, y1 = target.position
            w, h = target.size
            start_x = x1 + w // 2
            start_y = y1 + h // 2
            
            # 2. 도착 좌표 계산 (Destination)
            # 화면 내의 임의의 위치로 드래그 (또는 다른 요소 위로 드래그)
            dest_x = random.randint(0, 1920)
            dest_y = random.randint(0, 1080)
            
            self.logger.info(f"[Action] Drag & Drop -> '{target.name}' from ({start_x},{start_y}) to ({dest_x},{dest_y})")
            
            # 3. 드래그 수행 (xdotool 사용)
            # mousemove (시작점) -> mousedown (1번버튼) -> mousemove (끝점) -> mouseup
            self.xdo(["mousemove", str(start_x), str(start_y)])
            time.sleep(0.2)
            self.xdo(["mousedown", "1"])
            time.sleep(0.5) # 드래그 중 체류 시간
            self.xdo(["mousemove", str(dest_x), str(dest_y)])
            time.sleep(0.5)
            self.xdo(["mouseup", "1"])
            
            # 상태 추적 업데이트
            self.fuzzer.interacted_elements.add(node_hash)
            return True
            
        except Exception as e:
            self.logger.warning(f"[Drag] Failed: {e}")
            return False

    def act_menu_exploration(self):
        """
        [New Action] 메뉴를 열고 하위 항목을 랜덤하게 클릭하는 시퀀스 행동
        """
        try:
            # 1. 메뉴 버튼 찾기 (보통 'menu button'이나 이름이 'Application menu'임)
            # Dogtail로 'menu button' 역할을 가진 요소를 찾음
            menu_btns = self.fuzzer.app_node.findChildren(lambda x: x.roleName == 'toggle button' and 'menu' in x.name.lower(), recursive=True)
            
            if not menu_btns:
                # Firefox/Chrome의 메인 메뉴 버튼은 보통 툴바 안에 있음
                toolbar = self.fuzzer.app_node.child(roleName='tool bar')
                menu_btns = toolbar.children
            
            if not menu_btns: return False

            # 2. 메뉴 열기
            target_menu = random.choice(menu_btns)
            target_menu.click()
            time.sleep(0.5) # 메뉴 펼쳐질 시간 대기
            
            # 3. 펼쳐진 메뉴 아이템 스캔 및 클릭
            steps = random.randint(1, 5)
            for _ in range(steps):
                self.xdo(["key", "Down"])
                time.sleep(0.1)
            
            self.xdo(["key", "Return"])
            self.logger.info(f"[Action] Menu Exploration -> Opened menu and clicked item {steps}")
            return True
            
        except: return False

    def act_ui_crawl(self):
        candidates = self._get_interactable_elements()
        if not candidates: return False
        
        # 상위권에서 랜덤 선택
        target, score, node_hash = random.choice(candidates[:5]) if len(candidates) > 5 else random.choice(candidates)
        
        try:
            self.logger.info(f"[Action] UI Crawl -> Activating '{target.name}' ({target.roleName})")
            
            # [FIX] 마우스 클릭 대신 키보드 실행 시도 (Robustness 강화)
            try:
                # 1. 요소에 포커스 맞추기
                target.grabFocus()
                time.sleep(0.2)
                # 2. 엔터 키로 실행
                self.xdo(["key", "Return"])
            except:
                # 포커스 실패 시 마우스 클릭으로 Fallback
                target.click()

            self.fuzzer.interacted_elements.add(node_hash)
            if target.roleName == 'menu': time.sleep(0.5)
            return True
        except Exception as e:
            self.logger.warning(f"[Crawl] Interaction failed: {e}")
            return False

    def act_ui_input(self):
        try:
            text_fields = self.fuzzer.app_node.findChildren(lambda x: x.roleName == 'text' and x.showing, recursive=True)
            if not text_fields: return False
            target = random.choice(text_fields)
            
            self.logger.info(f"[Action] UI Input -> Typing into '{target.name}'")
            target.grabFocus()
            time.sleep(0.2)
            
            payloads = ["test", "admin", "1234", "file:///etc/passwd", "javascript:alert(1)"]
            text = random.choice(payloads)
            
            self.xdo(["type", text])
            self.xdo(["key", "Return"])
            return True
        except: return False

    def act_dialog_handler(self):
        """
        [Robustness] 대화상자(Dialog)가 떴을 때 이를 '해결'하는 전용 로직
        """
        try:
            # 현재 윈도우가 Dialog인지 확인
            active = self.fuzzer.app_node.child(roleName='dialog', recursive=False)
            if not active or not active.showing: return False
            
            self.logger.info("[Action] Dialog Handler Triggered!")
            
            # 1. 텍스트 필드가 있다면 무조건 채운다 (파일명 등)
            text_fields = active.findChildren(lambda x: x.roleName == 'text', recursive=True)
            for tf in text_fields:
                if tf.showing:
                    tf.grabFocus()
                    self.xdo(["type", "fuzz_artifact.txt"])
                    time.sleep(0.5)
                    
            # 2. 긍정 버튼(Save/OK)을 찾아 누른다 (또는 엔터)
            # Gedit은 헤더바에 버튼이 있을 수 있음
            buttons = active.findChildren(lambda x: x.roleName == 'push button', recursive=True)
            for btn in buttons:
                if any(k in btn.name.lower() for k in ['save', 'ok', 'open', 'create']):
                    self.logger.info(f"    -> Clicking positive button: {btn.name}")
                    btn.click()
                    return True
            
            # 버튼 못 찾았으면 엔터로 마무리
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
        if not self.fuzzer.app_node: return False
        try:
            for child in self.fuzzer.app_node.findChildren(recursive=True):
                if child.roleName in ["push button", "menu", "menu item", "page tab"]:
                    name = child.name.lower() if child.name else ""
                    if any(k in name for k in self.fuzzer.knowledge_base):
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
        try:
            # Try to get actual screen geometry
            out = subprocess.check_output(["xdotool", "getdisplaygeometry"], stderr=subprocess.DEVNULL).decode().split()
            w, h = int(out[0]), int(out[1])
        except: pass
        
        self.xdo(["mousemove", str(random.randint(0, w)), str(random.randint(0, h)), "click", "1"])
        return True

    def act_hotkey(self, action_name):
        """설정 파일 기반 핫키 주입"""
        actions = self.fuzzer.target_config.get("actions", {})
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

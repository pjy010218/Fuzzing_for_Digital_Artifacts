import os
import time
import json
import signal
import logging
import subprocess
import shutil
import sys
from typing import List, Dict, Optional, Set, Any

from core.tracer.ebpf_engine import EBPFTracer
from core.fuzzing.gui.xvfb_display import XvfbDisplay
from core.metadata.extractor import MetadataExtractor
from core.fuzzing.ipc import FeedbackServer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Orchestrator")

class ArtifactDiscoverySession:
    def __init__(self, 
                 target_cmd: List[str], 
                 app_name: str,
                 duration: int = 60, 
                 output_dir: str = "./experiment_data",
                 target_state_file: str = None,
                 config_path: str = "target_config.json"):
        
        self.app_name = app_name
        self.duration = duration
        self.output_dir = os.path.join(output_dir, f"{app_name}_{int(time.time())}")
        
        # [FIX] 디렉토리 먼저 생성 (가장 중요!)
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 1. 설정 로드
        self.config = self._load_or_generate_config(config_path, app_name)
        
        # 2. 런타임 설정 저장 (이제 디렉토리가 있으므로 성공함)
        self.runtime_config_path = os.path.join(self.output_dir, "runtime_config.json")
        with open(self.runtime_config_path, 'w') as f:
            json.dump({app_name: self.config}, f, indent=2)
            
        # ... (나머지 초기화 코드 동일) ...
        # 타겟 로드
        self.targets_config: List[Any] = []
        self.found_targets: Set[str] = set()
        if target_state_file:
            self._load_target_state(target_state_file)

        self.chrome_user_dir = f"/tmp/chrome_fuzz_profile_{int(time.time())}_{os.getpid()}"
        
        # Tracer 설정
        target_proc = self.config.get("process_name", app_name.lower())
        self.tracer = EBPFTracer(
            interest_patterns=[self.chrome_user_dir, "/home", "/tmp"],
            ignore_patterns=["Singleton", "LOCK", ".so", "FontConfig", "dconf", "goutputstream", "__pycache__", "GPUCache"]
        )
        
        self.extractor = MetadataExtractor()
        self.ipc_server = FeedbackServer()
        self.proc: Optional[subprocess.Popen] = None
        self.fuzzer_proc: Optional[subprocess.Popen] = None
        self.all_events = []

    def _load_or_generate_config(self, path, app_name) -> Dict:
        """
        설정 파일에 있으면 로드하고, 없으면 시스템에서 자동 탐지하여 생성합니다.
        """
        # 1. 기존 설정 파일 확인
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    full_config = json.load(f)
                normalized_name = app_name.lower().replace(" ", "-")
                for key, cfg in full_config.items():
                    if key in normalized_name:
                        logger.info(f"[Config] Found existing profile for {key}")
                        return cfg
        except Exception as e:
            logger.warning(f"[-] Config load error: {e}")

        # 2. 없으면 자동 생성 (Auto-Discovery)
        logger.info(f"[Config] No profile found for '{app_name}'. Attempting Auto-Discovery...")
        
        # A. 바이너리 찾기 (which)
        binary_path = shutil.which(app_name)
        if not binary_path:
            # 소문자로 한 번 더 시도
            binary_path = shutil.which(app_name.lower())
        
        if not binary_path:
            logger.error(f"[-] Could not find executable for '{app_name}'.")
            return {}

        # B. 패키지명 찾기 (dpkg)
        package_name = app_name.lower()
        try:
            out = subprocess.check_output(["dpkg", "-S", binary_path], stderr=subprocess.DEVNULL).decode()
            package_name = out.split(":")[0].strip()
        except: pass

        # C. 기본 핫키 설정 (표준 단축키)
        default_actions = {
            "hotkey_save": [["ctrl", "s"], "Save File"],
            "hotkey_open": [["ctrl", "o"], "Open File"],
            "hotkey_print": [["ctrl", "p"], "Print"],
            "hotkey_find": [["ctrl", "f"], "Find"],
            "hotkey_new": [["ctrl", "n"], "New Window/Tab"],
            "hotkey_quit": [["ctrl", "q"], "Quit"]
        }

        generated_config = {
            "binary_cmd": [binary_path],
            "package_name": package_name,
            "process_name": os.path.basename(binary_path),
            "user_dir_flag": "--user-data-dir", # 기본값 (앱마다 다를 수 있음은 감안)
            "actions": default_actions
        }
        
        logger.info(f"[Config] Auto-generated profile: {generated_config}")
        return generated_config

    def _load_target_state(self, path):
        try:
            with open(path, 'r') as f:
                self.targets_config = json.load(f)
            logger.info(f"[Target-Mode] Loaded {len(self.targets_config)} target rules.")
        except Exception:
            self.targets_config = []

    def _setup_inputs(self):
        logger.info("[Phase 0] Setting up environment...")
        if os.path.exists(self.chrome_user_dir):
            shutil.rmtree(self.chrome_user_dir, ignore_errors=True)
        os.makedirs(self.chrome_user_dir, exist_ok=True)

    def calculate_reward(self, new_events):
        total_score = 0.0
        for event in new_events:
            fpath = event['filename']
            base_score = self.extractor.calculate_forensic_score(fpath)
            
            target_bonus = 0.0
            if self.targets_config:
                meta = self.extractor.extract(fpath)
                for target in self.targets_config:
                    target_path = None
                    if isinstance(target, str): target_path = target
                    elif isinstance(target, dict): target_path = target.get('path') or target.get('path_pattern')
                    
                    if not target_path: continue
                    if target_path not in fpath: continue
                        
                    if isinstance(target, dict):
                        if 'min_size' in target:
                            if not meta or meta['size'] < target['min_size']: continue
                        if 'content_key' in target:
                            if not meta: continue
                            if target['content_key'] not in str(meta.get('content_summary', {})): continue

                    target_bonus = 500.0
                    if fpath not in self.found_targets:
                        logger.info(f"[★ PRECISE MATCH] {fpath} matches target!")
                        self.found_targets.add(fpath)
                    break
            total_score += (base_score + target_bonus)
        return int(total_score)

    def run(self):
        logger.info(f"[*] Starting Session for {self.app_name}")
        self._setup_inputs()
        self.ipc_server.start()

        with XvfbDisplay(display_id=99, res="1920x1080x24") as xvfb:
            logger.info("[Phase 1] Initializing eBPF Tracer...")
            
            target_proc = self.config.get("process_name", "chrome")
            self.tracer.start_trace(root_pid=0, target_name=target_proc) 
            time.sleep(2) 
            
            # 실행 명령어 구성
            cmd = self.config.get("binary_cmd", []).copy()
            
            # 환경변수 설정
            target_env = os.environ.copy()
            target_env["GTK_MODULES"] = "gail:atk-bridge" 
            target_env["NO_AT_BRIDGE"] = "0"
            target_env["PYTHONPATH"] = os.getcwd()
            
            if "DBUS_SESSION_BUS_ADDRESS" in os.environ:
                target_env["DBUS_SESSION_BUS_ADDRESS"] = os.environ["DBUS_SESSION_BUS_ADDRESS"]

            # 앱 특화 플래그 (Chrome/Firefox 등)
            if "chrome" in self.app_name.lower():
                 user_dir_flag = self.config.get("user_dir_flag", "--user-data-dir")
                 cmd.extend(["--no-sandbox", "--disable-gpu", "--force-renderer-accessibility", "--no-first-run"])
                 cmd.append(f"{user_dir_flag}={self.chrome_user_dir}")
            elif "firefox" in self.app_name.lower():
                 # Firefox 설정은 target_config.json에 이미 독립형 경로가 있다고 가정하거나
                 # auto-discovery된 경로 사용. 추가 플래그만 붙임.
                 # (이미 config에 binary_cmd가 완성되어 있으면 그대로 둠)
                 pass
            else:
                 # 일반 앱 (vscode, gedit 등)은 그냥 실행
                 pass

            logger.info(f"[Phase 2] Launching Target: {' '.join(cmd)}")

            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid, env=target_env)
            except FileNotFoundError:
                logger.error(f"Target executable not found: {cmd[0]}")
                return

            time.sleep(5) # 앱 실행 대기 (좀 더 넉넉하게)
            
            logger.info("[Phase 3] Starting Smart Fuzzer...")
            
            # [FIX] 생성된 런타임 설정을 Fuzzer에게 전달해야 함
            # 원래는 인자로 파일 경로를 줄 수 있지만, SmartTester 코드를 수정하지 않고
            # 같은 폴더의 'target_config.json' 대신 'runtime_config.json'을 읽게 하려면
            # SmartTester의 코드를 약간 수정하거나, 여기서 심볼릭 링크를 걸 수도 있음.
            # 가장 깔끔한 건 SmartTester가 인자를 하나 더 받게 하는 것.
            
            fuzzer_script_name = os.environ.get("FUZZER_SCRIPT", "smart_tester.py")
            current_dir = os.path.dirname(os.path.abspath(__file__))
            fuzzer_path = os.path.join(current_dir, "gui", fuzzer_script_name)
            if not os.path.exists(fuzzer_path): fuzzer_path = os.path.join(current_dir, fuzzer_script_name)

            # Fuzzer 실행 (인자: 앱이름, 시간, 설정파일경로)
            # 주의: 기존에는 3번째가 target_file이었는데, SmartTester는 config_path를 인자로 받도록 수정 필요.
            # 하지만 SmartTester __init__을 보면 config_path="target_config.json"이 기본값.
            # 따라서 SmartTester 코드를 조금 수정하여 argv[3]으로 config_path를 받게 해야 함.
            
            self.fuzzer_proc = subprocess.Popen(
                [sys.executable, fuzzer_path, self.app_name, str(self.duration), self.runtime_config_path], 
                env=target_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            
            start_time = time.time()
            total_score = 0.0
            total_artifacts_count = 0
            
            try:
                while True:
                    if time.time() - start_time >= self.duration:
                        logger.info("[DEBUG] Loop exiting: Duration expired.")
                        break
                    if self.proc.poll() is not None:
                        logger.warning("[-] Target application exited early.")
                        break
                    if self.fuzzer_proc.poll() is not None:
                        out, err = self.fuzzer_proc.communicate()
                        logger.error(f"[-] Fuzzer process died. Stderr: {err.decode() if err else 'None'}")
                        break

                    new_events = self.tracer.get_events()
                    if new_events:
                        self.all_events.extend(new_events)
                        total_artifacts_count += len(new_events)
                        
                        reward = self.calculate_reward(new_events)
                        total_score += reward
                        self.ipc_server.update_count(int(total_score))
                        
                        if self.targets_config and len(self.found_targets) >= len(self.targets_config):
                             if not hasattr(self, '_mission_logged'):
                                logger.info("[!!!] MISSION COMPLETE: All targets reproduced! (Continuing...)")
                                self._mission_logged = True
                             pass 

                    time.sleep(1)
            except KeyboardInterrupt: pass

            logger.info("[Phase 3.5] Draining remaining events...")
            final_events = self.tracer.get_events()
            if final_events:
                self.all_events.extend(final_events)
                total_artifacts_count += len(final_events)
                total_score += self.calculate_reward(final_events)
                logger.info(f"[+] Final Artifact Count: {total_artifacts_count} | Final Score: {total_score:.1f}")
                self.ipc_server.update_count(int(total_score))

            logger.info("[Phase 4] Stopping experiment...")
            self._cleanup()

        self._analyze_results()

    def _cleanup(self):
        if self.fuzzer_proc: self.fuzzer_proc.terminate()
        self.ipc_server.stop()
        self.tracer.stop_trace()
        if self.proc:
            try: os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except: pass

    def _analyze_results(self):
        logger.info("[Phase 5] Analyzing captured artifacts...")
        events = self.all_events
        
        actions = []
        log_path = "/tmp/fuzzer_debug.log"
        
        import re
        from datetime import datetime
        
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", errors='ignore') as f:
                    for line in f:
                        if "[Action]" in line:
                            try:
                                time_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                                if not time_match: continue
                                dt = datetime.strptime(time_match.group(1), "%Y-%m-%d %H:%M:%S")
                                action_desc = line.split("[Action]")[-1].strip()
                                actions.append({"time": dt.timestamp(), "action": action_desc})
                            except: continue
                logger.info(f"Parsed {len(actions)} fuzzer actions from log")
            except Exception as e:
                logger.warning(f"Error reading fuzzer log: {e}")

        unique_artifacts = {}
        for e in events:
            fname = e['filename']
            created_time = e['timestamp']
            
            if fname not in unique_artifacts:
                likely_cause = "Unknown (Background)"
                best_gap = 5.0 
                if actions:
                    for act in reversed(actions):
                        gap = created_time - act['time']
                        if 0 <= gap < best_gap:
                            likely_cause = act['action']
                            break
                
                unique_artifacts[fname] = {"syscalls": set(), "processes": set(), "cause_action": likely_cause}
            
            unique_artifacts[fname]["syscalls"].add(e['type'])
            unique_artifacts[fname]["processes"].add(e['process_name'])

        report = []
        for filepath, data in unique_artifacts.items():
            exists = os.path.exists(filepath)
            meta = self.extractor.extract(filepath) if exists else "File Deleted or Inaccessible"
            artifact_entry = {
                "filepath": filepath,
                "cause_action": data["cause_action"],
                "interactions": list(data["syscalls"]),
                "accessed_by": list(data["processes"]),
                "exists_on_disk": exists,
                "metadata": meta
            }
            report.append(artifact_entry)

        output_json = os.path.join(self.output_dir, "artifact_footprint.json")
        try:
            with open(output_json, "w") as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"[Success] Report saved to {output_json}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")


if __name__ == "__main__":
    app = "Google Chrome"
    dur = 120
    target_file = None
    
    if len(sys.argv) > 1: app = sys.argv[1]
    if len(sys.argv) > 2:
        try:
            dur = int(sys.argv[2])
        except ValueError:
            dur = 120
    if len(sys.argv) > 3: target_file = sys.argv[3]
    
    session = ArtifactDiscoverySession(
        target_cmd=["google-chrome"], 
        app_name=app, 
        duration=dur,
        target_state_file=target_file
    )
    session.run()
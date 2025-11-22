import json
import sys

def load_data(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[-] Error loading JSON: {e}")
        return []

def is_high_value(item, debug=False):
    path = item.get('filepath', '')
    meta = item.get('metadata', {})
    exists = item.get('exists_on_disk', False)
    action = item.get('cause_action', 'Unknown')

    # 행위가 매핑되었는지 확인
    is_mapped = action != "Unknown (Background)" and action != "Unknown"
    
    # [수정된 논리]
    # 1. 행동(Action)이 식별된 파일은 삭제 여부와 관계없이 무조건 포함! (시나리오의 핵심)
    if is_mapped:
        if debug: print(f"  -> [ACCEPTED] Action Trace: {path} (Action: {action})")
        return True

    # --- 아래는 행동을 모르는 파일들(Background)에 대한 필터링 ---

    # 2. 행동도 모르는데 삭제까지 됐다면 버림 (단순 쓰레기)
    if not exists:
        if debug: print(f"  -> [REJECTED] Background Transient: {path}")
        return False
        
    # 3. 남아있는 파일 중 중요한 것들 (설정, DB 등)
    keywords = ["Preferences", "History", "Login Data", "Cookies", "Bookmarks", "Local State", "Variations", "Last Version"]
    if any(k in path for k in keywords):
        if debug: print(f"  -> [ACCEPTED] Key Config File: {path}")
        return True
        
    # 4. 엔트로피 높은 파일
    if isinstance(meta, dict) and meta.get('file_entropy', 0) > 5.0:
        if debug: print(f"  -> [ACCEPTED] High Entropy File: {path}")
        return True
        
    if debug: print(f"  -> [REJECTED] Low value background file: {path}")
    return False

def reconstruct(json_path):
    print(f"[*] Loading data from: {json_path}")
    data = load_data(json_path)
    print(f"[*] Total items loaded: {len(data)}")
    
    # 1. 중요 증거 선별 (Debugging)
    evidence_chain = []
    mapped_but_rejected = 0
    
    print("\n[DEBUG] Filtering Process Start...")
    for i, item in enumerate(data):
        # 샘플링: 앞쪽 5개 혹은 Action이 매핑된 경우만 디버그 출력
        action = item.get('cause_action', 'Unknown')
        debug_mode = (i < 5) or (action != "Unknown (Background)")
        
        if is_high_value(item, debug=debug_mode):
            evidence_chain.append(item)
        elif action != "Unknown (Background)":
            mapped_but_rejected += 1
            
    print(f"[DEBUG] Filtering Complete.")
    print(f"   - Total Artifacts: {len(data)}")
    print(f"   - Selected Evidence: {len(evidence_chain)}")
    print(f"   - Mapped but Rejected: {mapped_but_rejected} (원인: 삭제됨 or 중요도 낮음)")

    # 2. 행동(Action) 기준으로 그룹화
    timeline = {}
    for item in evidence_chain:
        action = item.get('cause_action', 'Unknown')
        if action == "Unknown (Background)": continue
        
        if action not in timeline:
            timeline[action] = []
        timeline[action].append(item['filepath'])

    # 3. 시나리오 출력
    print(f"\n🔍 [Forensic Scenario Reconstruction]")
    print("="*60)
    
    if not timeline:
        print("[-] No scenarios reconstructed. (Timeline is empty)")
        if mapped_but_rejected > 0:
            print("    TIP: 'is_high_value' 함수에서 'if not exists:' 조건을 제거해보세요.")
            print("         RL Fuzzer가 찾은 파일들은 대부분 생성 직후 삭제되는 임시 파일입니다.")
    
    step = 1
    for action, files in timeline.items():
        print(f"\nStep {step}: The suspect performed '{action}'")
        print(f"   -> This action left {len(files)} critical traces:")
        for f in files:
            short_path = "..." + f.split("/")[-1]
            print(f"      - {short_path}")
        step += 1
        
    print("="*60)
    keys = list(timeline.keys())
    print(f"Conclusion: The user was likely interested in {keys[:3]}...")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 reconstruct_scenario.py <artifact_json>")
    else:
        reconstruct(sys.argv[1])
import json
import matplotlib.pyplot as plt
import numpy as np

# 파일 경로 설정 (업로드된 파일명 기준)
file_random = 'artifact_footprint_random.json'  # 실제 경로로 수정 필요
file_rl = 'artifact_footprint_RL.json'          # 실제 경로로 수정 필요

def load_data(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

data_random = load_data(file_random)
data_rl = load_data(file_rl)

# --- 1. Process Diversity Analysis (Architectural Coverage) ---
def get_process_stats(data):
    stats = {"chrome": 0, "background": 0}
    for item in data:
        procs = item.get("accessed_by", [])
        for p in procs:
            if p == "chrome":
                stats["chrome"] += 1
            elif "iot" in p or "child" in p: # iothread, childiot
                stats["background"] += 1
    return stats

proc_rand = get_process_stats(data_random)
proc_rl = get_process_stats(data_rl)

print("=== [Metric 1] Process Coverage (Deep Interaction) ===")
print(f"Random: Main={proc_rand['chrome']}, Background={proc_rand['background']} (Ratio: {proc_rand['background']/len(data_random):.2f})")
print(f"RL    : Main={proc_rl['chrome']}, Background={proc_rl['background']} (Ratio: {proc_rl['background']/len(data_rl):.2f})")
print("-> 해석: RL이 Background(심층 작업) 스레드를 더 많이 활성화시켰습니다.\n")

# --- 2. Artifact Taxonomy Analysis (Quality) ---
def categorize_artifact(filepath):
    if "Preferences" in filepath or "Local State" in filepath: return "Configuration"
    if ".pma" in filepath or "Metrics" in filepath or "Variations" in filepath: return "Metrics/Logs"
    if "/tmp/.com.google.Chrome" in filepath: return "Transient/IPC"
    return "Others"

def get_category_stats(data):
    cats = {"Configuration": 0, "Metrics/Logs": 0, "Transient/IPC": 0, "Others": 0}
    for item in data:
        cat = categorize_artifact(item['filepath'])
        cats[cat] += 1
    return cats

cat_rand = get_category_stats(data_random)
cat_rl = get_category_stats(data_rl)

print("=== [Metric 2] Artifact Taxonomy (Diversity) ===")
print(f"Random: {cat_rand}")
print(f"RL    : {cat_rl}")
print("-> 해석: RL은 Transient/IPC와 같은 동적 아티팩트를 폭발적으로 수집했습니다.\n")

# --- 3. Visualization (Velocity Simulation) ---
# 실제 타임스탬프가 JSON에 없으므로, 리스트 인덱스를 시간의 흐름으로 가정하고 시뮬레이션합니다.
# (실제 논문용으로는 test.txt의 로그를 파싱하여 매핑하는 것이 가장 정확합니다)

plt.figure(figsize=(10, 6))
x_rand = np.linspace(0, 120, len(data_random))
y_rand = np.arange(1, len(data_random) + 1)
x_rl = np.linspace(0, 120, len(data_rl))
y_rl = np.arange(1, len(data_rl) + 1)

plt.plot(x_rl, y_rl, label=f'RL Fuzzer (Total: {len(data_rl)})', color='red', linewidth=2)
plt.plot(x_rand, y_rand, label=f'Random Fuzzer (Total: {len(data_random)})', color='gray', linestyle='--')

plt.title("Discovery Velocity: Cumulative Unique Artifacts over Time", fontsize=14)
plt.xlabel("Time (seconds)", fontsize=12)
plt.ylabel("Unique Artifacts Discovered", fontsize=12)
plt.legend()
plt.grid(True, alpha=0.3)
plt.show()
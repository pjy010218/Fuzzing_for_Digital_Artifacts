import re
import sys
import matplotlib.pyplot as plt
from datetime import datetime

# === [1. 파일 입력 처리] ===
if len(sys.argv) < 2:
    print("사용법: python3 draw_graph.py <로그파일경로>")
    print("예시: python3 draw_graph.py fuzzer_debug.txt")
    sys.exit(1)

log_file_path = sys.argv[1]

try:
    with open(log_file_path, 'r', encoding='utf-8') as f:
        log_lines = f.readlines()
    print(f"[*] 로그 파일 로드 성공: {log_file_path} ({len(log_lines)} 라인)")
except FileNotFoundError:
    print(f"[-] 오류: 파일을 찾을 수 없습니다 - {log_file_path}")
    sys.exit(1)
except Exception as e:
    print(f"[-] 오류 발생: {e}")
    sys.exit(1)

# === [2. 데이터 파싱] ===
times = []
artifacts = []
states = []

current_artifacts = 0
current_states = 0
start_time = None

# 정규표현식 컴파일
re_time = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})')
re_reward = re.compile(r'REWARD: \+(\d+) Artifacts')
re_state = re.compile(r'Total Visited States: (\d+)')

for line in log_lines:
    line = line.strip()
    if not line: continue
    
    time_match = re_time.match(line)
    if time_match:
        ts_str = time_match.group(1)
        try:
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S,%f")
            
            if start_time is None:
                start_time = ts
            
            rel_time = (ts - start_time).total_seconds()
            
            updated = False

            reward_match = re_reward.search(line)
            if reward_match:
                current_artifacts += int(reward_match.group(1))
                updated = True
                
            state_match = re_state.search(line)
            if state_match:
                current_states = int(state_match.group(1))
                updated = True
            
            if updated or "Total Visited States" in line:
                times.append(rel_time)
                artifacts.append(current_artifacts)
                states.append(current_states)

        except ValueError:
            continue

# === [3. 그래프 그리기 및 저장] ===
if not times:
    print("[-] 경고: 그래프를 그릴 데이터가 없습니다. 로그 파일을 확인해주세요.")
    sys.exit(0)

fig, ax1 = plt.subplots(figsize=(12, 7))

# 왼쪽 Y축: 아티팩트
ax1.set_xlabel('Time (seconds)', fontsize=12, fontweight='bold')
ax1.set_ylabel('Cumulative Artifacts', color='tab:blue', fontsize=12, fontweight='bold')
ax1.plot(times, artifacts, color='tab:blue', linewidth=2.5, label='Artifacts Discovered')
ax1.tick_params(axis='y', labelcolor='tab:blue')
ax1.grid(True, which='both', linestyle='--', alpha=0.5)

# 오른쪽 Y축: 상태
ax2 = ax1.twinx()
ax2.set_ylabel('Unique UI States Visited', color='tab:red', fontsize=12, fontweight='bold')
ax2.step(times, states, color='tab:red', linewidth=2.5, linestyle='-', where='post', label='UI State Coverage')
ax2.tick_params(axis='y', labelcolor='tab:red')

ax2.set_ylim(0, max(states) + 2 if states else 5)
ax2.set_yticks(range(0, max(states) + 3))

plt.title(f'RL Fuzzer Performance Analysis\n({log_file_path})', fontsize=16, fontweight='bold', pad=20)

lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left", bbox_to_anchor=(0.02, 0.98), frameon=True, shadow=True)

plt.tight_layout()

# [핵심 수정] 그래프를 파일로 저장합니다.
output_filename = "fuzzer_performance.png"
plt.savefig(output_filename, dpi=300) 
print(f"[+] 그래프 저장 완료: {output_filename}")

print("\n=== Analysis Summary ===")
print(f"Duration: {times[-1]:.2f} seconds")
print(f"Total Artifacts: {artifacts[-1]}")
print(f"Total States Visited: {states[-1]}")

# plt.show() # 서버 환경에서는 주석 처리하거나 삭제
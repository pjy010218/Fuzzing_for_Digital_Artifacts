import re
import sys
import matplotlib.pyplot as plt
from datetime import datetime

def parse_log(filepath):
    times, states = [], []
    start_time = None
    current_state = 0
    
    re_time = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})')
    re_state = re.compile(r'Total Visited States: (\d+)')

    try:
        with open(filepath, 'r') as f:
            for line in f:
                time_match = re_time.match(line)
                if not time_match: continue
                
                ts = datetime.strptime(time_match.group(1), "%Y-%m-%d %H:%M:%S,%f")
                if start_time is None: start_time = ts
                rel_time = (ts - start_time).total_seconds()
                
                state_match = re_state.search(line)
                if state_match:
                    current_state = int(state_match.group(1))
                    times.append(rel_time)
                    states.append(current_state)
                    
        # 마지막 시간까지 데이터 연장 (그래프 끊김 방지)
        if times:
            times.append(times[-1] + 1)
            states.append(states[-1])
            
        return times, states
    except: return [], []

# === 실행 부분 ===
# 사용법: python3 compare_graph.py log_random.txt log_rl.txt
if len(sys.argv) < 3:
    print("Usage: python3 compare_graph.py <random_log> <rl_log>")
    sys.exit(1)

rand_t, rand_s = parse_log(sys.argv[1])
rl_t, rl_s = parse_log(sys.argv[2])

plt.figure(figsize=(10, 6))

# RL Fuzzer (Red, Bold)
plt.step(rl_t, rl_s, label='Proposed (RL Fuzzer)', color='#d62728', linewidth=3, where='post')

# Random Fuzzer (Gray, Dashed)
plt.step(rand_t, rand_s, label='Baseline (Random)', color='gray', linewidth=2, linestyle='--', where='post')

plt.xlabel('Time (seconds)', fontsize=12)
plt.ylabel('Unique UI States Visited', fontsize=12)
plt.title('State Coverage Comparison: Random vs RL', fontsize=14, fontweight='bold')
plt.legend(fontsize=11)
plt.grid(True, linestyle=':', alpha=0.6)
plt.ylim(bottom=0)

plt.savefig("comparison_graph.png", dpi=300)
print("[+] Comparison graph saved to comparison_graph.png")
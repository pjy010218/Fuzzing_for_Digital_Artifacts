import time
import ctypes
import threading
import logging
from bcc import BPF
from collections import deque
from typing import List, Optional

# 로깅 설정
logger = logging.getLogger("EBPFTracer")

# --- C BPF PROGRAM (최적화 유지) ---
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_data_t {
    u32 pid;
    u32 type;        // 1=OPEN, 2=DELETE, 3=RENAME
    char comm[16];   
    char fname[256]; 
};

BPF_PERF_OUTPUT(events);

// 문자열 길이 검증 및 안전한 읽기를 위한 헬퍼 매크로
#define SAFE_READ_STR(dst, src) \
    bpf_probe_read_user_str(&dst, sizeof(dst), (void *)src); \
    if (dst[0] == 0) return 0;

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.type = 1; 
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    SAFE_READ_STR(data.fname, args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct event_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.type = 2; 
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    SAFE_READ_STR(data.fname, args->pathname);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
    struct event_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.type = 3; 
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    SAFE_READ_STR(data.fname, args->newname);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

class TraceEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("fname", ctypes.c_char * 256),
    ]

class EBPFTracer:
    def __init__(self, interest_patterns: Optional[List[str]] = None, ignore_patterns: Optional[List[str]] = None):
        self.bpf = None
        self.running = False
        self.thread = None
        self.event_queue = deque()
        self.event_types = {1: "OPEN", 2: "DELETE", 3: "RENAME"}
        
        # --- [Robustness] 설정 기반 필터링 ---
        # 하드코딩을 제거하고 매개변수로 받거나 기본값을 설정
        self.interest_patterns = interest_patterns if interest_patterns else [
            "/home", "/tmp", "/root", "/var/log", "User Data"
        ]
        
        # 노이즈 필터 (시스템 라이브러리, 캐시, 디바이스 파일 등)
        self.ignore_patterns = ignore_patterns if ignore_patterns else [
            "__pycache__", ".so", ".pyc", "/dev/", "/proc/", "/sys/", 
            "pipe:", "socket:", ".cache/fontconfig", "GPUCache",
            "dconf", "goutputstream" # GTK 앱에서 발생하는 과도한 노이즈
        ]
        
        # 타겟 프로세스 이름 (필터링 최적화용)
        self.target_comm = None

    def start_trace(self, root_pid=0, target_name: str = ""):
        """
        Tracer를 시작합니다.
        :param target_name: 모니터링할 프로세스 이름 (예: 'chrome', 'firefox'). 
                            빈 문자열이면 모든 프로세스를 감시하되 필터링만 적용.
        """
        logger.info(f"[+] Compiling eBPF (Target: {target_name if target_name else 'ALL'})...")
        # Linux kernel truncates process names (comm) to 16 chars (15 + null).
        # We must truncate our target name to match what eBPF sees.
        self.target_comm = target_name.lower()[:15] if target_name else None
        
        try:
            self.bpf = BPF(text=bpf_source)
            self.bpf["events"].open_perf_buffer(self._process_event, page_cnt=256)
            self.running = True
            self.thread = threading.Thread(target=self._poll_loop)
            self.thread.daemon = True
            self.thread.start()
            logger.info("[+] eBPF Tracer attached successfully.")
        except Exception as e:
            logger.error(f"[-] Failed to attach eBPF: {e}")
            self.running = False

    def _process_event(self, cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(TraceEvent)).contents
        filename = event.fname.decode('utf-8', 'ignore')
        proc_name = event.comm.decode('utf-8', 'ignore').lower()

        # --- [Robustness] 동적 필터링 로직 ---
        
        # 1. 프로세스 필터 (설정된 경우)
        # Chrome의 경우 프로세스 이름이 'chrome', 'chrome:type=gpu' 등으로 다양하므로 '포함' 여부 확인
        if self.target_comm and self.target_comm not in proc_name:
            return

        # 2. 제외 패턴 확인 (Blacklist) - 가장 먼저 체크하여 성능 확보
        if any(ignore in filename for ignore in self.ignore_patterns):
            return

        # 3. 관심 패턴 확인 (Whitelist)
        # 파일 경로가 분석 대상 디렉토리나 키워드를 포함하는지 확인
        if not any(interest in filename for interest in self.interest_patterns):
            return

        # 로그 출력 (너무 빈번하면 제거 가능)
        # print(f"   [Trace] {proc_name} ({self.event_types.get(event.type)}) -> {filename}")

        py_event = {
            "timestamp": time.time(),
            "pid": event.pid,
            "process_name": proc_name,
            "type": self.event_types.get(event.type, "UNKNOWN"),
            "filename": filename
        }
        self.event_queue.append(py_event)

    def _poll_loop(self):
        while self.running:
            try: 
                self.bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt: 
                break
            except Exception as e:
                logger.error(f"Error in poll loop: {e}")
                break

    def stop_trace(self):
        self.running = False
        if self.thread: 
            self.thread.join(timeout=1)
        if self.bpf:
            self.bpf.cleanup()
        logger.info("[*] Tracer stopped.")

    def get_events(self):
        events = list(self.event_queue)
        self.event_queue.clear()
        return events
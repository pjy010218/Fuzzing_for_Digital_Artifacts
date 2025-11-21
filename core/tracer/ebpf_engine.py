import time
import ctypes
import threading
from bcc import BPF
from collections import deque

# --- C BPF PROGRAM ---
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

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.type = 1; 
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->filename);
    if (data.fname[0] == 0) return 0;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct event_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.type = 2; 
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->pathname);
    if (data.fname[0] == 0) return 0;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
    struct event_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.type = 3; 
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->newname);
    if (data.fname[0] == 0) return 0;
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
    def __init__(self):
        self.bpf = None
        self.running = False
        self.thread = None
        self.event_queue = deque()
        self.event_types = {1: "OPEN", 2: "DELETE", 3: "RENAME"}

    def start_trace(self, root_pid, target_name=""):
        print(f"[+] Compiling eBPF (Chrome Optimized)...")
        self.bpf = BPF(text=bpf_source)
        self.bpf["events"].open_perf_buffer(self._process_event)
        self.running = True
        self.thread = threading.Thread(target=self._poll_loop)
        self.thread.daemon = True
        self.thread.start()

    def _process_event(self, cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(TraceEvent)).contents
        filename = event.fname.decode('utf-8', 'ignore')
        proc_name = event.comm.decode('utf-8', 'ignore').lower()

        # --- CHROME WHITELIST FILTER ---
        is_interesting = False
        
        # 1. User Data Locations
        if filename.startswith("/home"): is_interesting = True
        if filename.startswith("/root"): is_interesting = True
        if filename.startswith("/tmp"):  is_interesting = True
        
        # 2. Capture Chrome Profile Activity explicitly
        # This catches History, Cookies, Cache even if hidden
        if "chrome_fuzz_profile" in filename or "google-chrome" in filename:
            is_interesting = True
            
            # NOISE FILTER: Ignore high-frequency internal locks/caches
            if any(x in filename for x in ["LOCK", "Singleton", "GPUCache", "ShaderCache", "blob_storage"]):
                is_interesting = False

        # 3. Global Blacklist (Self-noise)
        if any(x in filename for x in ["__pycache__", "fuzzer_debug", "ui_tree", ".so", ".dat", "pipe"]):
            is_interesting = False

        if not is_interesting:
            return

        print(f"   [Trace] {proc_name} ({self.event_types.get(event.type)}) -> {filename}")

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
            try: self.bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt: break

    def stop_trace(self):
        self.running = False
        if self.thread: self.thread.join()

    def get_events(self):
        events = list(self.event_queue)
        self.event_queue.clear()
        return events
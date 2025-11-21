import time
import ctypes
import threading
from bcc import BPF
from collections import deque

# --- C BPF PROGRAM (System-Wide Tracing) ---
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_data_t {
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 type;        // 1=OPEN, 2=DELETE, 3=RENAME
    char comm[16];   // Process name
    char fname[256]; // Filename
};

BPF_PERF_OUTPUT(events);

// We no longer filter by PID in the kernel. 
// We capture EVERYTHING and filter in Python.

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tgid = bpf_get_current_pid_tgid();
    data.uid = bpf_get_current_uid_gid();
    data.type = 1; // OPEN
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->filename);

    // Optimization: Don't send events for empty filenames
    if (data.fname[0] == 0) return 0;

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct event_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.type = 2; // DELETE
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->pathname);

    if (data.fname[0] == 0) return 0;

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

class TraceEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
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
        # Names of processes we want to watch (case insensitive)
        self.target_comms = [] 

    def start_trace(self, root_pid, target_name=""):
        """
        root_pid is ignored in this version (System-Wide Mode).
        target_name: e.g. "mousepad", "gedit" (Used for Python-side filtering)
        """
        print(f"[+] Compiling eBPF (System-Wide Mode)...")
        self.bpf = BPF(text=bpf_source)
        
        if target_name:
            self.target_comms.append(target_name.lower())
            # Add common variations (e.g. "Mousepad" -> "mousepad")
            if "mousepad" in target_name.lower():
                self.target_comms.append("mousepad")
                self.target_comms.append("xfce4-terminal") # Example

        print(f"[+] Tracing ALL processes. Filtering for: {self.target_comms}")

        self.bpf["events"].open_perf_buffer(self._process_event)
        
        self.running = True
        self.thread = threading.Thread(target=self._poll_loop)
        self.thread.daemon = True
        self.thread.start()

    def _process_event(self, cpu, data, size):
            event = ctypes.cast(data, ctypes.POINTER(TraceEvent)).contents
            
            proc_name = event.comm.decode('utf-8', 'ignore').lower()
            filename = event.fname.decode('utf-8', 'ignore')

            # --- FILTER LOGIC ---
            if not filename or filename.startswith("/proc") or filename.startswith("/dev"):
                return

            # --- DEBUG: DISABLE NAME FILTERING ---
            # Comment out these lines to capture EVERYTHING
            # is_target = False
            # if not self.target_comms:
            #     is_target = True 
            # else:
            #     for t in self.target_comms:
            #         if t in proc_name:
            #             is_target = True
            #             break
            # if not is_target:
            #     return

            # Always print to console for debugging
            print(f"   [Trace] {proc_name} ({event.pid}) -> {filename}")

            py_event = {
                "timestamp": time.time(),
                "pid": event.pid,
                "process_name": proc_name,
                "type": self.event_types.get(event.type, "UNKNOWN"),
                "filename": filename
            }
            self.event_queue.append(py_event)

    def _poll_loop(self):
        print("[*] eBPF Polling Thread Started")
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break

    def stop_trace(self):
        self.running = False
        if self.thread:
            self.thread.join()
        print("[*] eBPF Trace Stopped")

    def get_events(self):
        events = list(self.event_queue)
        self.event_queue.clear()
        return events
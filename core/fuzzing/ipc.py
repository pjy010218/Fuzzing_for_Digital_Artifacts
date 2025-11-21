import socket
import threading
import logging
import time

HOST = '127.0.0.1'
PORT = 13337

class FeedbackServer:
    """
    Runs inside the Orchestrator (Root).
    Stores the current artifact count and serves it to the Fuzzer.
    """
    def __init__(self):
        self.artifact_count = 0
        self.running = False
        self.server_sock = None
        self.lock = threading.Lock()
        self.logger = logging.getLogger("FeedbackServer")

    def update_count(self, count):
        """Call this from the Orchestrator loop to update the score."""
        with self.lock:
            self.artifact_count = count

    def start(self):
        self.running = True
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_sock.bind((HOST, PORT))
            self.server_sock.listen(1)
            self.logger.info(f"[*] IPC Server listening on {HOST}:{PORT}")
            
            thread = threading.Thread(target=self._listen_loop)
            thread.daemon = True
            thread.start()
        except Exception as e:
            self.logger.error(f"[-] IPC Bind Failed: {e}")

    def _listen_loop(self):
        while self.running:
            try:
                client, _ = self.server_sock.accept()
                with client:
                    # Simple Protocol: Client sends "GET", Server sends Count
                    data = client.recv(1024)
                    if data.strip() == b"GET":
                        with self.lock:
                            resp = str(self.artifact_count).encode()
                        client.sendall(resp)
            except:
                pass

    def stop(self):
        self.running = False
        if self.server_sock:
            self.server_sock.close()

class FeedbackClient:
    """
    Runs inside the Smart Fuzzer (User).
    Connects to the Orchestrator to get the current score.
    """
    def get_artifact_count(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5) # Fast timeout
                s.connect((HOST, PORT))
                s.sendall(b"GET")
                data = s.recv(1024)
                return int(data.decode())
        except:
            return 0
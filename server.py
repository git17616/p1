# server.py
import socket
import json
import time
from protocol_logic import TwoPProtocol

HOST = '127.0.0.1'
PORT = 65432

def run_server():
    proto = TwoPProtocol()
    
    # Reload keys (orchestrator updates these files)
    try:
        with open('server_keys.json', 'r') as f:
            s_keys = json.load(f)
            xb = proto.deserialize(s_keys['xb'])
        with open('public_directory.json', 'r') as f:
            pub_dir = json.load(f)
    except FileNotFoundError:
        return

    def get_pkA(cid):
        return proto.deserialize(pub_dir.get(cid))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((HOST, PORT))
        except OSError:
            time.sleep(1)
            s.bind((HOST, PORT))
            
        s.listen()
        s.settimeout(1.0) # Check for shutdown signal periodically
        
        running = True
        while running:
            try:
                conn, addr = s.accept()
                with conn:
                    data = conn.recv(16384)
                    if not data: continue
                    
                    if data == b"SHUTDOWN":
                        running = False
                        continue

                    msg_m1 = json.loads(data.decode('utf-8'))
                    resp_m2, state = proto.server_process_m1(msg_m1, xb, get_pkA)
                    
                    if not resp_m2:
                        conn.sendall(b"FAIL")
                        continue
                        
                    conn.sendall(json.dumps(resp_m2).encode('utf-8'))
                    
                    auth3_data = conn.recv(4096)
                    if proto.server_verify_auth3(auth3_data.decode('utf-8'), state):
                        conn.sendall(b"SUCCESS")
                    else:
                        conn.sendall(b"FAIL_AUTH")
            except socket.timeout:
                continue
            except Exception as e:
                pass

if __name__ == "__main__":
    run_server()
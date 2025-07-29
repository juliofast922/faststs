#!/usr/bin/env python3
import os
import ssl
import sys
import time
import socket
import http.client
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ========================
# CONFIG
# ========================
SERVER_PORT = 8443
BENCH_DURATION = 60  # seconds
THREADS = 10
CONNECTIONS = 1000
REQUEST_PATH = "/"

CERT_DIR = os.path.join(os.path.dirname(__file__), "..", "certs")
CERT_FILE = os.path.join(CERT_DIR, "client.crt")
KEY_FILE = os.path.join(CERT_DIR, "client.key")
CA_FILE = os.path.join(CERT_DIR, "ca.crt")

OUTPUT_DIR = "benchmark_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ========================
# ARGUMENT VALIDATION
# ========================
if len(sys.argv) < 2:
    print("Usage: benchmark.py <server_process_name>")
    sys.exit(1)

server_proc = sys.argv[1]

# ========================
# PID DETECTION
# ========================
try:
    pid = subprocess.check_output(["pgrep", server_proc]).decode().splitlines()[0]
except subprocess.CalledProcessError:
    print(f"Error: Could not find process named '{server_proc}'")
    sys.exit(1)

print(f"Benchmarking process PID={pid}...")

# ========================
# MONITORING
# ========================
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
pidstat_file = os.path.join(OUTPUT_DIR, f"pidstat_{timestamp}.log")
pidstat_proc = subprocess.Popen(["pidstat", "-p", pid, "1"], stdout=open(pidstat_file, "w"))

# ========================
# WORKER FUNCTION
# ========================
def connection_worker():
    durations = []
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    try:
        conn = http.client.HTTPSConnection("localhost", SERVER_PORT, context=context, timeout=5)
        conn.connect()
    except Exception:
        return durations

    end_time = time.time() + BENCH_DURATION
    while time.time() < end_time:
        try:
            t0 = time.time()
            conn.request("GET", REQUEST_PATH, headers={"Connection": "keep-alive"})
            resp = conn.getresponse()
            resp.read()
            t1 = time.time()
            durations.append(t1 - t0)
        except Exception:
            break

    try:
        conn.close()
    except:
        pass

    return durations

# ========================
# RUN BENCHMARK
# ========================
print(f"Running benchmark for {BENCH_DURATION} seconds using {THREADS} threads and {CONNECTIONS} connections...")
start_total = time.time()
all_durations = []

with ThreadPoolExecutor(max_workers=CONNECTIONS) as executor:
    futures = [executor.submit(connection_worker) for _ in range(CONNECTIONS)]
    for future in as_completed(futures):
        all_durations.extend(future.result())

end_total = time.time()
pidstat_proc.terminate()

# ========================
# STATS
# ========================
avg_time = sum(all_durations) / len(all_durations) if all_durations else 0
min_time = min(all_durations) if all_durations else 0
max_time = max(all_durations) if all_durations else 0
total_requests = len(all_durations)
total_runtime = end_total - start_total

# ========================
# CPU USAGE
# ========================
cpu_usage = subprocess.check_output(
    f"grep -A 100 'Command' {pidstat_file} | grep {server_proc} | "
    "awk '{usr+=$3; sys+=$4; c++} END {if (c>0) printf \"User: %.2f%%\\nSystem: %.2f%%\\nTotal CPU: %.2f%%\\n\", usr/c, sys/c, (usr+sys)/c; else print \"N/A\"}'",
    shell=True
).decode().strip()

# ========================
# SYSTEM INFO
# ========================
cpu_model = subprocess.getoutput("lscpu | grep 'Model name' | awk -F: '{print $2}'").strip()
ram_total = subprocess.getoutput("free -h | grep Mem | awk '{print $2}'").strip()
kernel = subprocess.getoutput("uname -r").strip()
arch = subprocess.getoutput("uname -m").strip()
cores = subprocess.getoutput("nproc").strip()

# ========================
# SAVE REPORT
# ========================
out_file = os.path.join(OUTPUT_DIR, f"benchmark_{server_proc}_{timestamp}.txt")
with open(out_file, "w") as f:
    f.write(f"""# {server_proc} – Benchmark Report

Date: {datetime.now()}
Host: {socket.gethostname()}
Kernel: {kernel}
CPU: {cpu_model}
Total RAM: {ram_total}
CPU Cores: {cores}
Architecture: {arch}
Server Port: {SERVER_PORT}

---

## Benchmark Configuration
- Duration: {BENCH_DURATION}s
- Threads: {THREADS}
- Connections: {CONNECTIONS}
- Connection reuse: keep-alive (mTLS)

---

## Results – HTTPS + mTLS
- Total requests: {total_requests}
- Min: {min_time:.6f}s
- Max: {max_time:.6f}s
- Avg: {avg_time:.6f}s
- Total benchmark time: {total_runtime:.2f}s

---

## CPU Usage (pidstat)
{cpu_usage}

---
""")

print(f"Report generated: {out_file}")

#!/bin/bash

# =====================
# ARGUMENT VALIDATION
# =====================

if [ -z "$1" ]; then
  echo "Usage: $0 <server_process_name>"
  exit 1
fi

SERVER_PROC_NAME="$1"
SERVER_PORT=8443
BENCH_DURATION="60s"
THREADS=10
CONNECTIONS=1000
DATE=$(date "+%Y-%m-%d_%H-%M-%S")
OUTPUT_DIR="benchmark_results"
OUT_FILE="$OUTPUT_DIR/benchmark_${SERVER_PROC_NAME}_${DATE}.txt"

mkdir -p "$OUTPUT_DIR"

# =====================
# SYSTEM INFORMATION
# =====================
CPU_MODEL=$(lscpu | grep "Model name" | awk -F: '{print $2}' | xargs)
TOTAL_RAM=$(free -h | grep Mem | awk '{print $2}')
KERNEL=$(uname -r)
ARCH=$(uname -m)
CORES=$(nproc)

# =====================
# START MONITORING
# =====================
PID=$(pgrep "$SERVER_PROC_NAME" | head -n 1)
if [ -z "$PID" ]; then
  echo "Error: Could not find process named '$SERVER_PROC_NAME'"
  exit 1
fi

echo "Running benchmark and monitoring for PID $PID..."

pidstat -p "$PID" 1 > "$OUTPUT_DIR/pidstat_${DATE}.log" &
PIDSTAT_PID=$!

# =====================
# RUN WRK BENCHMARK
# =====================
WRK_OUTPUT=$(wrk -t$THREADS -c$CONNECTIONS -d$BENCH_DURATION https://localhost:$SERVER_PORT/benchmark)
kill "$PIDSTAT_PID"

# =====================
# PARSE PIDSTAT OUTPUT
# =====================
CPU_AVG=$(grep -A 100 "Command" "$OUTPUT_DIR/pidstat_${DATE}.log" | grep "$SERVER_PROC_NAME" | awk '{usr+=$3; sys+=$4; count++} END {if (count>0) printf "User: %.2f%%\nSystem: %.2f%%\nTotal CPU: %.2f%%\n", usr/count, sys/count, (usr+sys)/count; else print "N/A"}')

# =====================
# GENERATE REPORT
# =====================

cat <<EOF > "$OUT_FILE"
# $SERVER_PROC_NAME – Benchmark Report

Date: $(date)
Host: $(hostname)
Kernel: $KERNEL
CPU: $CPU_MODEL
Total RAM: $TOTAL_RAM
CPU Cores: $CORES
Architecture: $ARCH
Server Port: $SERVER_PORT

---

## Benchmark Configuration
- Duration: $BENCH_DURATION
- Threads: $THREADS
- Connections: $CONNECTIONS

---

## Results – wrk
$WRK_OUTPUT

---

## Results – CPU Usage (pidstat)
$CPU_AVG

---

EOF

echo "Report generated at: $OUT_FILE"

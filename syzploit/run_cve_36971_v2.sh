#!/bin/bash
# CVE-2024-36971 v2 run — improved templates with kread64 via dst_entry._metrics
# Uses CFI-aware guidance (function pointer redirect blocked, data-only kread)
# Waits for the io_uring queue to finish before starting.
set -e

SYZPLOIT_DIR=/home/gl055/research/ingots/kernelcveanalysis/syzploit
POCS_DIR=/home/gl055/research/ingots/kernelcveanalysis/kernel_PoCs
CODEGEN=openrouter/anthropic/claude-sonnet-4.6
QUEUE_PID_PATTERN="run_exploit_queue.sh"

cd "$SYZPLOIT_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# Wait for the io_uring queue to finish (if still running)
log "Checking if io_uring queue is still running..."
while pgrep -f "$QUEUE_PID_PATTERN" > /dev/null 2>&1; do
    log "io_uring queue still running — waiting 60s..."
    sleep 60
done
log "io_uring queue is done (or not running). Starting CVE-2024-36971 v2..."

log "=== Starting CVE-2024-36971 v2 (improved kread64 templates) ==="
python -m syzploit agent CVE-2024-36971 \
    --reference-exploit "$POCS_DIR/cve-2024-36971_dst_uaf/adapted/ingots_5.10.107_challenge4/multi_file" \
    --codegen-model "$CODEGEN" \
    --output-dir analysis_CVE-2024-36971_v2 \
    > analysis_CVE-2024-36971_v2_nohup.log 2>&1
rc=$?
log "=== CVE-2024-36971 v2 finished (rc=$rc) ==="
exit $rc

#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
    printf 'Usage: https-soak.sh CA_FILE SERVER_NAME PORT DURATION_SECONDS CONCURRENCY\n' >&2
    exit 2
fi

ca_file="$1"
server_name="$2"
port="$3"
duration_seconds="$4"
concurrency="$5"

if [ ! -f "$ca_file" ]; then
    printf 'Trusted CA file does not exist: %s\n' "$ca_file" >&2
    exit 2
fi
case "$server_name" in
    ''|*[!A-Za-z0-9.-]*)
        printf 'Invalid HTTPS server name.\n' >&2
        exit 2
        ;;
esac
case "$port:$duration_seconds:$concurrency" in
    *[!0-9:]*|::*|*::*)
        printf 'Port, duration, and concurrency must be integers.\n' >&2
        exit 2
        ;;
esac
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ] || \
   [ "$duration_seconds" -lt 30 ] || [ "$duration_seconds" -gt 180 ] || \
   [ "$concurrency" -lt 1 ] || [ "$concurrency" -gt 16 ]; then
    printf 'Requested HTTPS soak is outside its safety bounds.\n' >&2
    exit 2
fi

umask 077
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/vivo-cp1-soak.XXXXXX")"
child_pids=''

cleanup() {
    for child_pid in $child_pids; do
        kill "$child_pid" >/dev/null 2>&1 || true
    done
    for child_pid in $child_pids; do
        wait "$child_pid" >/dev/null 2>&1 || true
    done
    rm -rf -- "$work_dir"
}

on_signal() {
    trap - EXIT HUP INT TERM
    cleanup
    exit 130
}

trap cleanup EXIT
trap on_signal HUP INT TERM

url="https://${server_name}:${port}/health/ready"
resolve="${server_name}:${port}:127.0.0.1"
start_epoch="$(date +%s)"
end_epoch="$((start_epoch + duration_seconds))"

worker() {
    worker_id="$1"
    successes=0
    failures=0
    : >"$work_dir/latency.$worker_id"
    : >"$work_dir/errors.$worker_id"

    while [ "$(date +%s)" -lt "$end_epoch" ]; do
        if response="$(curl \
            --silent \
            --show-error \
            --fail \
            --proto '=https' \
            --tlsv1.2 \
            --noproxy '*' \
            --cacert "$ca_file" \
            --resolve "$resolve" \
            --connect-timeout 2 \
            --max-time 5 \
            --output /dev/null \
            --write-out '%{http_code} %{time_total}' \
            "$url" 2>>"$work_dir/errors.$worker_id")"; then
            status_code="${response%% *}"
            latency_seconds="${response#* }"
            if [ "$status_code" = 200 ]; then
                successes="$((successes + 1))"
                printf '%s\n' "$latency_seconds" >>"$work_dir/latency.$worker_id"
            else
                failures="$((failures + 1))"
            fi
        else
            failures="$((failures + 1))"
        fi
        sleep 1
    done

    printf '%s %s\n' "$successes" "$failures" >"$work_dir/result.$worker_id"
}

worker_id=1
while [ "$worker_id" -le "$concurrency" ]; do
    worker "$worker_id" &
    child_pids="$child_pids $!"
    worker_id="$((worker_id + 1))"
done

for child_pid in $child_pids; do
    wait "$child_pid"
done
child_pids=''

successes="$(awk '{ total += $1 } END { print total + 0 }' "$work_dir"/result.*)"
failures="$(awk '{ total += $2 } END { print total + 0 }' "$work_dir"/result.*)"
maximum_latency_seconds="$(awk 'BEGIN { maximum = 0 } $1 > maximum { maximum = $1 } END { printf "%.6f", maximum }' "$work_dir"/latency.*)"
elapsed_seconds="$(( $(date +%s) - start_epoch ))"

printf 'duration_seconds: %s\n' "$duration_seconds"
printf 'elapsed_seconds: %s\n' "$elapsed_seconds"
printf 'concurrency: %s\n' "$concurrency"
printf 'successful_requests: %s\n' "$successes"
printf 'failed_requests: %s\n' "$failures"
printf 'maximum_latency_seconds: %s\n' "$maximum_latency_seconds"

if [ "$successes" -eq 0 ] || [ "$failures" -ne 0 ]; then
    exit 1
fi

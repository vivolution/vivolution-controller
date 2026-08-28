#!/bin/sh
set -eu

service_name="${CP_RESOURCE_SERVICE:-vivolution-cp-web.service}"
duration_seconds="${CP_RESOURCE_DURATION_SECONDS:-120}"

case "$service_name" in
    ''|*[!A-Za-z0-9@_.-]*)
        printf 'Invalid systemd service name.\n' >&2
        exit 2
        ;;
esac
case "$duration_seconds" in
    ''|*[!0-9]*)
        printf 'Duration must be an integer.\n' >&2
        exit 2
        ;;
esac
if [ "$duration_seconds" -lt 5 ] || [ "$duration_seconds" -gt 180 ]; then
    printf 'Duration must be between 5 and 180 seconds.\n' >&2
    exit 2
fi

systemd_value() {
    systemctl show "$service_name" --property="$1" --value
}

require_unsigned_integer() {
    case "$2" in
        ''|*[!0-9]*)
            printf '%s is not an unsigned integer: %s\n' "$1" "$2" >&2
            exit 1
            ;;
    esac
}

start_epoch="$(date +%s)"
end_epoch="$((start_epoch + duration_seconds))"
samples=0
peak_service_memory_bytes=0
peak_cpu_millipercent=0
minimum_system_available_bytes=0
first_cpu_usage_ns=0
first_sample_time_ns=0
last_cpu_usage_ns=0
last_sample_time_ns=0
previous_cpu_usage_ns=0
previous_sample_time_ns=0

while [ "$(date +%s)" -lt "$end_epoch" ]; do
    sample_time_ns="$(date +%s%N)"
    service_memory_bytes="$(systemd_value MemoryCurrent)"
    service_cpu_usage_ns="$(systemd_value CPUUsageNSec)"
    system_available_kib="$(awk '/^MemAvailable:/ { print $2; exit }' /proc/meminfo)"

    require_unsigned_integer service_memory_bytes "$service_memory_bytes"
    require_unsigned_integer service_cpu_usage_ns "$service_cpu_usage_ns"
    require_unsigned_integer system_available_kib "$system_available_kib"

    system_available_bytes="$((system_available_kib * 1024))"
    if [ "$service_memory_bytes" -gt "$peak_service_memory_bytes" ]; then
        peak_service_memory_bytes="$service_memory_bytes"
    fi
    if [ "$minimum_system_available_bytes" -eq 0 ] || \
       [ "$system_available_bytes" -lt "$minimum_system_available_bytes" ]; then
        minimum_system_available_bytes="$system_available_bytes"
    fi

    if [ "$samples" -eq 0 ]; then
        first_cpu_usage_ns="$service_cpu_usage_ns"
        first_sample_time_ns="$sample_time_ns"
    else
        cpu_delta_ns="$((service_cpu_usage_ns - previous_cpu_usage_ns))"
        wall_delta_ns="$((sample_time_ns - previous_sample_time_ns))"
        if [ "$cpu_delta_ns" -ge 0 ] && [ "$wall_delta_ns" -gt 0 ]; then
            cpu_millipercent="$((cpu_delta_ns * 100000 / wall_delta_ns))"
            if [ "$cpu_millipercent" -gt "$peak_cpu_millipercent" ]; then
                peak_cpu_millipercent="$cpu_millipercent"
            fi
        fi
    fi

    previous_cpu_usage_ns="$service_cpu_usage_ns"
    previous_sample_time_ns="$sample_time_ns"
    last_cpu_usage_ns="$service_cpu_usage_ns"
    last_sample_time_ns="$sample_time_ns"
    samples="$((samples + 1))"
    sleep 1
done

if [ "$samples" -lt 2 ]; then
    printf 'Too few resource samples were collected.\n' >&2
    exit 1
fi

printf 'duration_seconds: %s\n' "$duration_seconds"
printf 'samples: %s\n' "$samples"
printf 'peak_service_memory_bytes: %s\n' "$peak_service_memory_bytes"
printf 'peak_cpu_millipercent: %s\n' "$peak_cpu_millipercent"
printf 'minimum_system_available_bytes: %s\n' "$minimum_system_available_bytes"
printf 'service_cpu_usage_delta_ns: %s\n' "$((last_cpu_usage_ns - first_cpu_usage_ns))"
printf 'elapsed_sample_ns: %s\n' "$((last_sample_time_ns - first_sample_time_ns))"

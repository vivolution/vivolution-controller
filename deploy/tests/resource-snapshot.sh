#!/bin/sh
set -eu

service_name="${CP_RESOURCE_SERVICE:-vivolution-cp-web.service}"

case "$service_name" in
    ''|*[!A-Za-z0-9@_.-]*)
        printf 'Invalid systemd service name.\n' >&2
        exit 2
        ;;
esac

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

service_memory_current_bytes="$(systemd_value MemoryCurrent)"
service_memory_max_bytes="$(systemd_value MemoryMax)"
service_cpu_usage_ns="$(systemd_value CPUUsageNSec)"
service_cpu_quota="$(systemd_value CPUQuotaPerSecUSec)"
system_available_kib="$(awk '/^MemAvailable:/ { print $2; exit }' /proc/meminfo)"
root_used_bytes="$(df --block-size=1 --output=used / | awk 'NR == 2 { print $1 }')"
journal_bytes="$({
    find /var/log/journal /run/log/journal -type f -printf '%s\n' 2>/dev/null || true
} | awk '{ total += $1 } END { printf "%.0f\n", total + 0 }')"
failed_units="$(systemctl --failed --no-legend --plain | awk 'NF { count++ } END { print count + 0 }')"

require_unsigned_integer service_memory_current_bytes "$service_memory_current_bytes"
require_unsigned_integer service_memory_max_bytes "$service_memory_max_bytes"
require_unsigned_integer service_cpu_usage_ns "$service_cpu_usage_ns"
require_unsigned_integer system_available_kib "$system_available_kib"
require_unsigned_integer root_used_bytes "$root_used_bytes"
require_unsigned_integer journal_bytes "$journal_bytes"
require_unsigned_integer failed_units "$failed_units"

printf 'timestamp_epoch: %s\n' "$(date +%s)"
printf 'service_memory_current_bytes: %s\n' "$service_memory_current_bytes"
printf 'service_memory_max_bytes: %s\n' "$service_memory_max_bytes"
printf 'service_cpu_usage_ns: %s\n' "$service_cpu_usage_ns"
printf 'service_cpu_quota: "%s"\n' "$service_cpu_quota"
printf 'system_available_bytes: %s\n' "$((system_available_kib * 1024))"
printf 'root_used_bytes: %s\n' "$root_used_bytes"
printf 'journal_bytes: %s\n' "$journal_bytes"
printf 'failed_units: %s\n' "$failed_units"

import json
import time
import os

LOG_FILES = {
    "conn": r"C:\zeek\logs\conn.log",
    "dns":  r"C:\zeek\logs\dns.log",
    "http": r"C:\zeek\logs\http.log",
    "ssl":  r"C:\zeek\logs\ssl.log"
}

OUTPUT_FILE = r"C:\normalized_logs\zeek.json"

RESTART_INTERVAL = 15 * 60   # 15 minutes in seconds  # 45 minutes in seconds
POLL_INTERVAL    = 2          # seconds between polls

file_positions = {}

# ── helpers (unchanged) ──────────────────────────────────────────────────────

def is_internal(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            return 16 <= second_octet <= 31
        except (IndexError, ValueError):
            return False
    return False

def get_flow_direction(src: str, dest: str) -> str:
    if is_internal(src) and is_internal(dest):
        return "internal_to_internal"
    elif is_internal(src):
        return "internal_to_external"
    elif is_internal(dest):
        return "external_to_internal"
    else:
        return "external_to_external"

def is_multicast(ip: str) -> bool:
    if not ip:
        return False
    try:
        first = int(ip.split(".")[0])
        return 224 <= first <= 239
    except (IndexError, ValueError):
        return False

def clean(value):
    return None if value in ("-", "", [], None) else value

# ── normalizers (unchanged) ──────────────────────────────────────────────────

def normalize_conn(log):
    src  = log.get("id.orig_h") or ""
    dest = log.get("id.resp_h") or ""
    return {
        "timestamp":        log.get("ts"),
        "event_type":       "connection",
        "log_type":         "conn",
        "uid":              log.get("uid"),
        "src_ip":           src or None,
        "src_port":         log.get("id.orig_p"),
        "dest_ip":          dest or None,
        "dest_port":        log.get("id.resp_p"),
        "protocol":         clean(log.get("proto")),
        "service":          clean(log.get("service")),
        "duration":         log.get("duration"),
        "bytes_out":        log.get("orig_bytes"),
        "bytes_in":         log.get("resp_bytes"),
        "packets_out":      log.get("orig_pkts"),
        "packets_in":       log.get("resp_pkts"),
        "connection_state": log.get("conn_state"),
        "flow_direction":   get_flow_direction(src, dest),
        "is_multicast":     is_multicast(dest),
        "log_source":       "zeek",
        "normalized":       True,
    }

def normalize_dns(log):
    answers_raw = log.get("answers", "")
    if isinstance(answers_raw, str) and answers_raw:
        answers = [a.strip() for a in answers_raw.split(",") if a.strip()]
    elif isinstance(answers_raw, list):
        answers = answers_raw
    else:
        answers = []
    return {
        "timestamp":     log.get("ts"),
        "event_type":    "dns",
        "log_type":      "dns",
        "uid":           log.get("uid"),
        "src_ip":        log.get("id.orig_h"),
        "src_port":      log.get("id.orig_p"),
        "dest_ip":       log.get("id.resp_h"),
        "dest_port":     log.get("id.resp_p"),
        "proto":         clean(log.get("proto")),
        "query":         clean(log.get("query")),
        "query_class":   clean(log.get("qclass_name")),
        "query_type":    clean(log.get("qtype_name")),
        "response_code": clean(log.get("rcode_name")),
        "resolved_ips":  answers if answers else None,
        "ttls":          clean(log.get("TTLs")),
        "log_source":    "zeek",
        "normalized":    True,
    }

def normalize_http(log):
    src  = log.get("id.orig_h") or ""
    dest = log.get("id.resp_h") or ""
    return {
        "timestamp":          log.get("ts"),
        "event_type":         "http",
        "log_type":           "http",
        "uid":                log.get("uid"),
        "src_ip":             src or None,
        "src_port":           log.get("id.orig_p"),
        "dest_ip":            dest or None,
        "dest_port":          log.get("id.resp_p"),
        "method":             clean(log.get("method")),
        "host":               clean(log.get("host")),
        "uri":                clean(log.get("uri")),
        "http_version":       clean(log.get("version")),
        "user_agent":         clean(log.get("user_agent")),
        "referrer":           clean(log.get("referrer")),
        "status_code":        log.get("status_code"),
        "status_msg":         clean(log.get("status_msg")),
        "request_body_len":   log.get("request_body_len"),
        "response_body_len":  log.get("response_body_len"),
        "resp_mime_types":    clean(log.get("resp_mime_types")),
        "flow_direction":     get_flow_direction(src, dest),
        "log_source":         "zeek",
        "normalized":         True,
    }

def normalize_ssl(log):
    src  = log.get("id.orig_h") or ""
    dest = log.get("id.resp_h") or ""
    return {
        "timestamp":      log.get("ts"),
        "event_type":     "ssl",
        "log_type":       "ssl",
        "uid":            log.get("uid"),
        "src_ip":         src or None,
        "src_port":       log.get("id.orig_p"),
        "dest_ip":        dest or None,
        "dest_port":      log.get("id.resp_p"),
        "tls_version":    clean(log.get("version")),
        "cipher":         clean(log.get("cipher")),
        "server_name":    clean(log.get("server_name")),
        "established":    log.get("established"),
        "resumed":        log.get("resumed"),
        "ja3":            clean(log.get("ja3")),
        "ja3s":           clean(log.get("ja3s")),
        "next_protocol":  clean(log.get("next_protocol")),
        "flow_direction": get_flow_direction(src, dest),
        "log_source":     "zeek",
        "normalized":     True,
    }

NORMALIZERS = {
    "conn": normalize_conn,
    "dns":  normalize_dns,
    "http": normalize_http,
    "ssl":  normalize_ssl,
}

# ── file processor (unchanged) ───────────────────────────────────────────────

def process_file(log_type, filepath):
    if filepath not in file_positions:
        file_positions[filepath] = 0

    normalizer = NORMALIZERS.get(log_type)
    if normalizer is None:
        return

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            f.seek(file_positions[filepath])
            lines_written = 0
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    log = json.loads(line)
                    normalized = normalizer(log)
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
                        out.write(json.dumps(normalized) + "\n")
                    lines_written += 1
                except json.JSONDecodeError as e:
                    print(f"[WARN] JSON parse error in {log_type}: {e}")
                except Exception as e:
                    print(f"[WARN] Normalizer error in {log_type}: {e}")
            file_positions[filepath] = f.tell()
        if lines_written:
            print(f"[INFO] {log_type}: wrote {lines_written} record(s)")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[ERROR] Failed to process {filepath}: {e}")

# ── NEW: cycle runner ─────────────────────────────────────────────────────────

def run_cycle():
    """Run one 45-minute collection cycle, then return."""
    cycle_start = time.time()
    print(f"[INFO] Cycle started at {time.strftime('%Y-%m-%d %H:%M:%S')}")

    while True:
        for log_type, path in LOG_FILES.items():
            process_file(log_type, path)

        elapsed = time.time() - cycle_start
        if elapsed >= RESTART_INTERVAL:
            print(f"[INFO] 45-minute cycle complete — resetting file positions and restarting.")
            file_positions.clear()   # force re-open from current EOF on next cycle
            return                   # back to main() loop

        time.sleep(POLL_INTERVAL)

def main():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    print("[INFO] Zeek Normalizer Started...")
    cycle = 1
    while True:
        print(f"[INFO] === Cycle {cycle} ===")
        run_cycle()
        cycle += 1

if __name__ == "__main__":
    main()
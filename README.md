# ZeekNSM for Windows

[![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=flat-square)](#requirements)
[![Language](https://img.shields.io/badge/language-C-555555?style=flat-square)](#repository-layout)
[![Build](https://img.shields.io/badge/build-CMake-064F8C?style=flat-square)](#quick-start)
[![SIEM](https://img.shields.io/badge/SIEM-Wazuh-005571?style=flat-square)](#wazuh-integration)

ZeekNSM is a Zeek-inspired network security monitor built for Windows. It captures traffic with raw Windows sockets, tracks flows, parses common protocols, writes Zeek-style JSON logs, and ships with Wazuh integration files for alerting and SIEM ingestion.

> Made using Antigravity.

## Table of Contents

- [What Can You Do With It?](#what-can-you-do-with-it)
- [Quick Start](#quick-start)
- [Features](#features)
- [Repository Layout](#repository-layout)
- [Requirements](#requirements)
- [Installation Options](#installation-options)
- [Configuration](#configuration)
- [Log Streams](#log-streams)
- [Wazuh Integration](#wazuh-integration)
- [Troubleshooting](#troubleshooting)
- [Project Status](#project-status)
- [Contributing](#contributing)
- [License](#license)

## What Can You Do With It?

- Watch Windows network traffic in near real time
- Generate Zeek-like logs without installing the full Zeek stack
- Send JSON security telemetry into Wazuh
- Detect suspicious behavior such as port scans and possible DNS tunneling
- Run it temporarily in a terminal or permanently as a Windows service

## Quick Start

Pick the path that matches what you want to do.

| I want to... | Use this |
| --- | --- |
| Test it quickly | Run in console mode |
| Keep it running after reboot | Install as a Windows service |
| Send logs to Wazuh | Use the files in `wazuh/` |
| Tune detection behavior | Edit `zeek.conf` |

### 1. Build the executable

```powershell
cmake -S . -B build
cmake --build build --config Release
```

The executable is created at:

```text
build\zeek-nsm.exe
```

### 2. Run a quick test

Open PowerShell as Administrator:

```powershell
.\build\zeek-nsm.exe --config .\zeek.conf
```

### 3. Check the logs

By default, logs are written to:

```text
C:\zeek\logs
```

You should start seeing files such as:

```text
conn.log
dns.log
ssl.log
notice.log
stats.log
```

## Features

- Native Windows executable written in C
- Console mode and Windows service mode
- Raw packet capture with automatic interface selection
- Zeek-style NDJSON log streams
- Connection, DNS, HTTP, TLS/SSL, notice, weird, and stats logs
- TLS SNI, JA3, and JA3S extraction
- Basic behavioral detections for port scans and DNS tunneling
- Log rotation by time and file size
- Wazuh agent, decoder, and rule examples

## Repository Layout

```text
.
+-- CMakeLists.txt          # CMake build definition
+-- install.ps1             # Windows installer/service setup script
+-- zeek.conf               # Runtime configuration
+-- src/                    # ZeekNSM source code
+-- wazuh/                  # Wazuh integration snippets
`-- build/                  # Local build output
```

## Requirements

- Windows
- Administrator privileges for packet capture and service installation
- CMake 3.16 or newer
- A C compiler supported by CMake, such as MSVC or MinGW-w64

## Clone

```powershell
git clone https://github.com/<your-username>/<your-repository>.git
cd "<your-repository>"
```

Replace `<your-username>` and `<your-repository>` with your GitHub details after publishing.

## Installation Options

### Option A: Run Without Installing

Use this when you want to test ZeekNSM before installing it as a service.

Open PowerShell as Administrator:

```powershell
.\build\zeek-nsm.exe --config .\zeek.conf
```

Useful commands:

```powershell
.\build\zeek-nsm.exe --help
.\build\zeek-nsm.exe --version
.\build\zeek-nsm.exe --print-config
```

Stop it with `Ctrl+C`.

### Option B: Install as a Windows Service

Use this when you want ZeekNSM to run automatically in the background.

Run PowerShell as Administrator:

```powershell
.\install.ps1
```

The installer copies files to:

```text
C:\zeek
```

Logs are written to:

```text
C:\zeek\logs
```

The Windows service is registered as:

```text
ZeekNSM
```

### Manual Service Commands

Install the service manually:

```powershell
C:\zeek\zeek-nsm.exe --install --config C:\zeek\zeek.conf
```

Remove the service:

```powershell
C:\zeek\zeek-nsm.exe --uninstall
```

Start or stop the service:

```powershell
Start-Service ZeekNSM
Stop-Service ZeekNSM
```

## Configuration

Runtime settings live in `zeek.conf`.

Important sections:

| Section | What you can change |
| --- | --- |
| `[capture]` | Interface selection, snap length, capture buffer |
| `[logging]` | Log directory, rotation interval, log size limit, enabled streams |
| `[detection]` | Port scan and DNS tunneling thresholds |
| `[connection]` | TCP, UDP, and ICMP inactivity timeouts |
| `[service]` | Service behavior notes |

The default interface is:

```ini
interface = auto
```

This selects the first non-loopback interface automatically. You can also set a specific local IP address.

### Common Tweaks

Capture on a specific interface:

```ini
interface = 192.168.1.10
```

Rotate logs every hour:

```ini
rotation_interval = 3600
```

Make port scan detection more sensitive:

```ini
port_scan_threshold = 10
port_scan_window = 60
```

## Log Streams

ZeekNSM writes JSON-lines logs compatible with common SIEM pipelines:

| Log | What it contains |
| --- | --- |
| `conn.log` | Network flow records |
| `dns.log` | DNS queries, responses, and synthetic SNI-derived records |
| `http.log` | HTTP request and response metadata |
| `ssl.log` | TLS metadata, SNI, JA3, and JA3S |
| `notice.log` | Detection events |
| `weird.log` | Protocol anomalies |
| `stats.log` | Packet and capture statistics |

### What Should I Look At First?

- Start with `conn.log` to confirm traffic is being captured.
- Check `dns.log` and `ssl.log` to understand hostnames and TLS sessions.
- Watch `notice.log` for security detections.
- Use `stats.log` to confirm packet counts and dropped packets.

## Wazuh Integration

The `wazuh/` directory contains:

- `agent_config.xml`: Wazuh agent localfile examples for `C:\zeek\logs`
- `zeek_decoders.xml`: decoder definitions for the Wazuh manager
- `zeek_rules.xml`: example alerting rules

Typical setup:

1. Add the `localfile` blocks from `wazuh/agent_config.xml` to the Windows Wazuh agent configuration.
2. Copy `wazuh/zeek_decoders.xml` to the Wazuh manager decoder directory.
3. Copy `wazuh/zeek_rules.xml` to the Wazuh manager rules directory.
4. Restart the Wazuh agent and manager services.

## Example Output

Example `conn.log` record:

```json
{"ts":1712670000.123456,"uid":"Cabc123","id.orig_h":"192.168.1.10","id.orig_p":51524,"id.resp_h":"93.184.216.34","id.resp_p":443,"proto":"tcp","service":"ssl","duration":1.234000,"orig_bytes":421,"resp_bytes":2048,"conn_state":"SF","orig_pkts":5,"resp_pkts":6,"orig_ip_bytes":621,"resp_ip_bytes":2288}
```

Example `notice.log` record:

```json
{"ts":1712670001.123456,"uid":"Cnotice1","id.orig_h":"192.168.1.10","id.orig_p":53120,"id.resp_h":"192.168.1.1","id.resp_p":80,"note":"Scan::Port_Scan","msg":"Possible port scan detected","sub":"threshold exceeded","actions":["Notice::ACTION_LOG"]}
```

## Troubleshooting

| Problem | Try this |
| --- | --- |
| No logs are created | Run PowerShell as Administrator and confirm `log_dir` exists |
| No traffic appears | Set `interface = auto` or use a specific local IP |
| Service does not start | Run `.\build\zeek-nsm.exe --print-config` and check the config path |
| Wazuh does not show events | Confirm the Wazuh agent is reading `C:\zeek\logs\*.log` |
| Too many alerts | Raise thresholds in the `[detection]` section |

## Project Status

- [x] Windows packet capture
- [x] Zeek-style JSON logs
- [x] DNS, HTTP, and TLS parsing
- [x] JA3 and JA3S logging
- [x] Windows service support
- [x] Wazuh integration examples
- [ ] Add screenshots or sample dashboards
- [ ] Add a formal license

## Contributing

Contributions are welcome. Good first areas to improve:

- Add sample screenshots or Wazuh dashboard examples
- Expand protocol parsing coverage
- Add automated build instructions for GitHub Actions
- Improve detection rules
- Add tests for parsers and configuration loading

Before opening a pull request, please make sure the project builds successfully with CMake.

## Security Notes

- Run ZeekNSM only on systems and networks you are authorized to monitor.
- Packet capture requires Administrator privileges on Windows.
- Review logs before sharing them publicly because they can contain IP addresses, hostnames, URLs, and other sensitive metadata.

## Notes

- Run as Administrator. Windows raw socket capture requires elevated privileges.
- This project is Zeek-inspired, but it is not the official Zeek Network Security Monitor.
- Log output is intentionally JSON-based for easier ingestion by Wazuh and other SIEM tools.

## License

No license file is currently included. Add a license before publishing or distributing this project publicly.

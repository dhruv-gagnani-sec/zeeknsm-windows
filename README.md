# ZeekNSM for Windows

ZeekNSM is a Zeek-inspired network security monitor built for Windows. It captures traffic with raw Windows sockets, tracks network flows, parses common protocols, writes Zeek-style JSON logs, and includes Wazuh integration files for alerting and SIEM ingestion.

Made using Antigravity.

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

## Build

From the project root:

```powershell
cmake -S . -B build
cmake --build build --config Release
```

The executable is generated as:

```text
build\zeek-nsm.exe
```

## Run in Console Mode

Run PowerShell or Command Prompt as Administrator, then start ZeekNSM:

```powershell
.\build\zeek-nsm.exe --config .\zeek.conf
```

Useful commands:

```powershell
.\build\zeek-nsm.exe --help
.\build\zeek-nsm.exe --version
.\build\zeek-nsm.exe --print-config
```

## Install as a Windows Service

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

## Manual Service Commands

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

- `[capture]`: interface selection, snap length, capture buffer
- `[logging]`: log directory, rotation interval, log size limit, enabled streams
- `[detection]`: port scan and DNS tunneling thresholds
- `[connection]`: TCP, UDP, and ICMP inactivity timeouts
- `[service]`: service behavior notes

The default interface is:

```ini
interface = auto
```

This selects the first non-loopback interface automatically. You can also set a specific local IP address.

## Log Streams

ZeekNSM writes JSON-lines logs compatible with common SIEM pipelines:

- `conn.log`: network flow records
- `dns.log`: DNS queries, responses, and synthetic SNI-derived records
- `http.log`: HTTP request and response metadata
- `ssl.log`: TLS metadata, SNI, JA3, and JA3S
- `notice.log`: detection events
- `weird.log`: protocol anomalies
- `stats.log`: packet and capture statistics

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

## Notes

- Run as Administrator. Windows raw socket capture requires elevated privileges.
- This project is Zeek-inspired, but it is not the official Zeek Network Security Monitor.
- Log output is intentionally JSON-based for easier ingestion by Wazuh and other SIEM tools.

## License

No license file is currently included. Add a license before publishing or distributing this project publicly.

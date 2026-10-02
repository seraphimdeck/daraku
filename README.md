# daraku

[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/coseraph)

![daraku Terminal Output](assets/assets4.jpg)

**daraku** (*Active Directory Audit Engine*) is a high-performance Active Directory (AD) and Active Directory Certificate Services (AD CS) audit tool written in Go. Designed for Blue Teams, Auditors, and Security Engineers, **daraku** focuses on passive (read-only) security assessments that are safe, fast, and contained, eliminating out-of-scope risks.

## Features & Project Structure

- Safety Gatekeeper (pkg/gatekeeper): Validates target IPs against RFC1918 boundaries, local subnets, and enforces TTL=1 restrictions before connecting.
- Zero-Dependency & Fast: Compiles into a single static binary running natively on Linux, macOS and Windows without Python or .NET runtimes.
- Passive AD & AD CS Detection: Identifies ESC1, ESC3, ESC6, ESC8, Kerberoasting, AS-REP Roasting, and Delegation risks (Unconstrained, Constrained, RBCD).
- Interface-Driven Reporter (pkg/reporter): Supports Terminal (color-coded), Markdown (detailed audit reports), and JSON (SIEM integration).

## Installation, Usage & Security Disclaimer

To build from source, run:
git clone https://github.com/seraphimdeck/daraku.git && cd daraku && go build -o daraku cmd/daraku/main.go

Or install directly via:
go install github.com/seraphimdeck/daraku/cmd/daraku@latest

To execute a standard audit scan:
./daraku -target domain.local -user auditor_user -pass 'Password123!' -dc-ip 192.168.1.10

To export results directly to Markdown and JSON:
./daraku -target domain.local -user auditor_user -pass 'Password123!' -dc-ip 192.168.1.10 -o report.md -json report.json

daraku is strictly a passive (read-only) audit tool performing LDAP queries and passive HTTP probes without modifying Active Directory objects or requesting certificates. Usage must comply with official permissions and applicable laws. Licensed under the MIT License.

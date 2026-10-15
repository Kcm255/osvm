# System & VM Analyzer (`system_analyzer.py`)

A single-file, OS-independent Python tool that analyzes a machine (your laptop or a remote server over SSH) and produces a **JSON report** and a self-contained **HTML dashboard** every time it runs.

## What it reports

| Section | Details |
|---|---|
| **OS** | System, release, architecture, uptime, version name (e.g. "Noble Numbat", macOS codename, Windows 23H2) |
| **CPU / Memory / Disk** | Model, cores, RAM totals and usage, mounted disks |
| **Virtualization** | VM or bare metal, hypervisor (KVM, VMware, Hyper-V, VirtualBox...), container/WSL detection |
| **Network** | Hostname, IP, MAC |
| **Applications** | Installed software, common tools found on PATH, top processes |
| **Deployed applications** | What is actually running: listening ports mapped to processes, running containers (Docker/Podman), active services, nginx/Apache sites |
| **Application dependencies** | Scans an app folder **recursively** for every project and its libraries (see below) |

### Application dependency scan

Point it at a folder with `--app-path`. It walks all subfolders (up to 10 levels deep, skipping `node_modules`, `venv`, `.git`, `build`, `target` etc.) and finds every manifest, so nested folders and multi-language monorepos are fully covered. Each project folder is reported as its own **module**.

| Stack | Files read |
|---|---|
| Python | `requirements.txt`, `pyproject.toml`, `Pipfile`, `runtime.txt` |
| Node.js | `package.json` (+ lockfile detection) |
| Java | `pom.xml`, `build.gradle(.kts)`, `WEB-INF/lib/*.jar` |
| Tomcat | Any Tomcat install found (`bin/catalina.sh`), version from `RELEASE-NOTES` |
| .NET | `*.csproj` |
| Ruby | `Gemfile`, `.ruby-version` |
| PHP | `composer.json` |
| Go | `go.mod` |
| Rust | `Cargo.toml` |

For every library you get: name, module (subfolder), pinned version, **version name** (e.g. `numpy==2.0.0` becomes "NumPy 2"), and kind (runtime/dev/etc.).

## Requirements

- Python 3.6 or newer
- **Local mode:** nothing to install
- **SSH / remote mode:** `pip install -r requirements.txt` (installs `paramiko`) on the machine you run from. The remote server only needs Python 3.6+; nothing is installed there.

## Quick start

```bash
# 1. (optional, only for SSH mode) install the one dependency
pip install -r requirements.txt

# 2. analyze this machine
python system_analyzer.py
```

This writes **`report.json`** and **`report.html`** in the current folder. Open `report.html` by double-clicking it (or `start report.html` on Windows, `open report.html` on macOS, `xdg-open report.html` on Linux). No web server needed.

On Windows, use `python` (or `py`) in PowerShell/CMD. If you use a virtual environment, activate it first.

## Common commands

```bash
# Analyze this machine plus an application folder
python system_analyzer.py --app-path "C:\Users\you\Desktop\legal-aid\backend"

# Same, and look up the latest published version of each library
python system_analyzer.py --app-path ./myapp --check-latest

# Choose output file names
python system_analyzer.py --out mine.json --html mine.html

# JSON only to the terminal, no HTML file
python system_analyzer.py --json --no-html --no-json-file

# Human-readable text in the terminal
python system_analyzer.py --no-html
```

If `--app-path` is omitted, the script auto-discovers an app in common locations (current folder, `/var/www`, `/opt`, `/srv`, Tomcat `webapps/ROOT`).

## Running against a remote server (SSH)

```bash
# Password login (prompts securely)
python system_analyzer.py --host 203.0.113.10 --user ubuntu --ask-pass

# SSH key login
python system_analyzer.py --host server.example.com --user ubuntu --key ~/.ssh/id_rsa

# Also scan an app folder that lives ON THE SERVER
python system_analyzer.py --host server.example.com --user ubuntu --key ~/.ssh/id_rsa --app-path /var/www/myapp
```

#!/usr/bin/env python3
# /// script
# requires-python = ">=3.6"
# dependencies = ["paramiko"]
# ///
"""
System & VM Analyzer  -  single file, OS independent, JSON output.

Reports, in one combined JSON document:
  - OS artifacts (name, version, kernel, architecture, uptime)
  - System hardware: CPU, memory, disk
  - VM library: hypervisor / container detection
  - Network info
  - Applications: installed software, dev/server tools, top processes
  - Deployed applications: listening ports mapped to owning processes,
    running containers, active services, web server vhosts
  - Application dependencies (NEW): for an app folder on this machine --
    its language runtime version (Python/Java/Node/.NET/Ruby/PHP/Go),
    its application server if any (Tomcat) and version, and every
    library/dependency it declares, with version

Two modes from the same file:
  Local :  python3 system_analyzer.py
  Remote:  python3 system_analyzer.py --host 10.0.0.5 --user admin --key ~/.ssh/id_rsa

Remote mode connects with paramiko (the ONLY third-party dependency, needed
only on the machine you run this from), sends this same script to the server,
runs it there, and reads the JSON back. The server needs only Python 3.6+.

Dependency scanning is a LOCAL / STATIC file scan -- it never opens a network
connection of its own. Point it at an app folder with --app-path (works in
both local and remote mode: in remote mode the path is read on the server).
If --app-path is omitted, the scanner also tries a short list of common
deploy locations (Tomcat webapps, /opt, /srv, /var/www, the script's own
directory) and reports whatever it actually finds.
"""

import argparse
import csv
import getpass
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET

VERSION = "1.1.0"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def run(cmd, timeout=20):
    """Run a command (list or string). Returns (returncode, stdout). Never raises."""
    try:
        env = dict(os.environ, LC_ALL="C", LANG="C")
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=timeout, env=env, shell=isinstance(cmd, str))
        return p.returncode, p.stdout.decode("utf-8", "replace").strip()
    except Exception:
        return -1, ""


def run_cmd(cmd, timeout=20):
    """Return stdout only if the command succeeded, else empty string."""
    rc, out = run(cmd, timeout)
    return out if rc == 0 else ""


def read_file(path):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read().strip()
    except Exception:
        return ""


def read_file_raw(path):
    """Like read_file but keeps leading/trailing whitespace -- line-oriented
    parsers (requirements.txt, go.mod, ...) want the real file content."""
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def reg_value(path, name):
    """Windows registry read (HKLM, 64-bit view). Returns None elsewhere / on error."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            return winreg.QueryValueEx(k, name)[0]
    except Exception:
        return None


def gb(n_bytes):
    return None if n_bytes is None else round(n_bytes / (1024 ** 3), 2)


def safe(fn, *args):
    """One failing section must never kill the whole report."""
    try:
        return fn(*args)
    except Exception as e:
        return {"error": "%s: %s" % (type(e).__name__, e)}


# --------------------------------------------------------------------------
# OS artifacts
# --------------------------------------------------------------------------

def get_uptime():
    s = platform.system()
    if s == "Linux":
        t = read_file("/proc/uptime").split()
        return int(float(t[0])) if t else None
    if s == "Windows":
        import ctypes
        k32 = ctypes.windll.kernel32
        k32.GetTickCount64.restype = ctypes.c_ulonglong
        return int(k32.GetTickCount64() // 1000)
    m = re.search(r"sec\s*=\s*(\d+)", run_cmd(["sysctl", "-n", "kern.boottime"]))
    return int(time.time()) - int(m.group(1)) if m else None


# macOS doesn't expose its marketing codename via any command -- sw_vers only
# gives the numeric version -- so this is a lookup table keyed by major version.
_MACOS_CODENAMES = {
    "26": "Tahoe", "15": "Sequoia", "14": "Sonoma", "13": "Ventura",
    "12": "Monterey", "11": "Big Sur", "10.15": "Catalina", "10.14": "Mojave",
    "10.13": "High Sierra", "10.12": "Sierra",
}


def _macos_codename(product_version):
    if not product_version:
        return None
    parts = product_version.split(".")
    if parts and parts[0] == "10" and len(parts) > 1:
        return _MACOS_CODENAMES.get("10." + parts[1])
    return _MACOS_CODENAMES.get(parts[0]) if parts else None


def get_os_info():
    s = platform.system()
    info = {
        "system": s,
        "node": platform.node(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "version_name": None,  # the human/marketing name, alongside the version number
    }
    if s == "Linux":
        for line in read_file("/etc/os-release").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                if k in ("NAME", "VERSION", "ID", "VERSION_ID", "PRETTY_NAME", "VERSION_CODENAME"):
                    info["os_release_" + k] = v.strip().strip('"')
        # Prefer the full animal name in parens, e.g. "24.04.5 LTS (Noble Numbat)"
        # -> "Noble Numbat" -- it's the name people actually recognize, vs. the
        # short machine-readable VERSION_CODENAME field (e.g. "noble").
        m = re.search(r"\(([^)]+)\)", info.get("os_release_VERSION", ""))
        codename = m.group(1) if m else info.get("os_release_VERSION_CODENAME")
        info["version_name"] = codename.title() if codename and codename.islower() else codename
    elif s == "Darwin":
        info["product_name"] = run_cmd(["sw_vers", "-productName"])
        info["product_version"] = run_cmd(["sw_vers", "-productVersion"])
        info["build"] = run_cmd(["sw_vers", "-buildVersion"])
        info["version_name"] = _macos_codename(info["product_version"])
    elif s == "Windows":
        cv = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        name = reg_value(cv, "ProductName") or ""
        build = reg_value(cv, "CurrentBuild")
        try:
            if int(build) >= 22000:  # registry still says "Windows 10" on Win 11
                name = name.replace("Windows 10", "Windows 11")
        except (TypeError, ValueError):
            pass
        info["product_name"] = name or None
        info["display_version"] = reg_value(cv, "DisplayVersion") or reg_value(cv, "ReleaseId")
        info["build"] = build
        # Windows' "version name" is its feature-update label, e.g. "23H2"
        info["version_name"] = info["display_version"]
    info["uptime_seconds"] = safe(get_uptime)
    return info


# --------------------------------------------------------------------------
# System: CPU, memory, disk
# --------------------------------------------------------------------------

def get_cpu_info():
    s = platform.system()
    info = {"model": None, "logical_cores": os.cpu_count(), "physical_cores": None,
            "architecture": platform.machine(), "load_avg": None}
    if s == "Linux":
        txt = read_file("/proc/cpuinfo")
        m = (re.search(r"^model name\s*:\s*(.+)$", txt, re.M)
             or re.search(r"^(?:Hardware|Model)\s*:\s*(.+)$", txt, re.M))
        lscpu = run_cmd(["lscpu"])
        if m:
            info["model"] = m.group(1).strip()
        else:
            m = re.search(r"^Model name:\s*(.+)$", lscpu, re.M)
            if m:
                info["model"] = m.group(1).strip()
        c = re.search(r"^Core\(s\) per socket:\s*(\d+)", lscpu, re.M)
        sk = re.search(r"^Socket\(s\):\s*(\d+)", lscpu, re.M)
        if c and sk:
            info["physical_cores"] = int(c.group(1)) * int(sk.group(1))
    elif s == "Darwin":
        info["model"] = run_cmd(["sysctl", "-n", "machdep.cpu.brand_string"]) or None
        p = run_cmd(["sysctl", "-n", "hw.physicalcpu"])
        info["physical_cores"] = int(p) if p.isdigit() else None
    elif s == "Windows":
        info["model"] = (reg_value(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                                   "ProcessorNameString") or "").strip() or None
    if not info["model"]:
        info["model"] = platform.processor() or None
    try:
        info["load_avg"] = [round(x, 2) for x in os.getloadavg()]
    except (AttributeError, OSError):
        pass
    return info


def get_memory_info():
    s = platform.system()
    total = avail = swap_total = swap_free = None
    if s == "Linux":
        mi = {}
        for line in read_file("/proc/meminfo").splitlines():
            parts = line.replace(":", "").split()
            if len(parts) >= 2 and parts[1].isdigit():
                mi[parts[0]] = int(parts[1]) * 1024
        total = mi.get("MemTotal")
        avail = mi.get("MemAvailable", mi.get("MemFree"))
        swap_total, swap_free = mi.get("SwapTotal"), mi.get("SwapFree")
    elif s == "Windows":
        import ctypes

        class MEMSTAT(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]
        st = MEMSTAT()
        st.dwLength = ctypes.sizeof(MEMSTAT)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st))
        total, avail = st.ullTotalPhys, st.ullAvailPhys
    elif s == "Darwin":
        t = run_cmd(["sysctl", "-n", "hw.memsize"])
        total = int(t) if t.isdigit() else None
        vm = run_cmd(["vm_stat"])
        ps = re.search(r"page size of (\d+) bytes", vm)
        if ps:
            page = int(ps.group(1))
            pages = 0
            for key in ("free", "inactive", "speculative"):
                m = re.search(r"Pages %s:\s+(\d+)" % key, vm)
                pages += int(m.group(1)) if m else 0
            avail = pages * page
    if total is None:
        try:
            total = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        except (ValueError, OSError, AttributeError):
            pass
    used = (total - avail) if (total is not None and avail is not None) else None
    return {
        "total_gb": gb(total),
        "available_gb": gb(avail),
        "used_gb": gb(used),
        "used_percent": round(used * 100.0 / total, 1) if used is not None and total else None,
        "swap_total_gb": gb(swap_total),
        "swap_free_gb": gb(swap_free),
    }


_SKIP_FS = {"tmpfs", "devtmpfs", "devfs", "squashfs", "udev", "none", "map", "overlay",
            "shm", "proc", "sysfs", "cgroup", "efivarfs", "autofs"}


def _disk_entry(fs, mount, total, used, free, pct=None, kind=None):
    if pct is None:
        pct = round(used * 100.0 / total, 1) if total else None
    return {"filesystem": fs, "mount": mount, "type": kind, "total_gb": gb(total),
            "used_gb": gb(used), "free_gb": gb(free), "used_percent": pct}


def get_disk_info():
    disks = []
    if platform.system() == "Windows":
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if not mask & (1 << i):
                continue
            root = "%s:\\" % chr(65 + i)
            dtype = ctypes.windll.kernel32.GetDriveTypeW(root)
            if dtype not in (3, 4):  # fixed, network
                continue
            try:
                u = shutil.disk_usage(root)
                disks.append(_disk_entry(root, root, u.total, u.used, u.free,
                                         kind={3: "fixed", 4: "network"}[dtype]))
            except OSError:
                continue
    else:
        out = run_cmd(["df", "-kP"])
        for line in out.splitlines()[1:]:
            parts = line.split(None, 5)
            if len(parts) < 6 or not parts[1].isdigit() or int(parts[1]) == 0:
                continue
            fs, size, used, avail, pct, mount = parts
            if fs in _SKIP_FS and mount != "/":
                continue
            if mount.startswith("/snap/"):
                continue
            if mount.startswith("/System/Volumes/") and not mount.endswith("/Data"):
                continue
            disks.append(_disk_entry(fs, mount, int(size) * 1024, int(used) * 1024,
                                     int(avail) * 1024,
                                     float(pct.rstrip("%")) if pct.rstrip("%").isdigit() else None))
    return disks


# --------------------------------------------------------------------------
# VM library: hypervisor + container detection
# --------------------------------------------------------------------------

# Order matters: more specific strings first.
VM_SIGNATURES = [
    ("vmware", "VMware"), ("virtualbox", "VirtualBox"), ("innotek", "VirtualBox"),
    ("vbox", "VirtualBox"), ("parallels", "Parallels"), ("virtualmac", "Apple Virtualization"),
    ("amazon ec2", "AWS EC2"), ("google compute engine", "Google Compute Engine"),
    ("openstack", "OpenStack"), ("bhyve", "bhyve"), ("bochs", "Bochs"),
    ("qemu", "QEMU"), ("kvm", "KVM"), ("xen", "Xen"),
]

SYSTEMD_NAMES = {"kvm": "KVM", "qemu": "QEMU", "vmware": "VMware", "oracle": "VirtualBox",
                 "microsoft": "Hyper-V", "xen": "Xen", "amazon": "AWS Nitro",
                 "parallels": "Parallels", "bochs": "Bochs", "bhyve": "bhyve",
                 "google": "Google Compute Engine", "apple": "Apple Virtualization"}


def match_hypervisor(text):
    t = (text or "").lower()
    if "microsoft" in t and ("virtual machine" in t or "hyper-v" in t):
        return "Hyper-V"
    for key, name in VM_SIGNATURES:
        if key in t:
            return name
    return None


def _detect_container():
    runtime = None
    if platform.system() == "Linux":
        rel = platform.release().lower()
        rc, out = run(["systemd-detect-virt", "--container"])
        if rc == 0 and out and out != "none":
            runtime = out
        elif "microsoft" in rel or "wsl" in rel:
            runtime = "wsl"
        elif os.path.exists("/.dockerenv"):
            runtime = "docker"
        elif os.path.exists("/run/.containerenv"):
            runtime = "podman"
        else:
            cg = read_file("/proc/1/cgroup")
            for key in ("kubepods", "docker", "lxc", "containerd"):
                if key in cg:
                    runtime = key
                    break
    return {"is_container": runtime is not None, "runtime": runtime}


def detect_virtualization():
    s = platform.system()
    res = {"is_vm": False, "hypervisor": None, "method": None, "evidence": None}

    if s == "Linux":
        # 1) systemd-detect-virt (most reliable)
        rc, out = run(["systemd-detect-virt", "--vm"])
        if out and out != "none":
            res.update(is_vm=True, hypervisor=SYSTEMD_NAMES.get(out, out),
                       method="systemd-detect-virt", evidence=out)
        # 2) DMI strings
        if not res["is_vm"]:
            dmi = " ".join(read_file("/sys/class/dmi/id/" + f) for f in
                           ("product_name", "sys_vendor", "board_vendor", "bios_vendor",
                            "chassis_vendor")).strip()
            hv = match_hypervisor(dmi)
            if hv:
                res.update(is_vm=True, hypervisor=hv, method="dmi", evidence=dmi)
        # 3) /sys/hypervisor and CPU "hypervisor" flag
        if not res["is_vm"]:
            xen = read_file("/sys/hypervisor/type")
            if xen:
                res.update(is_vm=True, hypervisor=match_hypervisor(xen) or xen,
                           method="/sys/hypervisor", evidence=xen)
            elif re.search(r"^flags\s*:.*\bhypervisor\b", read_file("/proc/cpuinfo"), re.M):
                res.update(is_vm=True, hypervisor="Unknown", method="cpu-flag",
                           evidence="hypervisor flag in /proc/cpuinfo")

    elif s == "Windows":
        bios = r"HARDWARE\DESCRIPTION\System\BIOS"
        text = " ".join(str(reg_value(bios, n) or "") for n in
                        ("SystemManufacturer", "SystemProductName", "BIOSVendor",
                         "BaseBoardManufacturer")).strip()
        if not text:  # registry empty: fall back to PowerShell CIM (wmic is deprecated)
            text = run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                            "$c=Get-CimInstance Win32_ComputerSystem; $c.Manufacturer+' '+$c.Model"])
        hv = match_hypervisor(text)
        if hv:
            res.update(is_vm=True, hypervisor=hv, method="bios-registry", evidence=text)

    elif s == "Darwin":
        model = run_cmd(["sysctl", "-n", "hw.model"])
        present = run_cmd(["sysctl", "-n", "kern.hv_vmm_present"]) == "1"
        feats = run_cmd(["sysctl", "-n", "machdep.cpu.features"])
        hv = match_hypervisor(model)
        if present or hv or re.search(r"\bVMM\b", feats):
            res.update(is_vm=True, hypervisor=hv or "Unknown",
                       method="sysctl", evidence=model or "VMM flag")

    else:  # BSD and others
        g = run_cmd(["sysctl", "-n", "kern.vm_guest"])
        if g and g != "none":
            res.update(is_vm=True, hypervisor=SYSTEMD_NAMES.get(g, g),
                       method="sysctl kern.vm_guest", evidence=g)

    res["container"] = _detect_container()
    return res


# --------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------

def get_network_info():
    hostname = socket.gethostname()
    ip = None
    try:  # UDP connect sends no packets; it just asks the OS which interface routes out
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
    except Exception:
        try:
            ip = socket.gethostbyname(hostname)
        except Exception:
            pass
    addrs = []
    try:
        for info in socket.getaddrinfo(hostname, None):
            a = info[4][0]
            if a not in addrs and not a.startswith("127.") and a != "::1":
                addrs.append(a)
    except Exception:
        pass
    mac_int = uuid.getnode()
    mac = None if (mac_int >> 40) & 1 else ":".join("%02x" % ((mac_int >> s) & 0xff)
                                                    for s in range(40, -1, -8))
    return {"hostname": hostname, "fqdn": socket.getfqdn(), "ip": ip,
            "addresses": addrs, "mac": mac}


# --------------------------------------------------------------------------
# Applications (installed software, detected tools, top processes)
# --------------------------------------------------------------------------

TOOLS = ["python3", "python", "pip", "java", "node", "npm", "go", "dotnet", "php", "ruby",
         "gcc", "git", "docker", "podman", "kubectl", "nginx", "apache2", "httpd", "mysql",
         "psql", "mongod", "redis-server", "sqlite3", "ssh", "sshd", "systemctl"]


def _installed_windows():
    import winreg
    seen = {}
    for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                                  0, winreg.KEY_READ | view)
        except OSError:
            continue
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            try:
                with winreg.OpenKey(root, sub) as k:
                    name = winreg.QueryValueEx(k, "DisplayName")[0]
                    try:
                        ver = winreg.QueryValueEx(k, "DisplayVersion")[0]
                    except OSError:
                        ver = ""
                    seen[name] = ver
            except OSError:
                continue
    return "windows-registry", sorted(seen.items(), key=lambda x: x[0].lower())


def _installed_posix():
    if platform.system() == "Darwin":
        try:
            apps = sorted(a[:-4] for a in os.listdir("/Applications") if a.endswith(".app"))
        except OSError:
            apps = []
        return "/Applications", [(a, "") for a in apps]
    attempts = [
        ("dpkg", ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], "\t"),
        ("rpm", ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], "\t"),
        ("pacman", ["pacman", "-Q"], " "),
        ("apk", ["apk", "list", "--installed"], None),
    ]
    for source, cmd, sep in attempts:
        if not shutil.which(cmd[0]):
            continue
        out = run_cmd(cmd, timeout=60)
        if not out:
            continue
        items = []
        for line in out.splitlines():
            if sep:
                parts = line.split(sep, 1)
                items.append((parts[0], parts[1] if len(parts) > 1 else ""))
            else:  # apk: "name-1.2.3-r0 x86_64 {origin} ..."
                items.append((line.split(" ")[0], ""))
        return source, sorted(items)
    return None, []


def get_installed_apps(max_items):
    if platform.system() == "Windows":
        source, items = _installed_windows()
    else:
        source, items = _installed_posix()
    return {"source": source, "count": len(items),
            "items": [{"name": n, "version": v} for n, v in items[:max_items]]}


def get_top_processes(n=10):
    procs = []
    if platform.system() == "Windows":
        out = run_cmd(["tasklist", "/FO", "CSV", "/NH"])
        for row in csv.reader(out.splitlines()):
            if len(row) >= 5:
                mem = re.sub(r"\D", "", row[4])
                procs.append({"pid": int(row[1]) if row[1].isdigit() else None,
                              "name": row[0], "memory_mb": round(int(mem) / 1024.0, 1) if mem else 0})
        procs.sort(key=lambda p: p["memory_mb"], reverse=True)
    else:
        out = run_cmd(["ps", "-Ao", "pid,pcpu,pmem,comm"])
        for line in out.splitlines()[1:]:
            parts = line.split(None, 3)
            if len(parts) == 4:
                try:
                    procs.append({"pid": int(parts[0]), "cpu_percent": float(parts[1]),
                                  "mem_percent": float(parts[2]),
                                  "name": os.path.basename(parts[3])})
                except ValueError:
                    continue
        procs.sort(key=lambda p: p["mem_percent"], reverse=True)
    return {"total": len(procs), "top_by_memory": procs[:n]}


def get_applications(max_apps):
    return {
        "installed": safe(get_installed_apps, max_apps),
        "tools_detected": {t: shutil.which(t) for t in TOOLS if shutil.which(t)},
        "processes": safe(get_top_processes),
    }


# --------------------------------------------------------------------------
# Deployed applications: what's actually running and serving traffic
# --------------------------------------------------------------------------

_NAME_FROM_CMD_RE = re.compile(
    r"(gunicorn|uwsgi|uvicorn|waitress|puma|unicorn|node|java|python[0-9.]*|"
    r"nginx|apache2?|httpd|caddy|haproxy|envoy|traefik|mysqld|postgres|mongod|"
    r"redis-server|memcached|dotnet|php-fpm|docker-proxy|containerd)", re.I)


def _proc_cmdline(pid):
    if platform.system() == "Linux":
        c = read_file("/proc/%s/cmdline" % pid).replace("\x00", " ").strip()
        if c:
            return c
    return ""


def _guess_app_name(cmdline, fallback):
    m = _NAME_FROM_CMD_RE.search(cmdline or "")
    if m:
        return m.group(1).lower()
    return fallback


def _linux_inode_to_pid_map():
    """Walk /proc/<pid>/fd to map a socket inode -> owning pid. Standard library
    only, so it works even when ss/lsof/netstat aren't installed (common on
    minimal server/container images)."""
    inode_pid = {}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return inode_pid
    for pid in pids:
        try:
            fd_dir = "/proc/%s/fd" % pid
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except OSError:
                    continue
                m = re.match(r"socket:\[(\d+)\]", target)
                if m:
                    inode_pid.setdefault(m.group(1), pid)
        except OSError:
            continue  # process exited mid-scan, or /proc/<pid>/fd not readable (not our process)
    return inode_pid


def _parse_proc_net(path, proto, inode_pid):
    out = []
    for line in read_file(path).splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local, state, inode = parts[1], parts[3], parts[9]
        if proto.startswith("tcp") and state != "0A":  # 0A = LISTEN
            continue
        hexip, _, hexport = local.rpartition(":")
        try:
            port = int(hexport, 16)
            if ":" in hexip or len(hexip) == 32:  # IPv6, 16 bytes hex
                addr = "::"
            else:
                b = bytes.fromhex(hexip)
                addr = ".".join(str(x) for x in b[::-1])
        except ValueError:
            continue
        pid = inode_pid.get(inode)
        name = _proc_name(pid) if pid else None
        out.append({"protocol": proto, "address": addr, "port": port,
                    "pid": int(pid) if pid else None, "process": name})
    return out


def _proc_name(pid):
    name = read_file("/proc/%s/comm" % pid)
    if name:
        return name
    return _guess_app_name(_proc_cmdline(pid), None)


def get_listening_ports():
    """Cross-platform: what's bound to a port and (where determinable) which process."""
    s = platform.system()
    entries = []

    if s == "Linux":
        inode_pid = _linux_inode_to_pid_map()
        for path, proto in (("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6"),
                            ("/proc/net/udp", "udp"), ("/proc/net/udp6", "udp6")):
            if os.path.exists(path):
                entries.extend(_parse_proc_net(path, proto, inode_pid))
        # ss, when present, is more reliable for process names (doesn't need our
        # /proc/<pid>/fd scan to win a race, and resolves names ss already knows)
        out = run_cmd(["ss", "-H", "-tulnp"])
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            local = parts[4] if len(parts) > 4 else ""
            addr, _, port = local.rpartition(":")
            nm = re.search(r'users:\(\("([^"]+)"', line)
            if nm and port.isdigit():
                for e in entries:
                    if e["port"] == int(port) and not e.get("process"):
                        e["process"] = nm.group(1)

    elif s == "Darwin":
        out = run_cmd(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]) or run_cmd(["netstat", "-anv", "-p", "tcp"])
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 9 and "LISTEN" in line:
                name, pid = parts[0], parts[1]
                m = re.search(r":(\d+)$", parts[8])
                if m:
                    entries.append({"protocol": "tcp", "address": parts[8].rsplit(":", 1)[0],
                                    "port": int(m.group(1)),
                                    "pid": int(pid) if pid.isdigit() else None, "process": name})

    elif s == "Windows":
        out = run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                       "Get-NetTCPConnection -State Listen | "
                       "Select-Object LocalAddress,LocalPort,OwningProcess | "
                       "ForEach-Object { \"$($_.LocalAddress)|$($_.LocalPort)|$($_.OwningProcess)\" }"])
        pid_names = {}
        for row in csv.reader(run_cmd(["tasklist", "/FO", "CSV", "/NH"]).splitlines()):
            if len(row) >= 2:
                pid_names[row[1]] = row[0]
        for line in out.splitlines():
            bits = line.strip().split("|")
            if len(bits) == 3 and bits[1].isdigit():
                entries.append({"protocol": "tcp", "address": bits[0], "port": int(bits[1]),
                                "pid": int(bits[2]) if bits[2].isdigit() else None,
                                "process": pid_names.get(bits[2])})

    # de-dupe identical (port, process) pairs e.g. IPv4+IPv6 binds, keep lowest pid
    seen = {}
    for e in entries:
        key = (e["port"], e.get("process"))
        if key not in seen or (e.get("pid") or 1e9) < (seen[key].get("pid") or 1e9):
            seen[key] = e
    return sorted(seen.values(), key=lambda e: e["port"])


def get_containers():
    """Running containers via Docker or Podman CLI (needs the user to have access)."""
    for cmd in (["docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"],
                ["podman", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"]):
        if not shutil.which(cmd[0]):
            continue
        out = run_cmd(cmd, timeout=15)
        if out is None:
            continue
        items = []
        for line in out.splitlines():
            f = line.split("\t")
            if len(f) == 5:
                items.append({"id": f[0], "image": f[1], "name": f[2],
                              "status": f[3], "ports": f[4]})
        return {"runtime": cmd[0], "count": len(items), "containers": items}
    return {"runtime": None, "count": 0, "containers": []}


_SKIP_UNIT_PATTERNS = re.compile(
    r"^(systemd-|dbus|getty|console-|polkit|udisks|rsyslog|cron\.service$|"
    r"networkd-dispatcher|snapd\.|packagekit|ModemManager|accounts-daemon|"
    r"user@|session-)", re.I)


def get_active_services(limit=40):
    """Linux: non-OS-core systemd units that are active -- the closest thing to
    a list of 'what applications this box runs', independent of language/stack."""
    if platform.system() != "Linux" or not shutil.which("systemctl"):
        return None
    out = run_cmd(["systemctl", "list-units", "--type=service", "--state=running",
                  "--no-legend", "--no-pager", "--plain"])
    services = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if not parts:
            continue
        unit = parts[0]
        if not unit.endswith(".service"):
            continue
        name = unit[:-8]
        if _SKIP_UNIT_PATTERNS.match(name):
            continue
        desc = parts[4] if len(parts) > 4 else ""
        services.append({"unit": unit, "description": desc})
    return {"count": len(services), "services": services[:limit]}


def _list_vhosts(enabled_dir, available_dir):
    try:
        names = sorted(os.listdir(enabled_dir))
    except OSError:
        return None
    return {"enabled_dir": enabled_dir, "sites": names}


def get_web_server_sites():
    """nginx / Apache virtual hosts -- what domains/apps a web server is fronting."""
    found = {}
    nginx = _list_vhosts("/etc/nginx/sites-enabled", "/etc/nginx/sites-available")
    if nginx is None and os.path.isdir("/etc/nginx/conf.d"):
        try:
            nginx = {"enabled_dir": "/etc/nginx/conf.d",
                     "sites": [f for f in sorted(os.listdir("/etc/nginx/conf.d"))
                              if f.endswith(".conf")]}
        except OSError:
            pass
    if nginx:
        found["nginx"] = nginx
    for apache_dir in ("/etc/apache2/sites-enabled", "/etc/httpd/conf.d"):
        a = _list_vhosts(apache_dir, None)
        if a:
            found["apache"] = a
            break
    return found or None


def get_deployed_applications(port_limit=200):
    """What's actually running and serving traffic on this machine, as opposed
    to merely installed. Combines listening ports (the most reliable signal),
    containers, systemd services, and web server vhosts."""
    ports = safe(get_listening_ports)
    return {
        "listening_ports": {"count": len(ports) if isinstance(ports, list) else 0,
                            "ports": ports[:port_limit] if isinstance(ports, list) else ports},
        "containers": safe(get_containers),
        "active_services": safe(get_active_services),
        "web_server_sites": safe(get_web_server_sites),
    }


# ============================================================================
# Application dependency scanning -- local/static scan of an app folder:
# runtime version (Python/Java/Node/.NET/Ruby/PHP/Go), app server (Tomcat)
# and version, and every declared library + version.
# ============================================================================

# How many directory levels deep the dependency scanners will recurse looking
# for manifest files. Generous enough for nested/multi-module monorepos
# (frontend/backend split, microservices folders, etc.) without wandering
# into something pathological.
_DEP_SCAN_MAX_DEPTH = 10

_DEP_SCAN_SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "env",
                       "dist", "build", "target", ".idea", ".vscode", "vendor"}


def _find_files(root, names=None, suffix=None, max_depth=_DEP_SCAN_MAX_DEPTH):
    skip = _DEP_SCAN_SKIP_DIRS
    root = os.path.abspath(root)
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in filenames:
            if (names and fn in names) or (suffix and fn.endswith(suffix)):
                yield os.path.join(dirpath, fn)


def _first_existing(paths):
    for p in paths:
        if os.path.isfile(p):
            return p
    return None


def _rel_module(root, dirpath):
    """A directory's path relative to the scan root, using forward slashes,
    for tagging which sub-project/module a detected library belongs to."""
    rel = os.path.relpath(dirpath, root)
    return "." if rel == "." else rel.replace(os.sep, "/")


def _group_manifests_by_dir(root, name_keys, max_depth=_DEP_SCAN_MAX_DEPTH):
    """name_keys: {key: set_of_filenames}. Recursively finds every matching
    manifest file under root and groups full paths by the directory they live
    in, so a single scan can tell "this subfolder is its own project" apart
    from "the whole repo root is one project." Returns {dirpath: {key: path}}."""
    by_dir = {}
    for key, names in name_keys.items():
        for f in _find_files(root, names=names, max_depth=max_depth):
            by_dir.setdefault(os.path.dirname(f), {})[key] = f
    return by_dir


def _walk_dirs(root, max_depth=_DEP_SCAN_MAX_DEPTH, skip=None):
    """Like os.walk but depth-capped and skipping common noise directories --
    shared by the directory-shaped detectors below (WEB-INF/lib, Tomcat homes)."""
    skip = skip or _DEP_SCAN_SKIP_DIRS
    root_abs = os.path.abspath(root)
    base_depth = root_abs.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root_abs):
        depth = dirpath.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in skip]
        yield dirpath, dirnames, filenames


_PY_REQ_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"((?:==|>=|<=|~=|!=|>|<)\s*[A-Za-z0-9.*+!_-]+(?:\s*,\s*(?:==|>=|<=|~=|!=|>|<)\s*[A-Za-z0-9.*+!_-]+)*)?")


def _parse_requirements(path):
    libs = []
    for line in read_file_raw(path).splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        m = _PY_REQ_RE.match(line)
        if m and m.group(1):
            libs.append({"name": m.group(1), "version_spec": (m.group(2) or "").replace(" ", "") or None})
    return libs


def _parse_pyproject(path):
    """Best-effort TOML parse without a toml library: pull [tool.poetry.dependencies]
    or PEP 621 [project] dependencies with a regex, since the stdlib's tomllib
    isn't available before Python 3.11."""
    txt = read_file_raw(path)
    libs = []
    m = re.search(r"dependencies\s*=\s*\[(.*?)\]", txt, re.S)
    if m:
        for entry in re.findall(r'"([^"]+)"', m.group(1)):
            pm = re.match(r"([A-Za-z0-9._-]+)\s*(.*)", entry)
            if pm:
                libs.append({"name": pm.group(1), "version_spec": pm.group(2) or None})
    sec = re.search(r"\[tool\.poetry\.dependencies\](.*?)(\n\[|\Z)", txt, re.S)
    if sec:
        for line in sec.group(1).splitlines():
            m2 = re.match(r'\s*([A-Za-z0-9._-]+)\s*=\s*"?([^"\n]*)"?', line)
            if m2 and m2.group(1).lower() != "python":
                libs.append({"name": m2.group(1), "version_spec": m2.group(2) or None})
    return libs


def _parse_pipfile_packages(txt):
    libs = []
    sec = re.search(r"\[packages\](.*?)(\n\[|\Z)", txt, re.S)
    if sec:
        for line in sec.group(1).splitlines():
            m = re.match(r'\s*([A-Za-z0-9._-]+)\s*=\s*"?([^"\n]*)"?', line)
            if m:
                libs.append({"name": m.group(1), "version_spec": None if m.group(2) == "*" else m.group(2)})
    return libs


def scan_python_deps(root):
    """Recursively finds EVERY Python project under root (any subfolder with
    its own requirements.txt / pyproject.toml / Pipfile is its own module --
    common in monorepos with e.g. a backend/ and a scripts/ or worker/)."""
    result = {"present": False, "runtime": {}, "manifest": None, "libraries": [], "modules": []}
    by_dir = _group_manifests_by_dir(root, {
        "requirements.txt": {"requirements.txt"},
        "pyproject.toml": {"pyproject.toml"},
        "Pipfile": {"Pipfile"},
        "runtime.txt": {"runtime.txt"},
    })
    modules, all_libs = [], []
    for dirpath in sorted(by_dir):
        files = by_dir[dirpath]
        if not ({"requirements.txt", "pyproject.toml", "Pipfile"} & set(files)):
            continue  # a lone runtime.txt with nothing else isn't a Python project on its own
        module = _rel_module(root, dirpath)
        manifest_parts, libs = [], []
        if "requirements.txt" in files:
            manifest_parts.append(os.path.relpath(files["requirements.txt"], root))
            libs = _parse_requirements(files["requirements.txt"])
        elif "pyproject.toml" in files:
            manifest_parts.append(os.path.relpath(files["pyproject.toml"], root))
            libs = _parse_pyproject(files["pyproject.toml"])
        elif "Pipfile" in files:
            manifest_parts.append(os.path.relpath(files["Pipfile"], root))
            libs = _parse_pipfile_packages(read_file_raw(files["Pipfile"]))

        declared = None
        if "pyproject.toml" in files:
            m = re.search(r'python\s*=\s*"([^"]+)"', read_file_raw(files["pyproject.toml"]))
            if m:
                declared = m.group(1)
        if "runtime.txt" in files:  # Heroku-style, takes priority when present
            declared = read_file(files["runtime.txt"])

        for lib in libs:
            lib["module"] = module
        modules.append({"module": module, "manifest": ", ".join(manifest_parts),
                        "declared_version": declared, "libraries": libs})
        all_libs.extend(libs)

    if modules:
        result["present"] = True
        result["modules"] = modules
        result["libraries"] = all_libs
        result["manifest"] = modules[0]["manifest"]
    result["runtime"] = {
        "declared_version": next((m["declared_version"] for m in modules if m["declared_version"]), None),
        "interpreter_running_this_scan": platform.python_version(),
    }
    return result


# Official Node.js LTS release codenames, by major version.
# https://github.com/nodejs/Release -- odd majors are never LTS and have no codename.
_NODE_LTS_CODENAMES = {
    4: "Argon", 6: "Boron", 8: "Carbon", 10: "Dubnium", 12: "Erbium",
    14: "Fermium", 16: "Gallium", 18: "Hydrogen", 20: "Iron", 22: "Jod",
}


def _node_codename(version_str):
    if not version_str:
        return None
    m = re.search(r"(\d+)", version_str)
    return _NODE_LTS_CODENAMES.get(int(m.group(1))) if m else None


def scan_node_deps(root):
    """Finds every package.json under root (node_modules is always skipped),
    so a frontend/ + backend/ split, or any multi-package workspace, is
    reported as separate modules rather than only whichever is in the root."""
    result = {"present": False, "runtime": {}, "manifest": None, "libraries": [], "modules": []}
    node_running = run_cmd(["node", "--version"]) or None
    modules, all_libs = [], []
    for pkg in sorted(_find_files(root, names={"package.json"})):
        try:
            data = json.loads(read_file_raw(pkg))
        except ValueError:
            continue
        module = _rel_module(root, os.path.dirname(pkg))
        libs = []
        for section, kind in (("dependencies", "runtime"), ("devDependencies", "dev")):
            for name, spec in (data.get(section) or {}).items():
                libs.append({"name": name, "version_spec": spec, "kind": kind, "module": module})
        d = os.path.dirname(pkg)
        lockfile = ("package-lock.json" if os.path.isfile(os.path.join(d, "package-lock.json"))
                   else "yarn.lock" if os.path.isfile(os.path.join(d, "yarn.lock")) else None)
        declared_node = (data.get("engines") or {}).get("node")
        modules.append({"module": module, "manifest": os.path.relpath(pkg, root), "libraries": libs,
                        "declared_node_version": declared_node, "lockfile": lockfile})
        all_libs.extend(libs)

    if modules:
        result["present"] = True
        result["modules"] = modules
        result["libraries"] = all_libs
        result["manifest"] = modules[0]["manifest"]
        if modules[0].get("lockfile"):
            result["lockfile"] = modules[0]["lockfile"]
        declared = next((m["declared_node_version"] for m in modules if m["declared_node_version"]), None)
        result["runtime"] = {
            "declared_node_version": declared,
            "node_running_this_scan": node_running,
            # LTS codename (e.g. "Iron" for Node 20) of whichever version is known;
            # declared takes priority since that's what the app is pinned to
            "version_name": _node_codename(declared) or _node_codename(node_running),
        }
    return result


def _parse_pom(path):
    libs, props = [], {}
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return libs, props
    root = tree.getroot()
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    def tag(el, name):
        found = el.find(ns + name)
        return found.text.strip() if found is not None and found.text else None

    props_el = root.find(ns + "properties")
    if props_el is not None:
        for child in props_el:
            if child.text:
                props[child.tag.replace(ns, "")] = child.text.strip()

    deps_el = root.find(ns + "dependencies")
    if deps_el is not None:
        for dep in deps_el.findall(ns + "dependency"):
            gid, aid, ver = tag(dep, "groupId"), tag(dep, "artifactId"), tag(dep, "version")
            if ver and ver.startswith("${") and ver.endswith("}"):
                ver = props.get(ver[2:-1], ver)
            scope = tag(dep, "scope")
            libs.append({"name": "%s:%s" % (gid, aid), "version_spec": ver,
                        "kind": scope or "compile"})
    return libs, props


def _parse_gradle(path):
    libs = []
    txt = read_file_raw(path)
    for m in re.finditer(r"""(?:implementation|api|compile|testImplementation|runtimeOnly)\s*"""
                         r"""[\(\s]*['"]([\w.\-]+):([\w.\-]+):([\w.\-\[\],+]+)['"]""", txt):
        gid, aid, ver = m.groups()
        libs.append({"name": "%s:%s" % (gid, aid), "version_spec": ver, "kind": "gradle"})
    return libs


def _java_version_declared(pom_props, gradle_txt):
    for key in ("maven.compiler.source", "maven.compiler.target", "java.version"):
        if pom_props.get(key):
            return pom_props[key]
    if gradle_txt:
        m = re.search(r"sourceCompatibility\s*=\s*['\"]?([\w.]+)", gradle_txt)
        if m:
            return m.group(1)
    return None


def _java_version_running():
    out = run_cmd(["java", "-version"])
    m = re.search(r'version "([^"]+)"', out)
    return m.group(1) if m else None


def _find_webinf_lib_dirs(root):
    for dirpath, _dirnames, _filenames in _walk_dirs(root):
        if os.path.basename(dirpath) == "lib" and os.path.basename(os.path.dirname(dirpath)) == "WEB-INF":
            yield dirpath


def scan_java_deps(root):
    """Finds every pom.xml / build.gradle(.kts) under root (each directory
    with one is its own module -- a parent-POM multi-module build, or several
    unrelated Java services in one repo), plus every WEB-INF/lib/*.jar found
    anywhere under root (an exploded WAR deploy)."""
    result = {"present": False, "runtime": {}, "manifest": None, "libraries": [], "modules": []}
    by_dir = _group_manifests_by_dir(root, {
        "pom.xml": {"pom.xml"},
        "build.gradle": {"build.gradle", "build.gradle.kts"},
    })
    modules, all_libs = [], []
    for dirpath in sorted(by_dir):
        files = by_dir[dirpath]
        module = _rel_module(root, dirpath)
        libs, props, manifest_parts, gradle_txt = [], {}, [], ""
        if "pom.xml" in files:
            libs, props = _parse_pom(files["pom.xml"])
            manifest_parts.append(os.path.relpath(files["pom.xml"], root))
        if "build.gradle" in files:
            gradle_txt = read_file_raw(files["build.gradle"])
            libs = libs + _parse_gradle(files["build.gradle"])
            manifest_parts.append(os.path.relpath(files["build.gradle"], root))
        for lib in libs:
            lib["module"] = module
        modules.append({"module": module, "manifest": ", ".join(manifest_parts), "libraries": libs,
                        "declared_java_version": _java_version_declared(props, gradle_txt)})
        all_libs.extend(libs)

    for webinf_lib in sorted(_find_webinf_lib_dirs(root)):
        jar_libs = []
        module = _rel_module(root, os.path.dirname(webinf_lib))
        for fn in sorted(os.listdir(webinf_lib)):
            if fn.endswith(".jar"):
                m = re.match(r"(.+?)-(\d[\w.\-]*)\.jar$", fn)
                if m:
                    jar_libs.append({"name": m.group(1), "version_spec": m.group(2), "kind": "jar", "module": module})
                else:
                    jar_libs.append({"name": fn[:-4], "version_spec": None, "kind": "jar", "module": module})
        if jar_libs:
            manifest = os.path.relpath(os.path.join(os.path.dirname(webinf_lib), "WEB-INF", "lib"), root) + "/*.jar"
            modules.append({"module": module, "manifest": manifest, "libraries": jar_libs,
                            "declared_java_version": None})
            all_libs.extend(jar_libs)

    if modules:
        result["present"] = True
        result["modules"] = modules
        result["libraries"] = all_libs
        result["manifest"] = ", ".join(m["manifest"] for m in modules if m["manifest"])
        result["runtime"] = {
            "declared_java_version": next((m["declared_java_version"] for m in modules
                                           if m["declared_java_version"]), None),
            "java_running_this_scan": _java_version_running(),
        }
    return result


def _find_tomcat_homes(root):
    env_home = os.environ.get("CATALINA_HOME") or os.environ.get("CATALINA_BASE")
    seen = set()
    if env_home and os.path.isdir(env_home):
        seen.add(os.path.abspath(env_home))
        yield env_home
    for dirpath, _dirnames, _filenames in _walk_dirs(root):
        if os.path.basename(dirpath) == "bin" and (
                os.path.isfile(os.path.join(dirpath, "catalina.sh")) or
                os.path.isfile(os.path.join(dirpath, "catalina.bat"))):
            home = os.path.dirname(dirpath)
            if os.path.abspath(home) not in seen:
                seen.add(os.path.abspath(home))
                yield home


def scan_tomcat_deps(root):
    """Detect every Tomcat install (not just a webapp) found anywhere under
    root by its own directory layout, reading each one's version from
    RELEASE-NOTES or the bootstrap jar manifest."""
    result = {"present": False, "version": None, "evidence": None, "instances": []}
    instances = []
    for base in _find_tomcat_homes(root):
        bin_dir = os.path.join(base, "bin")
        inst = {"path": base, "version": None, "evidence": None}
        notes = _first_existing([os.path.join(base, "RELEASE-NOTES")])
        if notes:
            m = re.search(r"Apache Tomcat Version\s+([\w.]+)", read_file_raw(notes))
            if m:
                inst.update(version=m.group(1), evidence="RELEASE-NOTES")
        if not inst["version"]:
            cp = os.path.join(bin_dir, "bootstrap.jar")
            if os.path.isfile(cp):
                out = run_cmd(["java", "-cp", cp, "org.apache.catalina.util.ServerInfo"])
                m = (re.search(r"Server number:\s*([\w.]+)", out) or
                     re.search(r"Server version:\s*Apache Tomcat/([\w.]+)", out))
                if m:
                    inst.update(version=m.group(1), evidence="ServerInfo")
        instances.append(inst)
    if instances:
        result["present"] = True
        result["instances"] = instances
        result["version"] = instances[0]["version"]
        result["evidence"] = instances[0]["evidence"]
    return result


def scan_dotnet_deps(root):
    """Finds every .csproj under root, each as its own module (a typical
    .NET solution with several projects, or multiple unrelated services)."""
    result = {"present": False, "runtime": {}, "manifest": None, "libraries": [], "modules": []}
    modules, all_libs = [], []
    for csproj in sorted(_find_files(root, suffix=".csproj")):
        txt = read_file_raw(csproj)
        module = _rel_module(root, os.path.dirname(csproj))
        m = re.search(r"<TargetFramework>([^<]+)</TargetFramework>", txt)
        libs = []
        for pm in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', txt):
            libs.append({"name": pm.group(1), "version_spec": pm.group(2), "module": module})
        modules.append({"module": module, "manifest": os.path.relpath(csproj, root), "libraries": libs,
                        "declared_target_framework": m.group(1) if m else None})
        all_libs.extend(libs)

    if modules:
        result["present"] = True
        result["modules"] = modules
        result["libraries"] = all_libs
        result["manifest"] = modules[0]["manifest"]
        result["runtime"]["declared_target_framework"] = next(
            (m["declared_target_framework"] for m in modules if m["declared_target_framework"]), None)
    return result


def scan_ruby_deps(root):
    """Finds every Gemfile under root, each as its own module."""
    result = {"present": False, "runtime": {}, "manifest": None, "libraries": [], "modules": []}
    modules, all_libs = [], []
    for gemfile in sorted(_find_files(root, names={"Gemfile"})):
        module = _rel_module(root, os.path.dirname(gemfile))
        libs = []
        for m in re.finditer(r"gem\s+['\"]([\w.\-]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", read_file_raw(gemfile)):
            libs.append({"name": m.group(1), "version_spec": m.group(2), "module": module})
        rv = _first_existing([os.path.join(os.path.dirname(gemfile), ".ruby-version")])
        modules.append({"module": module, "manifest": os.path.relpath(gemfile, root), "libraries": libs,
                        "declared_ruby_version": read_file(rv) if rv else None})
        all_libs.extend(libs)

    if modules:
        result["present"] = True
        result["modules"] = modules
        result["libraries"] = all_libs
        result["manifest"] = modules[0]["manifest"]
        result["runtime"]["declared_ruby_version"] = next(
            (m["declared_ruby_version"] for m in modules if m["declared_ruby_version"]), None)
    return result


def scan_php_deps(root):
    """Finds every composer.json under root, each as its own module."""
    result = {"present": False, "runtime": {}, "manifest": None, "libraries": [], "modules": []}
    modules, all_libs = [], []
    for composer in sorted(_find_files(root, names={"composer.json"})):
        try:
            data = json.loads(read_file_raw(composer))
        except ValueError:
            continue
        module = _rel_module(root, os.path.dirname(composer))
        libs = [{"name": n, "version_spec": v, "module": module}
                for n, v in (data.get("require") or {}).items() if n != "php"]
        modules.append({"module": module, "manifest": os.path.relpath(composer, root), "libraries": libs,
                        "declared_php_version": (data.get("require") or {}).get("php")})
        all_libs.extend(libs)

    if modules:
        result["present"] = True
        result["modules"] = modules
        result["libraries"] = all_libs
        result["manifest"] = modules[0]["manifest"]
        result["runtime"]["declared_php_version"] = next(
            (m["declared_php_version"] for m in modules if m["declared_php_version"]), None)
    return result


def scan_go_deps(root):
    """Finds every go.mod under root, each as its own module."""
    result = {"present": False, "runtime": {}, "manifest": None, "libraries": [], "modules": []}
    modules, all_libs = [], []
    for gomod in sorted(_find_files(root, names={"go.mod"})):
        txt = read_file_raw(gomod)
        module = _rel_module(root, os.path.dirname(gomod))
        m = re.search(r"^go\s+([\d.]+)", txt, re.M)
        libs = []
        for m2 in re.finditer(r"^\s*([\w./-]+)\s+(v[\w.\-+]+)", txt, re.M):
            if m2.group(1) not in ("go", "module"):
                libs.append({"name": m2.group(1), "version_spec": m2.group(2), "module": module})
        modules.append({"module": module, "manifest": os.path.relpath(gomod, root), "libraries": libs,
                        "declared_go_version": m.group(1) if m else None})
        all_libs.extend(libs)

    if modules:
        result["present"] = True
        result["modules"] = modules
        result["libraries"] = all_libs
        result["manifest"] = modules[0]["manifest"]
        result["runtime"]["declared_go_version"] = next(
            (m["declared_go_version"] for m in modules if m["declared_go_version"]), None)
    return result


def scan_rust_deps(root):
    """Finds every Cargo.toml under root, each as its own module. A best-effort
    regex parse of [dependencies] (no toml library in the stdlib before 3.11)."""
    result = {"present": False, "runtime": {}, "manifest": None, "libraries": [], "modules": []}
    modules, all_libs = [], []
    for cargo in sorted(_find_files(root, names={"Cargo.toml"})):
        txt = read_file_raw(cargo)
        module = _rel_module(root, os.path.dirname(cargo))
        m = re.search(r'edition\s*=\s*"([^"]+)"', txt)
        libs = []
        sec = re.search(r"\[dependencies\](.*?)(\n\[|\Z)", txt, re.S)
        if sec:
            for line in sec.group(1).splitlines():
                lm = re.match(r'\s*([A-Za-z0-9_-]+)\s*=\s*"?([\w.\-^~=*]*)"?', line)
                if lm and lm.group(1):
                    libs.append({"name": lm.group(1), "version_spec": lm.group(2) or None, "module": module})
        modules.append({"module": module, "manifest": os.path.relpath(cargo, root), "libraries": libs,
                        "declared_edition": m.group(1) if m else None})
        all_libs.extend(libs)

    if modules:
        result["present"] = True
        result["modules"] = modules
        result["libraries"] = all_libs
        result["manifest"] = modules[0]["manifest"]
        result["runtime"]["declared_edition"] = next(
            (m["declared_edition"] for m in modules if m["declared_edition"]), None)
    return result


# --------------------------------------------------------------------------
# Latest-version lookup (opt-in, needs network: --check-latest)
# --------------------------------------------------------------------------
# Everything above this point is a pure local file scan. This section is the
# one part of the whole tool that calls out to the internet -- one read-only
# GET per library, to that ecosystem's public registry, to find out the
# newest version published for comparison against what's pinned. It never
# runs unless --check-latest is passed.

_UA = {"User-Agent": "system-analyzer/%s (+local dependency scan)" % VERSION}


def _fetch_json(url, timeout=6):
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _latest_pypi(name):
    data = _fetch_json("https://pypi.org/pypi/%s/json" % name)
    return (data or {}).get("info", {}).get("version")


def _latest_npm(name):
    data = _fetch_json("https://registry.npmjs.org/%s/latest" % urllib.request.quote(name, safe=""))
    return (data or {}).get("version")


def _latest_rubygems(name):
    data = _fetch_json("https://rubygems.org/api/v1/gems/%s.json" % name)
    return (data or {}).get("version")


def _latest_packagist(name):
    # name is already "vendor/package" from composer.json
    data = _fetch_json("https://repo.packagist.org/p2/%s.json" % name)
    try:
        versions = data["packages"][name]
        stable = [v["version"] for v in versions if not re.search(r"-(dev|alpha|beta|rc)", v["version"], re.I)]
        return (stable or [v["version"] for v in versions])[0]
    except Exception:
        return None


def _latest_nuget(name):
    data = _fetch_json("https://api.nuget.org/v3-flatcontainer/%s/index.json" % name.lower())
    versions = (data or {}).get("versions") or []
    stable = [v for v in versions if not re.search(r"-", v)]
    return (stable or versions)[-1] if versions else None


def _latest_maven(coord):
    # coord is "groupId:artifactId"
    if ":" not in coord:
        return None
    gid, aid = coord.split(":", 1)
    data = _fetch_json("https://search.maven.org/solrsearch/select?q=g:%22%s%22+AND+a:%22%s%22"
                       "&core=gav&rows=1&wt=json&sort=v+desc" % (gid, aid))
    try:
        return data["response"]["docs"][0]["v"]
    except Exception:
        return None


def _latest_crates(name):
    data = _fetch_json("https://crates.io/api/v1/crates/%s" % name)
    return (data or {}).get("crate", {}).get("max_stable_version") or (data or {}).get("crate", {}).get("newest_version")


_LATEST_LOOKUP = {
    "python": _latest_pypi,
    "node": _latest_npm,
    "ruby": _latest_rubygems,
    "php": _latest_packagist,
    "dotnet": _latest_nuget,
    "java": _latest_maven,
    "rust": _latest_crates,
}


def _normalize_version(v):
    """Strip common specifier prefixes (==, ^, ~, >=, etc.) down to a bare
    version string, for comparing against a registry's 'latest'."""
    if not v:
        return None
    m = re.search(r"\d[\w.\-]*", v)
    return m.group(0) if m else None


def enrich_with_latest_versions(ecosystems, max_per_ecosystem=60, progress=True):
    """Mutates `ecosystems` in place: adds latest_version + is_outdated to
    every library, for ecosystems with a registry lookup available. Best
    effort -- a failed/timed-out lookup just leaves latest_version as None.
    This is the only part of the tool that makes network calls, so it's also
    the slowest -- one request per library -- hence the progress messages."""
    to_check = []
    for eco_name, lookup_fn in _LATEST_LOOKUP.items():
        eco = ecosystems.get(eco_name)
        if not isinstance(eco, dict) or not eco.get("present"):
            continue
        for lib in eco.get("libraries", [])[:max_per_ecosystem]:
            to_check.append((lib, lookup_fn))

    total = len(to_check)
    if progress and total:
        sys.stderr.write("Checking latest published versions for %d librar%s...\n" %
                         (total, "y" if total == 1 else "ies"))
        sys.stderr.flush()
    for i, (lib, lookup_fn) in enumerate(to_check, 1):
        if progress and total > 1 and (i % 10 == 0 or i == total):
            sys.stderr.write("  ...%d/%d checked\n" % (i, total))
            sys.stderr.flush()
        try:
            latest = lookup_fn(lib["name"])
        except Exception:
            latest = None
        lib["latest_version"] = latest
        pinned = _normalize_version(lib.get("version_spec"))
        lib["is_outdated"] = bool(latest and pinned and latest != pinned)
    return ecosystems


# --------------------------------------------------------------------------
# Library "version name" -- e.g. "NumPy 2" for numpy==2.0.0, "Pandas 2" for
# pandas==2.2.3. This is the library's real display name plus its major
# version number, the way projects commonly refer to a major release. Pure
# local derivation -- no network needed, works whether or not --check-latest
# was used.
# --------------------------------------------------------------------------

# A library's package/import name often isn't how the project capitalizes its
# own name (numpy -> NumPy, sqlalchemy -> SQLAlchemy). This covers the common
# ones; anything not listed falls back to a reasonable title-cased guess.
_LIBRARY_DISPLAY_NAMES = {
    # Python
    "numpy": "NumPy", "pandas": "Pandas", "scipy": "SciPy", "matplotlib": "Matplotlib",
    "flask": "Flask", "django": "Django", "fastapi": "FastAPI", "requests": "Requests",
    "sqlalchemy": "SQLAlchemy", "gunicorn": "Gunicorn", "uvicorn": "Uvicorn",
    "pytest": "pytest", "pydantic": "Pydantic", "celery": "Celery", "scikit-learn": "scikit-learn",
    "pillow": "Pillow", "beautifulsoup4": "Beautiful Soup", "pyyaml": "PyYAML",
    "jinja2": "Jinja", "werkzeug": "Werkzeug", "boto3": "Boto3", "redis": "redis-py",
    "psycopg2": "Psycopg2", "pymongo": "PyMongo", "cryptography": "PyCA Cryptography",
    "tensorflow": "TensorFlow", "torch": "PyTorch", "transformers": "Transformers",
    # Node.js
    "react": "React", "vue": "Vue", "angular": "Angular", "express": "Express",
    "axios": "Axios", "lodash": "Lodash", "jest": "Jest", "eslint": "ESLint",
    "webpack": "webpack", "typescript": "TypeScript", "next": "Next.js", "nuxt": "Nuxt",
    "vite": "Vite", "babel": "Babel", "jquery": "jQuery", "moment": "Moment.js",
    "socket.io": "Socket.IO", "mongoose": "Mongoose", "nodemon": "nodemon",
    # Java (artifactId, not groupId:artifactId)
    "spring-boot-starter-web": "Spring Boot", "spring-core": "Spring Framework",
    "mysql-connector-java": "MySQL Connector/J", "lombok": "Lombok",
    "commons-io": "Apache Commons IO", "commons-lang3": "Apache Commons Lang",
    "log4j-core": "Log4j", "slf4j-api": "SLF4J", "junit": "JUnit", "guava": "Guava",
    "hibernate-core": "Hibernate", "jackson-databind": "Jackson",
    # Ruby / PHP / .NET
    "rails": "Ruby on Rails", "rspec": "RSpec", "nokogiri": "Nokogiri", "devise": "Devise",
    "laravel/framework": "Laravel", "symfony/console": "Symfony", "guzzlehttp/guzzle": "Guzzle",
    "newtonsoft.json": "Newtonsoft.Json", "entityframework": "Entity Framework",
    "automapper": "AutoMapper", "serilog": "Serilog",
}


def _library_display_name(raw_name):
    if not raw_name:
        return raw_name
    key = raw_name.strip()
    if key.lower() in _LIBRARY_DISPLAY_NAMES:
        return _LIBRARY_DISPLAY_NAMES[key.lower()]
    # Java dependencies are recorded as "groupId:artifactId" -- look up (and
    # fall back to title-casing) just the artifactId part.
    if ":" in key:
        artifact = key.split(":", 1)[1]
        if artifact.lower() in _LIBRARY_DISPLAY_NAMES:
            return _LIBRARY_DISPLAY_NAMES[artifact.lower()]
        key = artifact
    # Generic fallback: "scikit-learn" stays as-is if already lowercase-hyphenated
    # and known; otherwise title-case each word segment, e.g. "some-package" ->
    # "Some Package". Preserve segments that are already mixed-case (likely
    # intentional, e.g. a scoped npm name) rather than reflowing them.
    words = re.split(r"[-_]", key)
    return " ".join(w if (w != w.lower() and w != w.upper()) else w.capitalize() for w in words if w)


def _version_name_for(raw_name, version_spec, latest_version):
    """'<Display Name> <major version>', using whichever version is known --
    the pinned one if present, else the latest-published one if looked up."""
    display = _library_display_name(raw_name)
    major = None
    for candidate in (version_spec, latest_version):
        v = _normalize_version(candidate)
        if v:
            m = re.match(r"(\d+)", v)
            if m:
                major = m.group(1)
                break
    if not display or major is None:
        return None
    return "%s %s" % (display, major)


def _add_version_names(ecosystems):
    for eco in ecosystems.values():
        if not isinstance(eco, dict):
            continue
        for lib in eco.get("libraries", []):
            lib["version_name"] = _version_name_for(
                lib.get("name"), lib.get("version_spec"), lib.get("latest_version"))
    return ecosystems


def scan_application_dependencies(root, check_latest=False):
    """Static scan of one app folder: runtime version, app server, and every
    declared library per ecosystem found. Local-only and network-free, unless
    check_latest=True (--check-latest), which adds one registry lookup per
    library to report its latest published version alongside what's pinned."""
    root = os.path.abspath(root)
    ecosystems = {
        "python": safe(scan_python_deps, root),
        "node": safe(scan_node_deps, root),
        "java": safe(scan_java_deps, root),
        "dotnet": safe(scan_dotnet_deps, root),
        "ruby": safe(scan_ruby_deps, root),
        "php": safe(scan_php_deps, root),
        "go": safe(scan_go_deps, root),
    }
    tomcat = safe(scan_tomcat_deps, root)
    detected = [name for name, r in ecosystems.items() if isinstance(r, dict) and r.get("present")]
    total_libs = sum(len(r.get("libraries", [])) for r in ecosystems.values()
                     if isinstance(r, dict) and r.get("libraries"))
    if check_latest:
        safe(enrich_with_latest_versions, ecosystems)
    safe(_add_version_names, ecosystems)
    return {
        "scanned_path": root,
        "scan_type": "local-static",
        "checked_latest_versions": check_latest,
        "ecosystems_detected": detected,
        "total_libraries_found": total_libs,
        "application_server": {"tomcat": tomcat},
        "ecosystems": ecosystems,
    }


# Common places a deployed app tends to live, tried in order when --app-path
# isn't given. Each candidate is only used if it actually looks like an app
# (i.e. scan_application_dependencies finds at least one ecosystem in it).
_DEFAULT_APP_PATH_CANDIDATES = [
    ".",
    "/var/www", "/var/www/html",
    "/opt", "/srv",
    "/usr/local/tomcat/webapps/ROOT", "/opt/tomcat/webapps/ROOT",
]


def auto_scan_application_dependencies(check_latest=False):
    for base in os.environ.get("CATALINA_HOME", ""), os.environ.get("CATALINA_BASE", ""):
        if base:
            wa = os.path.join(base, "webapps", "ROOT")
            if os.path.isdir(wa):
                r = safe(scan_application_dependencies, wa, check_latest)
                if isinstance(r, dict) and r.get("ecosystems_detected"):
                    return r
    for cand in _DEFAULT_APP_PATH_CANDIDATES:
        if os.path.isdir(cand):
            r = safe(scan_application_dependencies, cand, check_latest)
            if isinstance(r, dict) and r.get("ecosystems_detected"):
                return r
    # nothing found: still return the current-directory result so the key
    # is always present and shows what (if anything) was checked
    return safe(scan_application_dependencies, ".", check_latest)


# --------------------------------------------------------------------------
# Gather everything
# --------------------------------------------------------------------------

def gather_all(max_apps=25, app_path=None, check_latest=False, progress=None):
    sections = {}
    stages = [
        ("meta", lambda: {"analyzer_version": VERSION,
                          "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          "collected_on": platform.node()}),
        ("os", get_os_info),
        ("cpu", get_cpu_info),
        ("memory", get_memory_info),
        ("disk", get_disk_info),
        ("virtualization", detect_virtualization),
        ("network", get_network_info),
        ("applications", lambda: get_applications(max_apps)),
        ("deployed_applications", get_deployed_applications),
        ("application_dependencies",
         lambda: (scan_application_dependencies(app_path, check_latest) if app_path
                  else auto_scan_application_dependencies(check_latest))),
    ]
    total = len(stages)
    for completed, (name, collect) in enumerate(stages, 1):
        sections[name] = collect() if name == "meta" else safe(collect)
        if progress:
            progress(completed * 100 // total)
    return sections


# --------------------------------------------------------------------------
# Remote mode (SSH via paramiko)
# --------------------------------------------------------------------------

def _exec(client, cmd, timeout, stdin_data=None):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    if stdin_data is not None:
        stdin.write(stdin_data)
        stdin.flush()
        stdin.channel.shutdown_write()
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    return stdout.channel.recv_exit_status(), out, err


def _parse_json(out):
    start, end = out.find("{"), out.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(out[start:end + 1])
    except ValueError:
        return None


def _remote_upload(client, source, flags, timeout):
    """Optional file-based mode (POSIX servers): SFTP upload -> run -> delete."""
    rc, out, _ = _exec(client, "uname -s", 15)
    if rc != 0:
        sys.stderr.write("[info] --upload supports POSIX servers only; using stdin instead\n")
        return None
    import io
    remote = "/tmp/_sysanalyzer_%s.py" % uuid.uuid4().hex[:12]
    sftp = client.open_sftp()
    try:
        sftp.putfo(io.BytesIO(source), remote)
        sftp.chmod(remote, 0o600)
        for py in ("python3", "python"):
            rc, out, err = _exec(client, "%s %s %s" % (py, remote, flags), timeout)
            data = _parse_json(out)
            if data:
                return data
    finally:
        try:
            sftp.remove(remote)
        except Exception:
            _exec(client, "rm -f %s" % remote, 15)
        sftp.close()
    return None


def run_remote(args, progress=None):
    try:
        import paramiko
    except ImportError:
        sys.exit("Remote mode needs paramiko:  pip install paramiko")
    if not args.user:
        sys.exit("--user is required with --host")

    password = args.password or os.environ.get("SYSANALYZER_PASSWORD")
    if args.ask_pass:
        password = getpass.getpass("SSH password for %s@%s: " % (args.user, args.host))

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(
        paramiko.RejectPolicy() if args.strict_host_key else paramiko.AutoAddPolicy())

    kw = dict(hostname=args.host, port=args.port, username=args.user, timeout=args.timeout,
              banner_timeout=args.timeout, auth_timeout=args.timeout)
    if args.key:
        kw["key_filename"] = os.path.expanduser(args.key)
        if args.key_passphrase:
            kw["passphrase"] = args.key_passphrase
    if password:
        kw["password"] = password
    try:
        client.connect(**kw)
    except Exception as e:
        sys.exit("SSH connection to %s:%s failed: %s" % (args.host, args.port, e))
    if progress:
        progress(20)

    with open(os.path.abspath(__file__), "rb") as f:
        source = f.read()
    if progress:
        progress(25)
    flags = "--json --max-apps %d" % args.max_apps
    if args.app_path:
        flags += " --app-path %s" % args.app_path
    if args.check_latest:
        flags += " --check-latest"  # note: runs on the SERVER, which needs its own internet access
    errors = []
    try:
        if args.upload:
            if progress:
                progress(30)
            data = _remote_upload(client, source, flags, args.run_timeout)
            if data:
                if progress:
                    progress(100)
                return data
        # Default: pipe this script into the remote interpreter's stdin.
        # No temp file, nothing to clean up, works on Linux/macOS/Windows SSH servers.
        if progress:
            progress(30)
        for py in ("python3", "python", "py -3"):
            rc, out, err = _exec(client, "%s - %s" % (py, flags), args.run_timeout, source)
            data = _parse_json(out)
            if data:
                if progress:
                    progress(100)
                return data
            errors.append("%s -> exit %s %s" % (py, rc, (err or out).strip()[:200]))
    finally:
        client.close()
    sys.exit("Could not run Python 3 on the server:\n  " + "\n  ".join(errors))


# --------------------------------------------------------------------------
# HTML report (self-contained, dark-themed dashboard over the same JSON)
# --------------------------------------------------------------------------

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>System &amp; VM Analyzer Report</title>
<style>
  :root{
    --bg:#10141A; --panel:#171D26; --panel-2:#1D2530; --line:#2A3341;
    --text:#E8ECF1; --text-dim:#8B96A5; --accent:#4C8DFF; --warn:#E8A33D; --ok:#4CC38A; --off:#566072;
  }
  *{box-sizing:border-box;}
  body{margin:0;background:var(--bg);color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    -webkit-font-smoothing:antialiased;}
  .mono{font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;}
  header{padding:20px clamp(16px,4vw,40px);border-bottom:1px solid var(--line);
    display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;}
  .brand{display:flex;align-items:center;gap:12px;}
  .brand-mark{width:34px;height:34px;border-radius:8px;
    background:linear-gradient(155deg,var(--accent),#2E5FCC);
    display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;
    color:#fff;flex-shrink:0;}
  .brand h1{font-size:15px;margin:0;font-weight:600;}
  .brand p{margin:2px 0 0;font-size:12.5px;color:var(--text-dim);}
  .status-pill{display:inline-flex;align-items:center;gap:7px;background:rgba(76,195,138,.12);
    color:var(--ok);border:1px solid rgba(76,195,138,.35);padding:6px 12px;border-radius:99px;
    font-size:12.5px;font-weight:600;}
  .status-pill .dot{width:7px;height:7px;border-radius:50%;background:var(--ok);
    box-shadow:0 0 0 3px rgba(76,195,138,.18);}
  main{max-width:1080px;margin:0 auto;padding:clamp(16px,4vw,40px);}
  h2.section-title{font-size:14px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.4px;
    margin:30px 0 12px;}
  h2.section-title:first-child{margin-top:0;}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-bottom:8px;}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;}
  .card h3{margin:0 0 14px;font-size:12.5px;color:var(--text-dim);font-weight:600;}
  .card .row{display:flex;justify-content:space-between;gap:12px;padding:7px 0;
    border-bottom:1px solid rgba(255,255,255,.045);font-size:13.5px;}
  .card .row:last-child{border-bottom:none;}
  .card .row .k{color:var(--text-dim);}
  .card .row .v{font-weight:600;text-align:right;}
  .vm-flag{display:inline-flex;align-items:center;gap:8px;font-size:13.5px;font-weight:700;
    padding:5px 10px;border-radius:7px;margin-bottom:12px;}
  .vm-flag.yes{background:rgba(232,163,61,.14);color:var(--warn);}
  .vm-flag.no{background:rgba(76,195,138,.14);color:var(--ok);}
  table.plain{width:100%;border-collapse:collapse;font-size:13px;}
  table.plain th{text-align:left;font-weight:600;color:var(--text-dim);font-size:11.5px;
    padding:0 10px 8px 0;border-bottom:1px solid var(--line);}
  table.plain td{padding:8px 10px 8px 0;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:top;}
  table.plain tr:last-child td{border-bottom:none;}
  .summary-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:10px;}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px;}
  .stat .num{font-size:24px;font-weight:700;}
  .stat .label{font-size:12px;color:var(--text-dim);margin-top:3px;}
  section.eco{background:var(--panel);border:1px solid var(--line);border-radius:12px;
    margin-bottom:14px;overflow:hidden;}
  .eco-head{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;
    cursor:pointer;user-select:none;gap:12px;}
  .eco-left{display:flex;align-items:center;gap:12px;}
  .eco-icon{width:30px;height:30px;border-radius:8px;display:flex;align-items:center;
    justify-content:center;font-size:12.5px;font-weight:700;flex-shrink:0;color:#0d1117;}
  .eco-title{font-size:14.5px;font-weight:650;}
  .eco-sub{font-size:12px;color:var(--text-dim);margin-top:2px;}
  .eco-badge{font-size:11.5px;font-weight:700;padding:4px 10px;border-radius:99px;
    background:rgba(76,195,138,.14);color:var(--ok);}
  .eco-badge.off{background:rgba(86,96,114,.18);color:var(--off);}
  .chevron{transition:transform .18s ease;color:var(--text-dim);flex-shrink:0;}
  section.eco.collapsed .chevron,.json-panel.collapsed .chevron{transform:rotate(-90deg);}
  .eco-body{padding:0 20px 18px;}
  section.eco.collapsed .eco-body{display:none;}
  section.eco.absent .eco-head{opacity:.55;}
  .runtime-row{display:flex;gap:20px;flex-wrap:wrap;padding:12px 14px;background:var(--panel-2);
    border-radius:8px;margin-bottom:14px;font-size:13px;}
  .runtime-row .k{color:var(--text-dim);margin-right:6px;}
  .kind-tag{font-size:10.5px;font-weight:700;padding:2px 7px;border-radius:5px;
    background:rgba(76,141,255,.14);color:var(--accent);text-transform:uppercase;letter-spacing:.3px;}
  .kind-tag.dev{background:rgba(232,163,61,.14);color:var(--warn);}
  .no-version{color:var(--text-dim);font-style:italic;}
  td.outdated{color:var(--warn);}
  td.uptodate{color:var(--ok);}
  .kind-tag.outdated-tag{background:rgba(232,163,61,.14);color:var(--warn);}
  .empty-note{font-size:13px;color:var(--text-dim);padding:4px 0 2px;}
  .json-panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;
    overflow:hidden;margin-top:10px;}
  .json-head{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;
    border-bottom:1px solid var(--line);cursor:pointer;user-select:none;gap:12px;}
  .json-head h3{margin:0;font-size:13.5px;font-weight:650;}
  .json-actions{display:flex;gap:8px;align-items:center;}
  .copy-btn{background:var(--panel-2);border:1px solid var(--line);color:var(--text);
    font-size:12.5px;padding:7px 12px;border-radius:7px;cursor:pointer;}
  .copy-btn:hover{border-color:var(--accent);}
  .json-body{max-height:480px;overflow:auto;padding:0 18px;transition:max-height .22s ease;}
  .json-panel.collapsed .json-body{max-height:0;padding-top:0;padding-bottom:0;overflow:hidden;}
  pre{margin:0;padding:16px 0 20px;font-size:12.5px;line-height:1.65;color:#C7D0DC;white-space:pre;}
  .tok-key{color:#7FB0FF;}.tok-str{color:#9FDB9A;}.tok-num{color:#E8A33D;}
  .tok-bool{color:#E88AC9;}.tok-null{color:#8B96A5;}
  footer{max-width:1080px;margin:0 auto;padding:8px clamp(16px,4vw,40px) 32px;font-size:12px;color:var(--text-dim);}
  @media (prefers-reduced-motion:reduce){.chevron,.json-body{transition:none;}}
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="brand-mark">SV</div>
    <div><h1>System &amp; VM Analyzer</h1><p id="hostSub">Report</p></div>
  </div>
  <span class="status-pill"><span class="dot"></span>Live scan</span>
</header>
<main>
  <h2 class="section-title">System</h2>
  <div class="grid" id="sysGrid"></div>

  <h2 class="section-title">Application dependencies</h2>
  <div class="summary-row" id="appSummaryRow"></div>
  <div id="ecosystems"></div>

  <h2 class="section-title">Raw JSON</h2>
  <div class="json-panel" id="jsonPanel">
    <div class="json-head" id="jsonToggle" role="button" tabindex="0" aria-expanded="true" aria-controls="jsonBody">
      <div style="display:flex;align-items:center;gap:10px;">
        <svg class="chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M6 9l6 6 6-6"/></svg>
        <h3>Full report JSON</h3>
      </div>
      <div class="json-actions">
        <button class="copy-btn" id="copyBtn" onclick="copyJson(event)">Copy</button>
      </div>
    </div>
    <div class="json-body" id="jsonBody"><pre id="jsonPre"></pre></div>
  </div>
</main>
<footer>Generated locally by system_analyzer.py -- no data leaves this machine.</footer>

<script>
  const report = __REPORT_JSON__;

  const ECO_META = {
    python:{label:"Python",letter:"Py",color:"#FFD43B"},
    node:{label:"Node.js",letter:"Nd",color:"#8CC84B"},
    java:{label:"Java",letter:"Jv",color:"#F08C3A"},
    dotnet:{label:".NET",letter:".N",color:"#A66DDF"},
    ruby:{label:"Ruby",letter:"Rb",color:"#E5584F"},
    php:{label:"PHP",letter:"Ph",color:"#7A86B6"},
    go:{label:"Go",letter:"Go",color:"#4DC5E8"},
  };

  function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}

  function runtimeSummary(name, eco){
    const r = eco.runtime || {};
    const vn = r.version_name ? (" “"+r.version_name+"”") : "";
    if(name==="python") return (r.declared_version || ("interpreter: "+(r.interpreter_running_this_scan||"unknown"))) + vn;
    if(name==="node") return (r.declared_node_version || ("node: "+(r.node_running_this_scan||"unknown"))) + vn;
    if(name==="java") return (r.declared_java_version ? ("Java "+r.declared_java_version) : ("JDK: "+(r.java_running_this_scan||"unknown"))) + vn;
    if(name==="dotnet") return r.declared_target_framework || "unknown target framework";
    if(name==="ruby") return r.declared_ruby_version || "version not declared";
    if(name==="php") return r.declared_php_version || "version not declared";
    if(name==="go") return r.declared_go_version || "version not declared";
    return "";
  }

  function renderSystem(){
    const o=report.os||{}, c=report.cpu||{}, m=report.memory||{}, v=report.virtualization||{}, n=report.network||{};
    document.getElementById('hostSub').textContent = (n.hostname||"host") + " · " + (n.ip||"no ip");
    const vmLine = v.is_vm ? ("Yes - "+(v.hypervisor||"unknown")+" (via "+(v.method||"?")+")") : "No (likely bare metal)";
    const osLine = o.os_release_PRETTY_NAME || o.product_name || ((o.system||"")+" "+(o.release||""));
    const osVersionName = o.version_name || "—";
    const cards = [
      {h:"OS", rows:[["System",osLine],["Version name",osVersionName],["Architecture",o.architecture],["Uptime (s)",o.uptime_seconds]]},
      {h:"CPU", rows:[["Model",c.model],["Logical cores",c.logical_cores],["Physical cores",c.physical_cores]]},
      {h:"Memory", rows:[["Total",m.total_gb+" GB"],["Available",m.available_gb+" GB"],["Used %",m.used_percent]]},
      {h:"Virtualization", rows:[["Is VM", v.is_vm ? "Yes" : "No"],["Hypervisor", v.hypervisor||"-"],["Method", v.method||"-"]]},
      {h:"Network", rows:[["Hostname",n.hostname],["IP",n.ip],["MAC",n.mac||"-"]]},
    ];
    document.getElementById('sysGrid').innerHTML = cards.map(c=>
      `<div class="card"><h3>${esc(c.h)}</h3>${c.rows.map(r=>
        `<div class="row"><span class="k">${esc(r[0])}</span><span class="v">${r[1]!==undefined&&r[1]!==null?esc(r[1]):'-'}</span></div>`).join('')}</div>`
    ).join('');
  }

  function renderAppDeps(){
    const ad = report.application_dependencies || {ecosystems:{}, ecosystems_detected:[], total_libraries_found:0, application_server:{tomcat:{}}};
    const tomcat = (ad.application_server||{}).tomcat || {};
    const stats = [
      {num: (ad.ecosystems_detected||[]).length, label:"Ecosystems detected"},
      {num: ad.total_libraries_found||0, label:"Libraries found"},
      {num: tomcat.present ? (tomcat.version||"yes") : "—", label:"Tomcat"},
    ];
    if(ad.checked_latest_versions){
      let outdated = 0;
      Object.values(ad.ecosystems||{}).forEach(e=>(e.libraries||[]).forEach(l=>{if(l.is_outdated)outdated++;}));
      stats.push({num: outdated, label:"Outdated (vs. latest)"});
    } else {
      stats.push({num: "off", label:"Latest-version check (--check-latest)"});
    }
    document.getElementById('appSummaryRow').innerHTML = stats.map(s=>
      `<div class="stat"><div class="num">${esc(s.num)}</div><div class="label">${esc(s.label)}</div></div>`).join('');

    const order=["python","node","java","dotnet","ruby","php","go"];
    const container = document.getElementById('ecosystems');
    let html = `<div class="empty-note" style="margin-bottom:10px;">Scanned path: <span class="mono">${esc(ad.scanned_path||'-')}</span></div>`;
    order.forEach(name=>{
      const eco = (ad.ecosystems||{})[name];
      if(!eco) return;
      const meta = ECO_META[name];
      const present = !!eco.present;
      const libs = eco.libraries||[];
      const checkedLatest = !!ad.checked_latest_versions;
      const rows = libs.map(l=>{
          const latestCell = !checkedLatest ? '' :
            (l.latest_version
              ? `<td class="mono ${l.is_outdated?'outdated':'uptodate'}">${esc(l.latest_version)}${l.is_outdated?' <span class="kind-tag outdated-tag">newer</span>':''}</td>`
              : `<td class="no-version">unknown</td>`);
          return `<tr><td class="mono">${esc(l.name)}</td>
          <td class="mono">${l.version_spec?esc(l.version_spec):'<span class="no-version">not pinned</span>'}</td>
          <td>${l.version_name?esc(l.version_name):'<span class="no-version">—</span>'}</td>
          ${latestCell}
          <td>${l.kind?`<span class="kind-tag ${l.kind==='dev'?'dev':''}">${esc(l.kind)}</span>`:''}</td></tr>`;
        }).join('');
      const runtimeEntries = Object.entries(eco.runtime||{}).map(([k,v])=>
        `<span><span class="k">${esc(k.replace(/_/g,' '))}:</span> <span class="v mono">${v?esc(v):'—'}</span></span>`).join('');
      html += `<section class="eco ${present?'':'absent collapsed'}">
        <div class="eco-head" role="button" tabindex="0" aria-expanded="${present}">
          <div class="eco-left">
            <div class="eco-icon" style="background:${meta.color}">${meta.letter}</div>
            <div><div class="eco-title">${meta.label}</div>
              <div class="eco-sub">${present?(esc(eco.manifest||'')+' · '+esc(runtimeSummary(name,eco))):'not detected'}</div>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:12px;">
            <span class="eco-badge ${present?'':'off'}">${present?libs.length+' librar'+(libs.length===1?'y':'ies'):'absent'}</span>
            <svg class="chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M6 9l6 6 6-6"/></svg>
          </div>
        </div>
        ${present?`<div class="eco-body"><div class="runtime-row">${runtimeEntries}</div>
          ${libs.length?`<table class="plain"><tr><th>Library</th><th>Version</th><th>Version name</th>${checkedLatest?'<th>Latest</th>':''}<th>Kind</th></tr>${rows}</table>`
            :'<div class="empty-note">No libraries listed in the manifest.</div>'}</div>`:''}
      </section>`;
    });
    container.innerHTML = html;
    container.querySelectorAll('.eco-head').forEach(head=>{
      const section = head.closest('section.eco');
      const toggle = ()=>{const collapsed=section.classList.toggle('collapsed');head.setAttribute('aria-expanded',String(!collapsed));};
      head.addEventListener('click', toggle);
      head.addEventListener('keydown', e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();toggle();}});
    });
  }

  function highlight(json){
    return esc(json)
      .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*")(\s*:)?/g, (m,p1,p2,p3)=> p3 ? '<span class="tok-key">'+p1+'</span>'+p3 : '<span class="tok-str">'+p1+'</span>')
      .replace(/\b(true|false)\b/g,'<span class="tok-bool">$1</span>')
      .replace(/\bnull\b/g,'<span class="tok-null">null</span>')
      .replace(/\b(-?\d+\.?\d*)\b/g,'<span class="tok-num">$1</span>');
  }

  renderSystem();
  renderAppDeps();
  document.getElementById('jsonPre').innerHTML = highlight(JSON.stringify(report,null,2));

  const panel=document.getElementById('jsonPanel'), toggle=document.getElementById('jsonToggle');
  function togglePanel(){const collapsed=panel.classList.toggle('collapsed');toggle.setAttribute('aria-expanded',String(!collapsed));}
  toggle.addEventListener('click', togglePanel);
  toggle.addEventListener('keydown', e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();togglePanel();}});

  function copyJson(e){
    e.stopPropagation();
    const text = JSON.stringify(report,null,2);
    const btn = document.getElementById('copyBtn');
    try{
      navigator.clipboard.writeText(text).then(()=>{const prev=btn.textContent;btn.textContent='Copied';setTimeout(()=>{btn.textContent=prev;},1400);});
    }catch(err){btn.textContent='Copy failed';}
  }
</script>
</body>
</html>
"""


def generate_html_report(data):
    # Escape "</" so a value like a path or library name containing "</script>"
    # can't break out of the <script> block it's embedded in.
    safe_json = json.dumps(data).replace("</", "<\\/")
    return _HTML_TEMPLATE.replace("__REPORT_JSON__", safe_json)


# --------------------------------------------------------------------------
# Output + CLI
# --------------------------------------------------------------------------

def pretty_os(o):
    if not isinstance(o, dict):
        return "unknown"
    base = None
    if o.get("os_release_PRETTY_NAME"):
        base = o["os_release_PRETTY_NAME"]
    elif o.get("product_name"):
        base = " ".join(str(x) for x in (o["product_name"], o.get("product_version")
                                         or o.get("display_version")) if x)
    else:
        base = "%s %s" % (o.get("system"), o.get("release"))
    vn = o.get("version_name")
    return "%s “%s”" % (base, vn) if vn and vn not in base else base


def print_report(data, text):
    o, c, m = data.get("os", {}), data.get("cpu", {}), data.get("memory", {})
    v, n = data.get("virtualization", {}), data.get("network", {})
    ad = data.get("application_dependencies", {})
    vm = "No (likely bare metal)"
    if isinstance(v, dict) and v.get("is_vm"):
        vm = "Yes - %s (via %s)" % (v.get("hypervisor"), v.get("method"))
    print("=" * 60)
    print("System & VM Analyzer v%s" % VERSION)
    print("=" * 60)
    print("Host    : %s (%s)" % (n.get("hostname"), n.get("ip")))
    print("OS      : %s [%s]" % (pretty_os(o), o.get("architecture")))
    print("CPU     : %s (%s logical cores)" % (c.get("model"), c.get("logical_cores")))
    print("Memory  : %s GB total, %s GB available" % (m.get("total_gb"), m.get("available_gb")))
    print("VM      : %s" % vm)
    if isinstance(ad, dict):
        print("App deps: %s (%s path: %s)" %
              (", ".join(ad.get("ecosystems_detected", [])) or "none detected",
               ad.get("total_libraries_found", 0), ad.get("scanned_path")))
    print("=" * 60)
    print(text)


def build_parser():
    ap = argparse.ArgumentParser(description="System & VM Analyzer (local or over SSH), with application dependency scanning")
    ap.add_argument("--host", help="Remote server IP/hostname. Omit to analyze this machine.")
    ap.add_argument("--user", help="SSH username (required with --host)")
    ap.add_argument("--password", help="SSH password (visible in shell history; prefer --key or --ask-pass)")
    ap.add_argument("--ask-pass", action="store_true", help="Prompt for the SSH password securely")
    ap.add_argument("--key", help="Path to SSH private key")
    ap.add_argument("--key-passphrase", help="Passphrase for the private key")
    ap.add_argument("--port", type=int, default=22, help="SSH port (default 22)")
    ap.add_argument("--strict-host-key", action="store_true",
                    help="Refuse hosts not already in known_hosts (default: auto-add)")
    ap.add_argument("--upload", action="store_true",
                    help="POSIX servers: SFTP-upload the script to /tmp, run it, delete it "
                         "(default is to pipe it over stdin, no temp file)")
    ap.add_argument("--timeout", type=int, default=15, help="SSH connect timeout, seconds")
    ap.add_argument("--run-timeout", type=int, default=120, help="Remote run timeout, seconds")
    ap.add_argument("--max-apps", type=int, default=25,
                    help="Max installed applications to list (count is always reported)")
    ap.add_argument("--app-path",
                    help="Directory of a deployed app to scan for runtime + library dependencies "
                         "(evaluated on the server in remote mode). If omitted, a short list of "
                         "common deploy locations is tried automatically.")
    ap.add_argument("--check-latest", action="store_true",
                    help="For each detected library, look up its latest published version "
                         "(PyPI/npm/RubyGems/Packagist/NuGet/Maven) and flag outdated ones. "
                         "Needs internet access -- in remote mode, the SERVER needs it, not "
                         "your machine. Off by default; everything else in this script never "
                         "makes an outbound connection of its own.")
    ap.add_argument("--json", action="store_true", help="Print raw JSON only")
    ap.add_argument("--out", default="report.json",
                    help="Write the JSON report to this file (default: report.json)")
    ap.add_argument("--html", default="report.html",
                    help="Write a self-contained HTML dashboard to this file "
                         "(default: report.html). The same JSON is embedded in it.")
    ap.add_argument("--no-json-file", action="store_true", help="Don't write the JSON file")
    ap.add_argument("--no-html", action="store_true", help="Don't write the HTML file")
    return ap


def _run_with_loading(message, operation, *args):
    if not sys.stderr.isatty():
        return operation(*args)

    stop = threading.Event()
    current_progress = [0]

    def animate():
        frames = "|/-\\"
        index = 0
        while not stop.is_set():
            sys.stderr.write("\r%s %3d%% %s" %
                             (message, current_progress[0], frames[index % len(frames)]))
            sys.stderr.flush()
            index += 1
            stop.wait(0.1)

    def update_progress(percent):
        current_progress[0] = max(0, min(100, percent))

    spinner = threading.Thread(target=animate, daemon=True)
    spinner.start()
    try:
        return operation(*args, progress=update_progress)
    finally:
        stop.set()
        spinner.join()
        sys.stderr.write("\r%s %3d%%\n" % (message, current_progress[0]))
        sys.stderr.flush()


def main():
    args = build_parser().parse_args()
    if args.host:
        if args.ask_pass and args.user:
            args.password = getpass.getpass("SSH password for %s@%s: " % (args.user, args.host))
            args.ask_pass = False
        data = _run_with_loading("Loading system information", run_remote, args)
    else:
        data = _run_with_loading("Loading system information", gather_all,
                                 args.max_apps, args.app_path, args.check_latest)
    text = json.dumps(data, indent=2)

    if not args.no_json_file and args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
        sys.stderr.write("JSON report written to %s\n" % os.path.abspath(args.out))

    if not args.no_html and args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(generate_html_report(data))
        sys.stderr.write("HTML report written to %s\n" % os.path.abspath(args.html))

    if args.json:
        print(text)
    else:
        print_report(data, text)


if __name__ == "__main__":
    main()
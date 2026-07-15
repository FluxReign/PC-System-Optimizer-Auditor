from __future__ import annotations

import csv
import html
import json
import os
import platform
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import psutil
import requests
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "PC System Optimizer Auditor"
APP_VERSION = "1.0.0"
TIMEOUT = 20


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    detail: str
    recommendation: str
    gain: str = "Context dependent"
    risk: str = "Low"


def run_command(command: list[str], timeout: int = 30) -> str:
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        creationflags=flags,
    )
    return (result.stdout or result.stderr).strip()


def powershell_json(script: str) -> Any:
    output = run_command([
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command", f"$ProgressPreference='SilentlyContinue'; {script} | ConvertTo-Json -Depth 5"
    ], timeout=45)
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"raw": output}


def normalize_list(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    return value if isinstance(value, list) else [{"value": value}]


def collect_system() -> dict[str, Any]:
    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "computer_name": platform.node(),
        "windows": platform.platform(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(timespec="seconds"),
        "uptime_hours": round((time.time() - psutil.boot_time()) / 3600, 2),
        "cpu_usage_percent": psutil.cpu_percent(interval=1),
        "memory": dict(psutil.virtual_memory()._asdict()),
    }


def collect_cpu() -> list[dict[str, Any]]:
    return normalize_list(powershell_json(
        "Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,"
        "NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,CurrentClockSpeed,"
        "L2CacheSize,L3CacheSize,VirtualizationFirmwareEnabled,SecondLevelAddressTranslationExtensions"
    ))


def collect_board_bios() -> dict[str, Any]:
    return {
        "baseboard": normalize_list(powershell_json(
            "Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,Version,SerialNumber"
        )),
        "bios": normalize_list(powershell_json(
            "Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,"
            "ReleaseDate,SerialNumber"
        )),
    }


def collect_ram() -> list[dict[str, Any]]:
    return normalize_list(powershell_json(
        "Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer,PartNumber,"
        "Capacity,Speed,ConfiguredClockSpeed,ConfiguredVoltage,DeviceLocator,BankLabel"
    ))


def collect_gpu() -> list[dict[str, Any]]:
    return normalize_list(powershell_json(
        "Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM,"
        "DriverVersion,DriverDate,VideoProcessor,CurrentHorizontalResolution,"
        "CurrentVerticalResolution,CurrentRefreshRate"
    ))


def collect_storage() -> dict[str, Any]:
    disks = normalize_list(powershell_json(
        "Get-PhysicalDisk | Select-Object FriendlyName,Manufacturer,Model,MediaType,"
        "BusType,Size,HealthStatus,OperationalStatus,FirmwareVersion"
    ))
    volumes = normalize_list(powershell_json(
        "Get-Volume | Select-Object DriveLetter,FileSystemLabel,FileSystem,"
        "HealthStatus,Size,SizeRemaining"
    ))
    trim = run_command(["fsutil", "behavior", "query", "DisableDeleteNotify"])
    return {"physical_disks": disks, "volumes": volumes, "trim_status": trim}


def collect_network() -> dict[str, Any]:
    adapters = normalize_list(powershell_json(
        "Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name,"
        "InterfaceDescription,LinkSpeed,MacAddress,DriverVersion"
    ))
    tcp = run_command(["netsh", "interface", "tcp", "show", "global"])
    return {"adapters": adapters, "tcp_global": tcp}


def collect_windows_security() -> dict[str, Any]:
    secure_boot = run_command([
        "powershell.exe", "-NoProfile", "-Command",
        "try { Confirm-SecureBootUEFI } catch { 'Unavailable: ' + $_.Exception.Message }"
    ])
    defender = powershell_json(
        "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
        "BehaviorMonitorEnabled,IoavProtectionEnabled,AntivirusSignatureLastUpdated"
    )
    bitlocker = run_command(["manage-bde", "-status"])
    return {"secure_boot": secure_boot, "defender": defender, "bitlocker": bitlocker}


def collect_power() -> dict[str, Any]:
    return {
        "active_plan": run_command(["powercfg", "/getactivescheme"]),
        "sleep_states": run_command(["powercfg", "/a"]),
    }


def collect_startup() -> list[dict[str, Any]]:
    return normalize_list(powershell_json(
        "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User"
    ))


def collect_drivers() -> list[dict[str, Any]]:
    return normalize_list(powershell_json(
        "Get-CimInstance Win32_PnPSignedDriver | Where-Object DeviceName | "
        "Select-Object DeviceName,Manufacturer,DriverVersion,DriverDate,IsSigned"
    ))


def collect_hotfixes() -> list[dict[str, Any]]:
    return normalize_list(powershell_json(
        "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 25 "
        "HotFixID,Description,InstalledOn"
    ))


def find_bitcoin_cli() -> Optional[Path]:
    candidates = [
        shutil.which("bitcoin-cli"),
        r"C:\Program Files\Bitcoin\daemon\bitcoin-cli.exe",
        r"C:\Program Files\Bitcoin\bitcoin-cli.exe",
    ]
    for value in candidates:
        if value and Path(value).exists():
            return Path(value)
    return None


def collect_bitcoin() -> dict[str, Any]:
    cli = find_bitcoin_cli()
    datadir = Path(os.environ.get("APPDATA", "")) / "Bitcoin"
    result: dict[str, Any] = {"installed": bool(cli), "datadir": str(datadir)}
    if not cli:
        return result

    def rpc(method: str) -> Any:
        output = run_command([str(cli), f"-datadir={datadir}", method])
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return {"raw": output}

    result["blockchain"] = rpc("getblockchaininfo")
    result["network"] = rpc("getnetworkinfo")
    conf = datadir / "bitcoin.conf"
    if conf.exists():
        result["config"] = conf.read_text(encoding="utf-8", errors="ignore")
    return result


def collect_all(progress=None) -> dict[str, Any]:
    collectors = [
        ("System", collect_system),
        ("CPU", collect_cpu),
        ("Motherboard and BIOS", collect_board_bios),
        ("Memory", collect_ram),
        ("GPU", collect_gpu),
        ("Storage", collect_storage),
        ("Network", collect_network),
        ("Power", collect_power),
        ("Security", collect_windows_security),
        ("Startup", collect_startup),
        ("Drivers", collect_drivers),
        ("Windows updates", collect_hotfixes),
        ("Bitcoin Core", collect_bitcoin),
    ]
    data: dict[str, Any] = {}
    for index, (name, func) in enumerate(collectors, 1):
        if progress:
            progress(name, index, len(collectors))
        try:
            data[name] = func()
        except Exception as exc:
            data[name] = {"error": str(exc)}
    return data


def first(items: Any) -> dict[str, Any]:
    values = normalize_list(items)
    return values[0] if values else {}


def gb(value: Any) -> float:
    try:
        return float(value) / (1024 ** 3)
    except (TypeError, ValueError):
        return 0.0


def analyze(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    system = data.get("System", {})
    memory = system.get("memory", {})
    ram_total = gb(memory.get("total"))
    ram_available = gb(memory.get("available"))

    cpu = first(data.get("CPU"))
    if cpu:
        if not cpu.get("VirtualizationFirmwareEnabled", False):
            findings.append(Finding(
                "CPU/BIOS", "Info", "CPU virtualization appears disabled",
                "VT-x/AMD-V is not reported as enabled in firmware.",
                "Enable virtualization only if you use Hyper-V, virtual machines, WSL2, Docker, or Android emulators.",
                "Feature enablement", "Low"
            ))

    ram_modules = normalize_list(data.get("Memory"))
    configured = [int(x.get("ConfiguredClockSpeed") or 0) for x in ram_modules]
    rated = [int(x.get("Speed") or 0) for x in ram_modules]
    if configured and rated and min(configured) and max(rated) > min(configured):
        findings.append(Finding(
            "Memory", "Medium", "Memory may be running below its reported module speed",
            f"Configured speed: {min(configured)} MT/s; module-reported speed: up to {max(rated)} MT/s.",
            "Check BIOS XMP/EXPO settings. Stability-test after enabling a memory profile; do not assume the highest profile is stable.",
            "Often 2–15% in memory-sensitive workloads", "Medium"
        ))

    if ram_total and ram_total <= 8:
        findings.append(Finding(
            "Memory", "High", "Low installed memory for a modern multitasking build",
            f"Detected approximately {ram_total:.1f} GB RAM with {ram_available:.1f} GB currently available.",
            "For gaming plus browsers, development, content creation, or Bitcoin Core, 16 GB is a practical floor and 32 GB provides better headroom.",
            "Fewer stalls and less paging", "Low"
        ))

    storage = data.get("Storage", {})
    disks = normalize_list(storage.get("physical_disks"))
    if any(str(d.get("MediaType", "")).lower() == "hdd" for d in disks):
        findings.append(Finding(
            "Storage", "High", "Mechanical hard drive detected",
            "An HDD has much higher random-access latency than an SSD.",
            "Keep Windows, applications, active projects, and Bitcoin Core chainstate on an internal SSD/NVMe. Use HDDs for archives and backups.",
            "Major responsiveness and I/O improvement", "Low"
        ))
    for volume in normalize_list(storage.get("volumes")):
        size = float(volume.get("Size") or 0)
        free = float(volume.get("SizeRemaining") or 0)
        if size and free / size < 0.12:
            findings.append(Finding(
                "Storage", "High", f"Drive {volume.get('DriveLetter', '?')}: is nearly full",
                f"Only {free/size*100:.1f}% free space remains.",
                "Free at least 15–20% on SSDs used for Windows, pagefile, games, or Bitcoin Core.",
                "Prevents slowdowns and failed updates", "Low"
            ))

    power = str(data.get("Power", {}).get("active_plan", ""))
    if "balanced" in power.lower():
        findings.append(Finding(
            "Power", "Info", "Balanced power plan is active",
            "Balanced mode is normally the correct default and preserves idle efficiency.",
            "Use High Performance only for troubleshooting sustained clock drops or dedicated heavy workloads. Avoid blanket timer/HPET tweaks.",
            "Usually small", "Low"
        ))

    startup = normalize_list(data.get("Startup"))
    if len(startup) > 15:
        findings.append(Finding(
            "Windows", "Medium", "Heavy startup-program load",
            f"{len(startup)} startup entries were detected.",
            "Disable nonessential launchers, updaters, RGB utilities, and tray applications one at a time through Task Manager.",
            "Faster login and lower background load", "Low"
        ))

    security = data.get("Security", {})
    defender = security.get("defender") or {}
    if isinstance(defender, dict) and defender.get("RealTimeProtectionEnabled") is False:
        findings.append(Finding(
            "Security", "High", "Microsoft Defender real-time protection is disabled",
            "The machine may not be receiving normal on-access malware scanning.",
            "Re-enable Defender unless another reputable real-time security product is installed and active.",
            "Security improvement", "Low"
        ))

    bitcoin = data.get("Bitcoin Core", {})
    chain = bitcoin.get("blockchain") if isinstance(bitcoin, dict) else None
    if isinstance(chain, dict) and chain.get("initialblockdownload"):
        conf = str(bitcoin.get("config", ""))
        if "txindex=1" in conf:
            findings.append(Finding(
                "Bitcoin Core", "Medium", "Bitcoin transaction index enabled during IBD",
                "txindex adds extra indexing and storage work.",
                "Keep txindex=0 unless your application requires arbitrary historical transaction lookup.",
                "Potentially shorter initial sync", "Low"
            ))
        if not re.search(r"(?m)^\s*dbcache\s*=", conf):
            suggested = 4096 if ram_total >= 16 else 2048
            findings.append(Finding(
                "Bitcoin Core", "Medium", "Bitcoin Core dbcache is not explicitly tuned",
                "Initial block download benefits from enough database cache, provided Windows is not forced to page.",
                f"Consider dbcache={suggested} during IBD, then reassess against available RAM and other workloads.",
                "Often meaningful on storage-limited syncs", "Low"
            ))

    bios = first(data.get("Motherboard and BIOS", {}).get("bios"))
    board = first(data.get("Motherboard and BIOS", {}).get("baseboard"))
    if board or bios:
        findings.append(Finding(
            "Firmware", "Research", "Verify BIOS and chipset packages with the board manufacturer",
            f"Board: {board.get('Manufacturer','')} {board.get('Product','')}; BIOS: {bios.get('SMBIOSBIOSVersion','')}.",
            "Use the exact motherboard support page. Read release notes before updating; do not flash solely because a newer version exists.",
            "Stability/security dependent", "Medium"
        ))

    if not findings:
        findings.append(Finding(
            "Overall", "Good", "No obvious high-impact issue detected",
            "The collected snapshot does not show a clear universal bottleneck.",
            "Benchmark the workload you actually care about and compare temperatures, clocks, utilization, frametimes, and storage latency under load.",
            "Workload dependent", "Low"
        ))
    return findings


def research_links(data: dict[str, Any]) -> list[tuple[str, str]]:
    cpu = first(data.get("CPU")).get("Name", "")
    gpu = first(data.get("GPU")).get("Name", "")
    board = first(data.get("Motherboard and BIOS", {}).get("baseboard"))
    bios = first(data.get("Motherboard and BIOS", {}).get("bios"))
    disks = normalize_list(data.get("Storage", {}).get("physical_disks"))

    queries = []
    if cpu:
        queries += [
            ("CPU specifications", f"{cpu} official specifications"),
            ("CPU stability and firmware", f"{cpu} official stability microcode guidance"),
        ]
    if gpu:
        queries += [
            ("GPU driver page", f"{gpu} official driver download"),
            ("GPU specifications", f"{gpu} official specifications"),
        ]
    if board:
        model = f"{board.get('Manufacturer','')} {board.get('Product','')}".strip()
        queries += [
            ("Motherboard support page", f"{model} official support BIOS"),
            ("Motherboard memory QVL", f"{model} official memory QVL"),
        ]
    if bios:
        queries.append(("BIOS version research", f"{board.get('Product','')} BIOS {bios.get('SMBIOSBIOSVersion','')}"))
    for d in disks[:4]:
        model = str(d.get("Model") or d.get("FriendlyName") or "").strip()
        if model:
            queries.append((f"{model} firmware", f"{model} official firmware support"))

    links = []
    for label, query in queries:
        url = "https://www.google.com/search?q=" + urllib.parse.quote(query)
        links.append((label, url))
    return links


def esc(value: Any) -> str:
    return html.escape(str(value))


def table_from_records(records: Any) -> str:
    rows = normalize_list(records)
    if not rows:
        return "<p>No data returned.</p>"
    keys = []
    for row in rows:
        for key in row:
            if key not in keys:
                keys.append(key)
    head = "".join(f"<th>{esc(k)}</th>" for k in keys)
    body = ""
    for row in rows:
        body += "<tr>" + "".join(f"<td>{esc(row.get(k,''))}</td>" for k in keys) + "</tr>"
    return f"<div class='scroll'><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def generate_report(data: dict[str, Any], findings: list[Finding], output: Path) -> None:
    severity_order = {"High": 0, "Medium": 1, "Research": 2, "Info": 3, "Good": 4}
    findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 99))
    cards = ""
    for f in findings:
        cards += f"""
        <article class="finding {esc(f.severity.lower())}">
          <div class="tag">{esc(f.severity)} · {esc(f.category)}</div>
          <h3>{esc(f.title)}</h3>
          <p>{esc(f.detail)}</p>
          <p><strong>Tweak:</strong> {esc(f.recommendation)}</p>
          <p><strong>Expected effect:</strong> {esc(f.gain)} · <strong>Risk:</strong> {esc(f.risk)}</p>
        </article>"""

    links = "".join(
        f'<li><a href="{esc(url)}">{esc(label)}</a></li>'
        for label, url in research_links(data)
    )

    sections = ""
    for key, value in data.items():
        if isinstance(value, list):
            rendered = table_from_records(value)
        elif isinstance(value, dict):
            rendered = ""
            for subkey, subvalue in value.items():
                rendered += f"<h4>{esc(subkey)}</h4>"
                if isinstance(subvalue, (list, dict)):
                    rendered += table_from_records(subvalue)
                else:
                    rendered += f"<pre>{esc(subvalue)}</pre>"
        else:
            rendered = f"<pre>{esc(value)}</pre>"
        sections += f"<section><h2>{esc(key)}</h2>{rendered}</section>"

    doc = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>{APP_NAME} Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#101318;color:#e9edf2;margin:0}}
main{{max-width:1200px;margin:auto;padding:28px}}
h1{{font-size:34px;margin-bottom:4px}} h2{{border-bottom:1px solid #39404a;padding-bottom:8px}}
.muted{{color:#aeb7c2}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}}
.finding,section{{background:#181d24;border:1px solid #303844;border-radius:12px;padding:18px;margin:16px 0}}
.finding.high{{border-left:5px solid #ef5350}} .finding.medium{{border-left:5px solid #ffb74d}}
.finding.research{{border-left:5px solid #42a5f5}} .finding.good{{border-left:5px solid #66bb6a}}
.tag{{font-size:12px;text-transform:uppercase;color:#aeb7c2}}
table{{border-collapse:collapse;width:100%;font-size:13px}} th,td{{border:1px solid #39404a;padding:7px;text-align:left}}
th{{background:#222934}} .scroll{{overflow:auto}} pre{{white-space:pre-wrap;word-break:break-word}}
a{{color:#73b7ff}} code{{background:#262d37;padding:2px 5px;border-radius:4px}}
</style></head>
<body><main>
<h1>{APP_NAME}</h1>
<p class="muted">Version {APP_VERSION} · Generated {esc(datetime.now().isoformat(timespec="seconds"))}</p>
<p>This report separates detected facts from recommendations. Online links are research launch points; verify model, revision, OS version, and release notes before changing firmware or drivers.</p>
<h2>Optimization findings</h2><div class="grid">{cards}</div>
<h2>Online research references</h2><ul>{links}</ul>
<h2>Raw audit</h2>{sections}
</main></body></html>"""
    output.write_text(doc, encoding="utf-8")


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("920x680")
        self.minsize(760, 560)
        self.result_queue: queue.Queue = queue.Queue()
        self.data: Optional[dict[str, Any]] = None
        self.findings: list[Finding] = []

        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")

        frame = ttk.Frame(self, padding=18)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text=APP_NAME, font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(
            frame,
            text="Local Windows hardware audit + clean optimization report + online research references",
        ).pack(anchor="w", pady=(0, 14))

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x")
        self.scan_button = ttk.Button(buttons, text="Run Full Audit", command=self.start_scan)
        self.scan_button.pack(side="left")
        self.save_button = ttk.Button(buttons, text="Save HTML Report", command=self.save_report, state="disabled")
        self.save_button.pack(side="left", padx=8)

        self.progress = ttk.Progressbar(frame, mode="determinate", maximum=13)
        self.progress.pack(fill="x", pady=14)
        self.status = ttk.Label(frame, text="Ready.")
        self.status.pack(anchor="w")

        self.text = tk.Text(frame, wrap="word", font=("Consolas", 10))
        self.text.pack(fill="both", expand=True, pady=(10, 0))
        self.text.insert("end", "Run the audit as a normal user. Some security and firmware fields may require Administrator privileges.\n")
        self.after(200, self.poll_queue)

    def start_scan(self) -> None:
        self.scan_button.configure(state="disabled")
        self.save_button.configure(state="disabled")
        self.progress["value"] = 0
        self.text.delete("1.0", "end")
        threading.Thread(target=self.worker, daemon=True).start()

    def worker(self) -> None:
        def update(name: str, index: int, total: int) -> None:
            self.result_queue.put(("progress", name, index, total))
        data = collect_all(update)
        findings = analyze(data)
        self.result_queue.put(("done", data, findings))

    def poll_queue(self) -> None:
        try:
            while True:
                item = self.result_queue.get_nowait()
                if item[0] == "progress":
                    _, name, index, total = item
                    self.progress["maximum"] = total
                    self.progress["value"] = index
                    self.status.configure(text=f"Scanning: {name} ({index}/{total})")
                    self.text.insert("end", f"[{index}/{total}] {name}\n")
                    self.text.see("end")
                elif item[0] == "done":
                    _, self.data, self.findings = item
                    self.status.configure(text="Audit complete.")
                    self.text.insert("end", "\nFINDINGS\n" + "=" * 70 + "\n")
                    for finding in self.findings:
                        self.text.insert(
                            "end",
                            f"\n[{finding.severity}] {finding.title}\n"
                            f"{finding.detail}\nTweak: {finding.recommendation}\n"
                            f"Effect: {finding.gain} | Risk: {finding.risk}\n"
                        )
                    self.scan_button.configure(state="normal")
                    self.save_button.configure(state="normal")
        except queue.Empty:
            pass
        self.after(200, self.poll_queue)

    def save_report(self) -> None:
        if not self.data:
            return
        default = f"PC-Audit-{platform.node()}-{datetime.now():%Y%m%d-%H%M}.html"
        filename = filedialog.asksaveasfilename(
            title="Save audit report",
            defaultextension=".html",
            initialfile=default,
            filetypes=[("HTML report", "*.html")],
        )
        if not filename:
            return
        path = Path(filename)
        generate_report(self.data, self.findings, path)
        if messagebox.askyesno("Report saved", f"Saved:\n{path}\n\nOpen it now?"):
            webbrowser.open(path.as_uri())


if __name__ == "__main__":
    if os.name != "nt":
        print("This application is designed for Windows.")
        raise SystemExit(1)
    App().mainloop()

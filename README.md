# PC System Optimizer Auditor

A Windows desktop audit tool that collects hardware and operating-system facts, checks common bottlenecks, detects Bitcoin Core when installed, and generates a readable HTML optimization report.

## Build the EXE completely online

GitHub Actions is the recommended online build method because PyInstaller must build a Windows executable on Windows.

1. Create a new GitHub repository.
2. Upload all files and folders from this project, including `.github/workflows/build-windows.yml`.
3. Open the repository's **Actions** tab.
4. Select **Build Windows EXE**.
5. Select **Run workflow**.
6. After the workflow finishes, open that run.
7. Download the `PC-System-Optimizer-Auditor-Windows` artifact.
8. Extract the ZIP to obtain `PC-System-Optimizer-Auditor.exe`.

## Local source run

```powershell
py -m pip install -r requirements.txt
py .\pc_system_optimizer.py
```

## Local EXE build

```powershell
pyinstaller --noconfirm --clean --onefile --windowed --name PC-System-Optimizer-Auditor pc_system_optimizer.py
```

The executable appears under `dist`.

## Important limitations

- This is an audit and report tool; it intentionally does not apply risky registry, BIOS, driver, voltage, timer, or bootloader tweaks.
- Some readings require Administrator privileges.
- WMI/CIM does not expose every temperature, fan, XMP, PCIe-link, PSU, or memory-timing field. Vendor tools or LibreHardwareMonitor integration would be needed for deeper telemetry.
- Online references are model-specific research links. Always verify the exact board revision and release notes before flashing firmware.

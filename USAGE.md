# 🔒 Enhanced PenTest Automation Toolkit

## ✨ New Features

### 📊 **Professional Report Generation**
- **Target-specific files**: `target_timestamp_report.json` and `target_timestamp_summary.md`
- **Formatted summaries**: Professional markdown reports with emojis and structured findings
- **No more overwriting**: Each scan creates unique timestamped files

### 🖥️ **Dual Interface Options**

#### **CLI Version (`pentest-cli.exe`)**
```powershell
.\pentest-cli.exe [target]
```
- Interactive menu-driven interface
- Choose specific modules or full workflow
- Enhanced results display

#### **GUI Version (`pentest-gui.exe`)**
```powershell
.\pentest-gui.exe
```
- Windows native GUI with buttons and text areas
- Real-time results display
- Double-click reports to open in default editor
- Visual scan progress and findings

## 🚀 **Quick Start**

### Build Both Versions
```powershell
# CLI version
gcc -std=c11 -Wall -Wextra -O2 -Iinclude src/engine.c src/ruleset.c src/report.c src/main.c -o pentest-cli.exe

# GUI version  
gcc -std=c11 -Wall -Wextra -O2 -Iinclude src/engine.c src/ruleset.c src/report.c src/gui.c -o pentest-gui.exe -lgdi32 -luser32 -lkernel32 -lshell32
```

### Run Tests
```powershell
# Automated testing
.\test_targets.bat

# Manual CLI testing
.\pentest-cli.exe example.com

# GUI testing
.\pentest-gui.exe
```

## 📋 **Sample Report Output**

```markdown
# 📊 Penetration Test Results Summary

**Target:** httpbin.org  
**Scan Time:** 20250902_014737  
**Total Findings:** 4

## 🔍 Reconnaissance Results (Module 0)
### DNS Lookup
- **IPv4:** `93.184.216.34`
- **IPv6:** `2606:2800:220:1:248:1893:25c8:1946`

### Port Scan
- **22/tcp open ssh**
- **80/tcp open http**

## 🛡️ Vulnerability Assessment (Module 1)
The toolkit detected **2 security findings**:

### 🟢 RULE-0004 - Finding #1
- **Finding:** `Server: nginx` header detected
- **Severity:** 1 (Low)
- **Impact:** Low risk - banner information leakage

### 🟠 RULE-0005 - Finding #2
- **Finding:** `X-Powered-By: Express` header detected
- **Severity:** 3 (Medium)  
- **Impact:** Potential security risk - information disclosure

## 🎯 Key Insights
- Target has 2 reconnaissance data points
- 2 potential security issues identified
- Server is revealing technology stack information
- Recommend header hardening and banner suppression
```

## 📁 **File Organization**

```
reports/
├── httpbin.org_20250902_014737_report.json    # Raw JSON data
├── httpbin.org_20250902_014737_summary.md     # Formatted summary  
├── example.com_20250902_014802_report.json
└── example.com_20250902_014802_summary.md
```

## 🎯 **Usage Examples**

### CLI Workflow
1. Run `.\pentest-cli.exe`
2. Enter target or use default
3. Select option (1=recon, 2=vuln, 3=full)
4. View results in console
5. Check `reports/` folder for detailed summaries

### GUI Workflow  
1. Run `.\pentest-gui.exe`
2. Enter target in text box
3. Click desired scan button (🔍🛡️⚡)
4. View results in text area
5. Double-click reports in list to open files

## 🔧 **Safe Testing Targets**
- `localhost` / `127.0.0.1`
- `example.com` 
- `httpbin.org`
- `jsonplaceholder.typicode.com`

**Remember**: Only test systems you own or have explicit permission to test!

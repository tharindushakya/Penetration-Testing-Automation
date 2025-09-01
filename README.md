# SecureScan Pro - Open Source Penetration Testing Toolkit

![SecureScan Logo](assets/icon-16x16.svg)

A comprehensive, portable penetration testing toolkit with automated reconnaissance, vulnerability assessment, and secure reporting capabilities.

## Features

### 🎯 **Core Modules**
- **Reconnaissance**: Port scanning, service enumeration, DNS lookup
- **Vulnerability Assessment**: Security rule-based scanning and analysis  
- **Pattern Analysis**: Rule-based vulnerability detection with MITRE ATT&CK mapping
- **Secure Reporting**: Ghost mode (memory-only) or file-based reports

### 🛡️ **Security Features**
- **Ghost Mode**: No file artifacts left on target systems (default)
- **Portable Execution**: Runs from USB without installation
- **Input Validation**: Protection against command injection
- **Memory Security**: Secure allocation with automatic cleanup
- **Anti-Forensics**: Complete trace elimination

### 📊 **Reporting Features**
- Target-specific timestamped reports
- Rule-based analysis with severity scoring
- Executive summaries with risk ratings
- JSON and Markdown output formats
- In-memory reports (ghost mode) or file output

## Installation

### Prerequisites
- GCC compiler (C11 standard)
- Windows environment (for GUI)
- Make utility (optional)

### Build Instructions

#### Using Make
```bash
# Build both CLI and GUI versions
make all

# Build CLI only
make cli

# Build GUI only
make gui
```

#### Manual Compilation
```bash
# CLI Version
gcc -std=c11 -Wall -Wextra -O2 -Iinclude src/engine.c src/ruleset.c src/report.c src/ai_detector.c src/main.c -o SecureScan-CLI.exe -lm

# GUI Version (Windows)
gcc -std=c11 -Wall -Wextra -O2 -Iinclude src/engine.c src/ruleset.c src/report.c src/ai_detector.c src/gui.c -o SecureScan-Pro.exe -lgdi32 -luser32 -lkernel32 -lshell32 -lm
```

## Usage

### Command Line Interface (CLI)
```bash
# Interactive mode
./SecureScan-CLI.exe

# Direct target scan
./SecureScan-CLI.exe example.com

# Specific module
echo "2" | ./SecureScan-CLI.exe example.com  # Vulnerability assessment only
```

### Graphical User Interface (GUI)
```bash
# Launch GUI
./SecureScan-Pro.exe
```

The GUI provides:
- Clean, professional interface
- Real-time scan progress
- Result visualization
- Export capabilities

## Project Structure
```
penetration-testing-automation/
├── src/
│   ├── engine.c          # Core orchestration engine
│   ├── ai_detector.c     # AI/ML detection algorithms
│   ├── main.c           # CLI interface
│   ├── gui.c            # Windows GUI interface
│   ├── report.c         # Reporting system
│   └── ruleset.c        # Security rulesets
├── include/
│   ├── engine.h         # Core engine interface
│   ├── ai_detector.h    # AI detection interface
│   ├── report.h         # Reporting interface
│   └── ruleset.h        # Ruleset interface
├── assets/
│   ├── icon-16x16.svg   # Application icon (16x16)
│   └── logo.svg         # Project logo
├── reports/             # Generated reports directory
├── Makefile            # Build configuration
└── README.md           # This file
```

## Sample Reports

Reports are generated in the `reports/` directory with the following structure:
- **JSON Report**: `example.com_20241226_143052.json`
- **Summary**: `example.com_20241226_143052_summary.md`

Each report includes:
- Reconnaissance results
- Vulnerability findings  
- Rule-based analysis with severity scoring
- Risk assessment and recommendations

## Security Analysis

The toolkit uses rule-based vulnerability detection:

1. **Rule Engine**: Pattern matching against known vulnerability signatures
2. **CVE Database**: Cross-reference findings with known vulnerabilities  
3. **MITRE ATT&CK**: Map findings to attack techniques and tactics
4. **Severity Scoring**: Risk-based classification of security issues

## Contributing

This project follows best practices for penetration testing tools:
- **Ethical Use Only**: For authorized testing and security research
- **Open Source**: Full transparency and community contributions welcome
- **Modular Design**: Easy to extend with new detection rules
- **Professional Standards**: Clean code, comprehensive documentation

## License

This project is open source and intended for educational and authorized security testing purposes only.

## Executables

- **SecureScan-CLI.exe**: Command-line interface for automated scripting
- **SecureScan-Pro.exe**: Professional GUI for interactive analysis

## Branches
- `main`: stable releases
- `dev`: active development


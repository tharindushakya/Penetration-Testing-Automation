# SecureScan Toolkit

![SecureScan Logo](assets/icon-16x16.svg)

A comprehensive penetration testing toolkit with AI-powered vulnerability detection, automated reconnaissance, and professional reporting capabilities.

## Features

### 🎯 **Core Modules**
- **Reconnaissance**: Port scanning, service enumeration, subdomain discovery
- **Vulnerability Assessment**: CVE scanning, security checks, configuration analysis
- **AI-Powered Detection**: Machine learning models for advanced threat identification
- **Professional Reporting**: JSON reports, markdown summaries, and executive dashboards

### 🤖 **AI/ML Capabilities**
- **VulnClassifier-v2.1**: Neural network-based vulnerability classification
- **AnomalyDetector-v1.3**: Behavioral pattern analysis for anomaly detection
- **ThreatPredictor-v3.0**: Risk assessment and threat scoring algorithms
- **Fuzzy Pattern Matching**: Advanced heuristic analysis for zero-day detection

### 📊 **Reporting Features**
- Target-specific timestamped reports
- AI analysis sections with confidence scores
- Executive summaries with risk ratings
- JSON and Markdown output formats

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
- AI analysis with confidence scores
- Risk assessment and recommendations

## AI Detection Models

The toolkit includes sophisticated ML algorithms:

1. **Neural Network Classifier**: 7-layer deep learning model for vulnerability pattern recognition
2. **Bayesian Threat Assessment**: Statistical analysis for threat probability calculation
3. **Fuzzy Logic Engine**: Heuristic analysis for unknown attack patterns
4. **Anomaly Detection**: Behavioral analysis for identifying suspicious activities

## Contributing

This project follows best practices for penetration testing tools:
- **Ethical Use Only**: For authorized testing and security research
- **Modular Design**: Easy to extend with new detection modules
- **Professional Standards**: Clean code, comprehensive documentation

## License

This project is intended for educational and authorized security testing purposes only.

## Executables

- **SecureScan-CLI.exe**: Command-line interface for automated scripting
- **SecureScan-Pro.exe**: Professional GUI for interactive analysis

## Branches
- `main`: stable releases
- `dev`: active development


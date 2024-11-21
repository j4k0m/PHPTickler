# PHPTickler - PHP Security Scanner

PHPTickler is a static analysis tool for scanning PHP codebases for common vulnerabilities, including:

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Path Traversal
- Remote Code Execution (RCE)

This tool aims to enhance the security of PHP applications by detecting and reporting insecure code patterns and configurations.

---

# Features

- Scans for vulnerabilities like SQLi, XSS, Path Traversal, and RCE.
- Supports customizable scanning rules and exclusions.
- Generates detailed reports in HTML, JSON, or XML formats.
- Multi-threaded scanning for improved performance.
---

# Installation
## Requirements

- Python 3.8 or higher
- Dependencies listed in requirements.txt

## Installation Steps

1. Clone the repository:

```bash
git clone https://github.com/j4k0m/PHPTickler.git
cd PHPTickler
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Usage

### Basic Usage
Scan a PHP project directory:
```bash
python phptickler.py -d /path/to/your/project
```

### Advanced Options
- Exclude specific directories:
  ```bash
  python phptickler.py -d /path/to/project --exclude path1 path2
  ```
- Generate a report in JSON format:
  ```bash
  python phptickler.py -d /path/to/project --format json
  ```
- Adjust the verbosity level:
  ```bash
  python phptickler.py -d /path/to/project -v 2
  ```

---

# Output

### Reports
PHPTickler generates reports in the selected format:
- **HTML**: A user-friendly report with highlights and remediation advice.
- **JSON**: Structured data for integration with CI/CD pipelines.
- **XML**: Machine-readable format for security tools.

### Example
Upon scanning, a report is generated:
```
vulnerability_report.html
```
Open this file in your browser to view detailed results.
---

# License

This project is licensed under the MIT License. See the `LICENSE` file for details.

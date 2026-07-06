# Zero-Trust Secret Scanner

A Python tool that finds hidden secrets (like passwords and API keys) in your code before hackers do.

## Quick Start

### 1. Clone the repository

Open your terminal and run:

```bash
git clone https://github.com/Oluwashina04/zero-trust-scanner.git
cd zero-trust-scanner
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the scanner

```bash
python main.py ./test_repo
```

## Usage Examples

### Basic Scan

```bash
python main.py ./your-folder-name
```

### Verbose Mode (See everything happening)

```bash
python main.py ./your-folder-name --verbose
```

### GitHub SARIF Report

```bash
python main.py ./your-folder-name --format sarif --output ./report.sarif
```

### Adjust Sensitivity

```bash
python main.py ./your-folder-name --entropy-threshold 4.0 --min-length 15
```

## Options

| Option | What it does |
|--------|--------------|
| `--format` | Choose output: `json` (default) or `sarif` (for GitHub) |
| `--output` | Where to save the report (e.g., `./my_report.json`) |
| `--entropy-threshold` | Sensitivity: lower numbers catch more secrets (default: 4.5) |
| `--min-length` | Minimum string length to check (default: 20) |
| `--verbose` | Show every file being scanned in real-time |

## Example Output (JSON)

```json
{
  "scan_metadata": {
    "target": "./test_repo",
    "files_scanned": 2,
    "total_findings": 7
  },
  "findings": [
    {
      "file": "test_repo/vulnerable_app/.env",
      "type": "AWS_Key",
      "match": "AKIAIOSFODNN7EXAMPLE",
      "line": 1
    }
  ]
}
```

## License

MIT

## Author

**Oluwashina** - [GitHub Profile](https://github.com/Oluwashina04)

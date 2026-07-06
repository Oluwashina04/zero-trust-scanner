#!/usr/bin/env python3
import os
import sys
import json
import click
from pathlib import Path
from datetime import datetime

from scanner.core.walker import walk_directory
from scanner.core.entropy import is_high_entropy_string
from scanner.plugins.regex_rules import scan_with_regex
from scanner.plugins.concatenators import detect_concatenated_secrets
from scanner.utils.output_formatter import generate_sarif, generate_json

@click.command()
@click.argument('target_path', type=click.Path(exists=True))
@click.option('--output', '-o', default='./output/report.json', help='Output file path')
@click.option('--format', '-f', type=click.Choice(['json', 'sarif'], case_sensitive=False), default='json')
@click.option('--entropy-threshold', default=4.5, help='Entropy threshold (default: 4.5)')
@click.option('--min-length', default=20, help='Minimum string length for entropy check (default: 20)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def scan(target_path, output, format, entropy_threshold, min_length, verbose):
    """
    Zero-Trust Secret Scanner - Detects hardcoded secrets in code repositories.
    """
    if verbose:
        click.echo(f"Target: {target_path}")
        click.echo(f"Entropy threshold: {entropy_threshold}, Min length: {min_length}")
    
    findings = []
    files_scanned = 0
    
    for file_path in walk_directory(target_path):
        if verbose:
            click.echo(f"Processing: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Regex-based scanning
            regex_findings = scan_with_regex(content)
            for finding in regex_findings:
                findings.append({
                    "file": str(file_path),
                    "type": finding["type"],
                    "match": finding["match"],
                    "line": content[:finding["span"][0]].count('\n') + 1,
                    "detection_method": "regex"
                })
            
            # Entropy-based scanning
            import re
            for line_num, line in enumerate(content.split('\n'), 1):
                for token in re.split(r'[\s,;:=+()"\'"]', line):
                    if is_high_entropy_string(token, threshold=entropy_threshold, min_len=min_length):
                        findings.append({
                            "file": str(file_path),
                            "type": "High_Entropy_String",
                            "match": token[:50] + "..." if len(token) > 50 else token,
                            "line": line_num,
                            "detection_method": "entropy"
                        })
            
            # Concatenation detection
            concat_findings = detect_concatenated_secrets(content, file_path)
            findings.extend(concat_findings)
            
            files_scanned += 1
            
        except Exception as e:
            if verbose:
                click.echo(f"Skipping {file_path}: {e}")
    
    os.makedirs(os.path.dirname(output) if os.path.dirname(output) else '.', exist_ok=True)
    
    if format == 'sarif':
        report = generate_sarif(findings, target_path)
        with open(output, 'w') as f:
            json.dump(report, f, indent=2)
    else:
        report = generate_json(findings, target_path, files_scanned)
        with open(output, 'w') as f:
            json.dump(report, f, indent=2)
    
    click.echo(f"\nScan complete. Files scanned: {files_scanned}")
    click.echo(f"Total findings: {len(findings)}")
    click.echo(f"Report saved to: {output}")

if __name__ == "__main__":
    scan()

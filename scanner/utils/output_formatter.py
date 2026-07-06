import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

def generate_json(findings: List[Dict[str, Any]], target_path: str, files_scanned: int) -> Dict[str, Any]:
    """
    Generate a JSON report from scan findings.
    
    Args:
        findings: List of detected secrets
        target_path: Path that was scanned
        files_scanned: Number of files processed
        
    Returns:
        Formatted JSON report as a dictionary
    """
    return {
        "scan_metadata": {
            "target": target_path,
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "files_scanned": files_scanned,
            "total_findings": len(findings),
            "scanner": "Zero-Trust Secret Scanner v1.0.0"
        },
        "findings": findings
    }

def generate_sarif(findings: List[Dict[str, Any]], target_path: str) -> Dict[str, Any]:
    """
    Generate SARIF 2.1.0 compliant output for GitHub Advanced Security.
    
    Args:
        findings: List of detected secrets
        target_path: Path that was scanned
        
    Returns:
        SARIF formatted report as a dictionary
    """
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Zero-Trust Secret Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/yourusername/zero-trust-scanner",
                        "rules": []
                    }
                },
                "artifacts": [],
                "results": []
            }
        ]
    }
    
    rule_ids = {}
    for finding in findings:
        rule_id = finding['type'].replace(' ', '_').upper()
        if rule_id not in rule_ids:
            rule_ids[rule_id] = {
                "id": rule_id,
                "name": finding['type'],
                "shortDescription": {
                    "text": f"Potential {finding['type']} detected"
                },
                "fullDescription": {
                    "text": f"Detected via {finding['detection_method']} analysis"
                },
                "defaultConfiguration": {
                    "level": "warning" if finding['detection_method'] == 'entropy' else "error"
                }
            }
    
    sarif['runs'][0]['tool']['driver']['rules'] = list(rule_ids.values())
    
    for finding in findings:
        result = {
            "ruleId": finding['type'].replace(' ', '_').upper(),
            "level": "warning" if finding['detection_method'] == 'entropy' else "error",
            "message": {
                "text": f"{finding['type']}: {finding['match']}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": Path(finding['file']).name
                        },
                        "region": {
                            "startLine": finding['line'],
                            "startColumn": 1
                        }
                    }
                }
            ]
        }
        sarif['runs'][0]['results'].append(result)
    
    return sarif

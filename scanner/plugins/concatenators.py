import re
from pathlib import Path
from typing import List, Dict, Any

def detect_concatenated_secrets(content: str, file_path: str) -> List[Dict[str, Any]]:
    """
    Detect secrets that have been split across multiple variables.
    
    Patterns detected:
        1. Variables named with PART, CHUNK, or FRAG suffixes
        2. Multi-line string concatenation using parentheses
        
    Args:
        content: File content to scan
        file_path: Path to the file being scanned
        
    Returns:
        List of findings with reconstructed secrets
    """
    findings = []
    lines = content.split('\n')
    
    # Pattern 1: Variables with PART/CHUNK/FRAG suffixes
    part_pattern = re.compile(
        r'^([A-Z_]+(?:PART|CHUNK|FRAG)[0-9]+)\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE
    )
    
    part_vars = {}
    
    for line_num, line in enumerate(lines, 1):
        match = part_pattern.search(line)
        if match:
            var_name, value = match.groups()
            # Extract base name (e.g., TOKEN_PART1 -> TOKEN)
            base_name = re.sub(r'_(?:PART|CHUNK|FRAG)[0-9]+$', '', var_name, flags=re.IGNORECASE)
            if base_name not in part_vars:
                part_vars[base_name] = []
            part_vars[base_name].append({
                'line_num': line_num,
                'var': var_name,
                'value': value
            })
    
    # Reconstruct secrets from parts
    for base_name, parts in part_vars.items():
        if len(parts) >= 2:
            parts.sort(key=lambda x: x['line_num'])
            reconstructed = ''.join([p['value'] for p in parts])
            
            # Verify reconstructed string looks like a secret
            if (len(reconstructed) > 20 and 
                any(c.isdigit() for c in reconstructed) and 
                any(c.isalpha() for c in reconstructed)):
                findings.append({
                    "file": str(file_path),
                    "type": f"Concatenated_Secret_{base_name}",
                    "match": f"{'+'.join([p['var'] for p in parts])} -> {reconstructed[:50]}",
                    "line": parts[0]['line_num'],
                    "detection_method": "concatenation"
                })
    
    # Pattern 2: Multi-line string concatenation
    multi_line_pattern = re.findall(
        r'\((["\'])\s*([^)]+)\s*\1\)',
        content,
        re.DOTALL
    )
    
    for quote, inner_content in multi_line_pattern:
        tokens = re.findall(r'["\']([^"\']+)["\']', inner_content)
        if len(tokens) >= 2:
            reconstructed = ''.join(tokens)
            if len(reconstructed) > 20:
                findings.append({
                    "file": str(file_path),
                    "type": "Multi_Line_Concatenated_Secret",
                    "match": f"{reconstructed[:50]}...",
                    "line": 1,
                    "detection_method": "concatenation"
                })
    
    return findings

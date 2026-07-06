#!/usr/bin/env python3
import os
import fnmatch
from pathlib import Path
import pathspec

def walk_directory(root_path, respect_gitignore=True):
    """Recursively walk directory, respecting .gitignore and skipping binaries."""
    root_path = Path(root_path)
    
    # Load .gitignore patterns if present
    gitignore_path = root_path / '.gitignore'
    ignore_patterns = []
    if gitignore_path.exists() and respect_gitignore:
        with open(gitignore_path, 'r') as f:
            ignore_patterns = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    # Binary file extensions to skip
    binary_extensions = {'.pyc', '.pyo', '.so', '.dll', '.dylib', '.exe', 
                         '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
                         '.mp3', '.mp4', '.avi', '.mov', '.pdf', '.zip', '.tar', '.gz'}
    
    for root, dirs, files in os.walk(root_path):
        # Skip hidden directories and common version control
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in {'node_modules', '__pycache__', 'venv', 'env'}]
        
        for file in files:
            file_path = Path(root) / file
            rel_path = file_path.relative_to(root_path)
            
            # Check .gitignore patterns
            if ignore_patterns and pathspec.PathSpec.from_lines('gitwildmatch', ignore_patterns).match_file(str(rel_path)):
                continue
            
            # Skip binary files
            if any(str(file_path).endswith(ext) for ext in binary_extensions):
                continue
            
            # Skip if file is too large (>10MB)
            if file_path.stat().st_size > 10 * 1024 * 1024:
                continue
            
            yield file_path

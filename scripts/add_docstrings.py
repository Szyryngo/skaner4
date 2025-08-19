#!/usr/bin/env python3
"""
Script to add placeholder docstrings to modules, classes, and functions in the skaner4 project.
"""
import os
import re

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def add_docstrings_to_file(path):
    """Insert placeholder docstrings into a single Python file.

    Reads the file at the given path, adds module, class, and function docstrings
    where missing, and writes the modified content back.

    Parameters
    ----------
    path : str
        Filesystem path to the Python file to process.
    """
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    output = []
    i = 0
    # Module docstring
    if lines and not lines[0].lstrip().startswith(('"""', "'''")):
        mod_name = os.path.splitext(os.path.basename(path))[0]
        output.append(f'"""Module {mod_name} - description."""\n')
    while i < len(lines):
        line = lines[i]
        # Class
        cls_match = re.match(r'^(\s*)class\s+(\w+)', line)
        if cls_match:
            indent, cls_name = cls_match.groups()
            output.append(line)
            # Check next non-empty for docstring
            j = i + 1
            while j < len(lines) and lines[j].strip() == '':
                output.append(lines[j])
                j += 1
            # Insert placeholder docstring if missing
            if j < len(lines) and not lines[j].lstrip().startswith(('"""', "'''")):
                output.append(f"{indent}    '''Class {cls_name} - description.'''\n")
            i += 1
            continue
        # Function
        fn_match = re.match(r'^(\s*)def\s+(\w+)\s*\(', line)
        if fn_match:
            indent, fn_name = fn_match.groups()
            output.append(line)
            # Check next non-empty for docstring
            j = i + 1
            while j < len(lines) and lines[j].strip() == '':
                output.append(lines[j])
                j += 1
            # Insert placeholder docstring if missing
            if j < len(lines) and not lines[j].lstrip().startswith(('"""', "'''")):
                output.append(f"{indent}    '''Function {fn_name} - description.'''\n")
            i += 1
            continue
        output.append(line)
        i += 1

    with open(path, 'w', encoding='utf-8') as f:
        f.writelines(output)

if __name__ == '__main__':
    """Walk project files and apply docstring insertion to all Python modules."""
    for root, _, files in os.walk(PROJECT_ROOT):
        if 'scripts' in root:
            continue
        for fname in files:
            if fname.endswith('.py'):
                fpath = os.path.join(root, fname)
                print(f'Processing {fpath}')
                add_docstrings_to_file(fpath)
    print('Docstring insertion complete.')

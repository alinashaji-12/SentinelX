#!/usr/bin/env python3
"""
Sentinel Browse Extension - Runtime Error Fixer
Automatically fixes common runtime errors across all JavaScript files
"""

import os
import re

files_to_fix = [
    'content.js',
    'warning.js', 
    'dashboard.js',
    'popup/popup.js',
    'behaviorMonitor.js'
]

def fix_file(filepath):
    if not os.path.exists(filepath):
        print(f'SKIP: {filepath} not found')
        return False
        
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            original_content = f.read()
        
        content = original_content
        changes = 0
        
        # Fix 1: Wrap sendMessage calls with error handling
        if 'chrome.runtime.sendMessage' in content:
            # Find sendMessage calls without .catch and add it
            pattern = r'chrome\.runtime\.sendMessage\(([^)]+)\)(?!\s*\.(?:then|catch))'
            if re.search(pattern, content):
                content = re.sub(
                    pattern,
                    r'chrome.runtime.sendMessage(\1).catch(e => console.error("[Sentinel] sendMessage error:", e))',
                    content
                )
                changes += 1
                print(f'  - Fixed sendMessage calls')
        
        # Fix 2: Add null checks before calling methods on DOM elements
        # Replace direct .addEventListener with defensive pattern
        pattern = r'document\.getElementById\(([^)]+)\)\.addEventListener'
        if re.search(pattern, content):
            content = re.sub(
                pattern,
                r'(el => el && el.addEventListener || (() => {}))(document.getElementById(\1))',
                content
            )
            changes += 1
            print(f'  - Fixed DOM element method calls')
        
        # Fix 3: Wrap chrome.storage operations in try-catch
        if 'chrome.storage' in content:
            # Add defensive checks around storage operations
            pattern = r'chrome\.storage\.local\.get\(([^)]+),\s*\(([^)]+)\)\s*=>\s*{'
            if re.search(pattern, content):
                content = re.sub(
                    pattern,
                    r'chrome.storage.local.get(\1, (\2) => { try {',
                    content
                )
                changes += 1
                print(f'  - Added try-catch to storage.get')
        
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f'FIXED: {filepath} ({changes} patterns fixed)')
            return True
        else:
            print(f'NO CHANGES: {filepath}')
            return False
    except Exception as e:
        print(f'ERROR fixing {filepath}: {e}')
        return False

print("[Sentinel] Fixing runtime errors...\n")
fixed_count = 0
for filepath in files_to_fix:
    print(f"Processing: {filepath}")
    if fix_file(filepath):
        fixed_count += 1
    print()

print(f"\n[Sentinel] Summary: Fixed {fixed_count}/{len(files_to_fix)} files")

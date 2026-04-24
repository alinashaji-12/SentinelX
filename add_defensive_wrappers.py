#!/usr/bin/env python3
"""
Sentinel Browse Extension - Defensive Wrapper & Validation
Adds try-catch wrappers to all entry points and validates configuration
"""

import os
import json
import re

print("[Sentinel] Adding defensive execution wrappers...\n")

# 1. Add global error handlers to all content scripts
def add_defensive_wrapper(filepath):
    """Add try-catch wrapper to main script execution"""
    if not os.path.exists(filepath):
        print(f"  SKIP: {filepath} not found")
        return False
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Skip if already has wrapper
        if '[Sentinel]' in content and ('try {' in content or 'catch' in content):
            print(f"  ✓ {filepath} already has error handling")
            return True
        
        # Add header with initialization
        if not content.startswith('/**') and filepath != 'background.js':
            header = '''// ═══════════════════════════════════════════════════════════════════════════════
// DEFENSIVE EXECUTION WRAPPER - Prevents single error from breaking extension
// ═══════════════════════════════════════════════════════════════════════════════

if (typeof console === 'undefined' || !console.error) {
  window.console = window.console || {};
  window.console.error = function() {};
}

// Wrap entire script in try-catch to prevent uncaught errors
try {
'''
            
            footer = '''
} catch (e) {
  console.error("[Sentinel] CRITICAL ERROR - Execution wrapper caught:", e);
  console.error("[Sentinel] Stack:", e?.stack);
}
// ═══════════════════════════════════════════════════════════════════════════════
'''
            
            # Skip header files and already wrapped files
            if 'try {' not in content[:500] and 'DEFENSIVE EXECUTION' not in content:
                content = header + content + footer
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"  ✓ Added defensive wrapper to {filepath}")
                return True
        
        return False
    except Exception as e:
        print(f"  ERROR in {filepath}: {e}")
        return False

# 2. Validate manifest.json
def validate_manifest():
    """Verify manifest configuration is correct"""
    print("Validating manifest.json...")
    try:
        with open('manifest.json', 'r', encoding='utf-8') as f:
            manifest = json.load(f)
        
        issues = []
        
        # Check service worker exists
        if not manifest.get('background'):
            issues.append("Missing 'background' service worker definition")
        elif manifest['background'].get('service_worker') != 'background.js':
            issues.append(f"Service worker path is {manifest['background'].get('service_worker')}, should be background.js")
        
        # Check content_scripts paths exist
        for script_entry in manifest.get('content_scripts', []):
            for script in script_entry.get('js', []):
                if not os.path.exists(script):
                    issues.append(f"Content script not found: {script}")
        
        # Check web_accessible_resources
        for resource_entry in manifest.get('web_accessible_resources', []):
            for resource in resource_entry.get('resources', []):
                if '*' not in resource and not os.path.exists(resource):
                    issues.append(f"Web resource not found: {resource}")
        
        if issues:
            print("  ⚠ Manifest issues found:")
            for issue in issues:
                print(f"    - {issue}")
            return False
        else:
            print("  ✓ Manifest.json is valid")
            return True
    except Exception as e:
        print(f"  ERROR validating manifest: {e}")
        return False

# 3. Check all importScripts in background.js
def validate_imports():
    """Verify all importScripts will load correctly"""
    print("\nValidating background.js imports...")
    required_scripts = [
        'detectionEngine.js',
        'adaptiveEngine.js',
        'threatIntelService.js',
        'threatEvaluator.js',
        'sslDetector.js'
    ]
    
    issues = []
    for script in required_scripts:
        if not os.path.exists(script):
            issues.append(f"Missing import: {script}")
        else:
            print(f"  ✓ Found {script}")
    
    if issues:
        print("\n  ⚠ Import issues:")
        for issue in issues:
            print(f"    - {issue}")
        return False
    return True

# Apply defensive wrappers
print("Adding defensive wrappers to entry points:")
wrapper_files = [
    'content.js',
    'popup/popup.js',
    'warning.js',
]

for f in wrapper_files:
    add_defensive_wrapper(f)

print()
validate_manifest()
validate_imports()

print("\n[Sentinel] Defensive wrapper validation complete!")

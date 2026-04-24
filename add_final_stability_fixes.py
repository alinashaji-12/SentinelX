#!/usr/bin/env python3
"""
Sentinel Browse Extension - Final Stability Fixes
Adds global error listeners and ensures all functions are available
"""

import os
import re

def add_global_error_handlers():
    """Add global error and promise rejection handlers to key files"""
    
    handlers = {
        'popup/popup.js': '''
// ═══════════════════════════════════════════════════════════════════════════
// GLOBAL ERROR HANDLING
// ═══════════════════════════════════════════════════════════════════════════

// Handle uncaught errors
window.addEventListener('error', (event) => {
  console.error('[Sentinel] Uncaught error:', event.error);
  event.preventDefault();
}, true);

// Handle promise rejections
window.addEventListener('unhandledrejection', (event) => {
  console.error('[Sentinel] Unhandled promise rejection:', event.reason);
  event.preventDefault();
});
''',
        'warning.js': '''
// ═══════════════════════════════════════════════════════════════════════════
// GLOBAL ERROR HANDLING
// ═══════════════════════════════════════════════════════════════════════════

// Handle uncaught errors
window.addEventListener('error', (event) => {
  console.error('[Sentinel] Uncaught error in warning page:', event.error);
  event.preventDefault();
}, true);

// Handle promise rejections
window.addEventListener('unhandledrejection', (event) => {
  console.error('[Sentinel] Unhandled promise rejection in warning page:', event.reason);
  event.preventDefault();
});
''',
        'content.js': '''
// ═══════════════════════════════════════════════════════════════════════════
// GLOBAL ERROR HANDLING - Content Script
// ═══════════════════════════════════════════════════════════════════════════

window.addEventListener('error', (event) => {
  console.error('[Sentinel] Content script error:', event.error);
  event.preventDefault();
}, true);

window.addEventListener('unhandledrejection', (event) => {
  console.error('[Sentinel] Content script promise rejection:', event.reason);
  event.preventDefault();
});
''',
    }
    
    print("[Sentinel] Adding global error handlers...\n")
    
    for filepath, handler_code in handlers.items():
        if not os.path.exists(filepath):
            print(f"  SKIP: {filepath} not found")
            continue
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Skip if already has global error handlers
            if 'window.addEventListener' in content and 'unhandledrejection' in content:
                print(f"  ✓ {filepath} already has global error handlers")
                continue
            
            # Find the right place to insert (after initial setup but before main code)
            insert_pos = None
            
            # Try to find 'use strict'
            strict_match = re.search(r'"use strict";?\s*\n', content)
            if strict_match:
                insert_pos = strict_match.end()
            else:
                # Try to find first import/requires
                import_match = re.search(r'(importScripts|chrome\.|const |let |var )', content)
                if import_match:
                    insert_pos = 0
                else:
                    insert_pos = 0
            
            if insert_pos is not None:
                # Add handler after finding a good location
                new_content = content[:insert_pos] + '\n' + handler_code + '\n' + content[insert_pos:]
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                
                print(f"  ✓ Added global error handlers to {filepath}")
        except Exception as e:
            print(f"  ERROR processing {filepath}: {e}")

# Add fallback functions for potentially undefined globals
def add_fallback_functions():
    """Add fallback functions for undefined objects/methods"""
    
    print("\n[Sentinel] Adding fallback functions...\n")
    
    fallbacks = {
        'popup/popup.js': '''
// Fallback if chrome.runtime is not available
if (!window.chrome) window.chrome = {};
if (!window.chrome.runtime) window.chrome.runtime = {
  sendMessage: async (msg) => { console.warn('[Sentinel] chrome.runtime.sendMessage unavailable'); return {}; },
  onMessage: { addListener: () => {} }
};
''',
        'content.js': '''
// Fallback for potentially undefined functions
if (!window.console) window.console = { error: () => {}, warn: () => {}, log: () => {} };
if (!window.chrome) window.chrome = {};
if (!window.chrome.runtime) window.chrome.runtime = {
  sendMessage: async (msg) => { console.warn('[Sentinel] chrome.runtime unavailable'); return {}; },
  getURL: (path) => path,
  onMessage: { addListener: () => {} }
};
''',
        'warning.js': '''
// Fallback for chrome API
if (!window.chrome) window.chrome = {};
if (!window.chrome.storage) window.chrome.storage = {
  local: { get: (keys, cb) => cb({}), set: (data, cb) => cb() }
};
if (!window.chrome.runtime) window.chrome.runtime = {
  sendMessage: async (msg) => ({})
};
'''
    }
    
    for filepath, fallback_code in fallbacks.items():
        if not os.path.exists(filepath):
            print(f"  SKIP: {filepath} not found")
            continue
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Skip if fallbacks already present
            if 'window.chrome' in content and 'Fallback' in content:
                print(f"  ✓ {filepath} already has fallback functions")
                continue
            
            # Add after 'use strict'
            strict_match = re.search(r'"use strict";?\s*\n', content)
            if strict_match:
                insert_pos = strict_match.end()
                new_content = content[:insert_pos] + '\n' + fallback_code + '\n' + content[insert_pos:]
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                
                print(f"  ✓ Added fallback functions to {filepath}")
        except Exception as e:
            print(f"  ERROR processing {filepath}: {e}")

# Main execution
if __name__ == '__main__':
    add_global_error_handlers()
    add_fallback_functions()
    print("\n[Sentinel] Final stability fixes complete!")

#!/usr/bin/env python3
"""
Sentinel Browse Extension - Advanced Runtime Error Fixer
Fixes critical DOM access and message passing issues
"""

import os
import re

def safe_replace(filepath, old, new):
    """Safely replace text in a file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if old in content:
            content = content.replace(old, new)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"  ERROR in {filepath}: {e}")
        return False

# Fix content.js - Wrap message listener callback
print("Fixing content.js...")
content_fixes = [
    ('chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {',
     'chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {\n  try {'),
    ('    sendResponse({ ok: true, deduplicated: true });\n    return;\n  }\n});',
     '    sendResponse({ ok: true, deduplicated: true });\n    return;\n  } catch (e) {\n    console.error("[Sentinel] Message handler error:", e);\n  }\n});'),
]

for old, new in content_fixes:
    if safe_replace('content.js', old, new):
        print(f"  ✓ Fixed message listener")

# Fix popup/popup.js - Add error handling
print("\nFixing popup/popup.js...")
popup_fixes = [
    ('const resp = await chrome.runtime.sendMessage({ type: "sentinel:get-tab-risk", tabId });',
     'let resp; try { resp = await chrome.runtime.sendMessage({ type: "sentinel:get-tab-risk", tabId }); } catch (e) { console.error("[Sentinel] get-tab-risk failed:", e); resp = {}; }'),
]

for old, new in popup_fixes:
    if safe_replace('popup/popup.js', old, new):
        print(f"  ✓ Fixed sendMessage with error handling")

# Fix dashboard.js - Add DOM safety checks
print("\nFixing dashboard.js...")
dashboard_fixes = [
    ('  const bodyEl    = document.getElementById("historyBody");\n  const emptyEl   = document.getElementById("emptyState");\n  if (!bodyEl) return;',
     '  const bodyEl    = document.getElementById("historyBody");\n  const emptyEl   = document.getElementById("emptyState");\n  if (!bodyEl || !emptyEl) return;'),
]

for old, new in dashboard_fixes:
    if safe_replace('dashboard.js', old, new):
        print(f"  ✓ Added DOM null checks")

# Fix warning.js - Add storage safety
print("\nFixing warning.js...")
warning_fixes = [
    ('  try {\n    const stored = await storageGet([STORAGE_KEYS.LAST_ANALYSIS]);',
     '  try {\n    if (!STORAGE_KEYS || !STORAGE_KEYS.LAST_ANALYSIS) { console.error("[Sentinel] Storage keys not configured"); return null; }\n    const stored = await storageGet([STORAGE_KEYS.LAST_ANALYSIS]);'),
]

for old, new in warning_fixes:
    if safe_replace('warning.js', old, new):
        print(f"  ✓ Added storage validation")

# Fix behaviorMonitor.js - Add event listener safety
print("\nFixing behaviorMonitor.js...")
bm_fixes = [
    ('document.addEventListener("click",   () => { lastUserEventTime = Date.now(); _markUserInitiated(); }, { capture: true, passive: true });',
     'try { document.addEventListener("click",   () => { lastUserEventTime = Date.now(); _markUserInitiated(); }, { capture: true, passive: true }); } catch (e) { console.warn("[Sentinel] Click listener failed:", e); }'),
]

for old, new in bm_fixes:
    if safe_replace('behaviorMonitor.js', old, new):
        print(f"  ✓ Added event listener error handling")

print("\n[Sentinel] Advanced fixes complete!")

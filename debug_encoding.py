file_path = r'd:\sentinel-browse-extension\background.js'

# Read file in binary mode to see raw bytes
with open(file_path, 'rb') as f:
    content = f.read()

# Try UTF-8 first
try:
    text = content.decode('utf-8')
    lines = text.split('\n')
    
    # Get lines 2000-2030 (0-indexed, so lines 1999-2029)
    target_lines = lines[1999:2030]
    
    print('=== Lines 2000-2030 (UTF-8) ===\n')
    for i, line in enumerate(target_lines, start=2000):
        print(f'Line {i}:')
        print(f'  Length: {len(line)} chars')
        print(f'  Text repr: {repr(line[:100])}')
        print(f'  Hex bytes: {line.encode("utf-8").hex()[:200]}')
        print()
        
except UnicodeDecodeError as e:
    print(f'UTF-8 Decode Error: {e}')
    print('\nTrying Latin-1...\n')
    
    text = content.decode('latin-1')
    lines = text.split('\n')
    target_lines = lines[1999:2030]
    
    print('=== Lines 2000-2030 (Latin-1) ===\n')
    for i, line in enumerate(target_lines, start=2000):
        print(f'Line {i}:')
        print(f'  Length: {len(line)} chars')
        print(f'  Text repr: {repr(line[:100])}')
        print(f'  Hex bytes: {line.encode("latin-1").hex()[:200]}')
        print()

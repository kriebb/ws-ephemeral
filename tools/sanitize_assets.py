import os
import re
from pathlib import Path

ASSETS_DIR = Path("tests/assets")

def sanitize_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        print(f"Skipping {file_path}: {e}")
        return

    original_content = content

    # Sanitize Cookies in _cookies.txt (Name: ...\nValue: ...)
    # Skip 'i_can_has_cookie' and 'ref' which are generic
    content = re.sub(r"(Name: (?!i_can_has_cookie|ref).*\nValue: )([^\n]+)", r"\1REDACTED", content)
    
    # Sanitize Headers in _info.txt (Python dictionary repr)
    # cookie': '...'
    # Regex to find auth_redir=... and replace value
    content = re.sub(r"(auth_redir)=[^;']+", r"\1=REDACTED", content)
    
    # Sanitize cf-ray
    content = re.sub(r"('cf-ray': ')[^']+", r"\1REDACTED", content)

    # Sanitize JSON tokens in _body.html (if json)
    # "token":"..."
    content = re.sub(r'("token":")[^"]+(")', r'\1REDACTED\2', content)
    content = re.sub(r'("token_id":")[^"]+(")', r'\1REDACTED\2', content)
    content = re.sub(r'("signature":")[^"]+(")', r'\1REDACTED\2', content)
    content = re.sub(r'("request_id":")[^"]+(")', r'\1REDACTED\2', content)
    # entropy struct
    content = re.sub(r'("entropy":\{)[^}]+(\})', r'\1"REDACTED"\2', content)

    if content != original_content:
        print(f"Sanitized {file_path}")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

def main():
    if not ASSETS_DIR.exists():
        print(f"Assets dir {ASSETS_DIR} not found")
        return

    print("Starting sanitization...")
    for file_path in ASSETS_DIR.glob("*"):
        if file_path.is_file():
            sanitize_file(file_path)
    print("Done.")

if __name__ == "__main__":
    main()

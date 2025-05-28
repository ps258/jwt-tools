#!/usr/bin/python3

import sys
import os
from authlib.jose import JsonWebKey

def read_file(filename):
    try:
        with open(filename, 'r') as file:
            content = file.read()
        return content
    except FileNotFoundError:
        return "File not found."
    except Exception as e:
        return f"An error occurred: {e}"

if len(sys.argv) < 2:
    print(f"Usage:{sys.argv[0]} <file1> [file2] [file3] ...")
    sys.exit(1)

# Check if all files exist first
files = sys.argv[1:]
for filename in files:
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' does not exist")
        sys.exit(1)

# Process each file and collect JWKs
jwks = {"keys": []}

for filename in files:
    print(f"Processing: {filename}", file=sys.stderr)
    key_data = read_file(filename)
    
    # Try different key types since we might have RSA, ECDSA, etc.
    try:
        key = JsonWebKey.import_key(key_data)
    except Exception as e:
        print(f"Error processing {filename}: {e}", file=sys.stderr)
        continue
    
    # Add the JWK to our collection
    jwk_dict = key.as_dict()
    jwks["keys"].append(jwk_dict)

# Output the complete JWKS
import json
print(json.dumps(jwks, indent=2))


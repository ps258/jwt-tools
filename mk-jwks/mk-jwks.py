#!/usr/bin/python3

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


key_data = read_file('cert.pem')
key = JsonWebKey.import_key(key_data, {'kty': 'RSA'})

#print(key.as_dict())
print(key.as_json())


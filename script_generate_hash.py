import hashlib

# Path to your script file
script_path = "url_safety_analyzer.py"

with open(script_path, "rb") as f:
    script_content = f.read()

script_hash = hashlib.sha256(script_content).hexdigest()
print(f"Script Hash: {script_hash}")

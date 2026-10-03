import os
import secrets
from pathlib import Path

def generate_secret_key(length=50):
    return secrets.token_urlsafe(length)

def update_env_file(secret_key, env_file_path=".env"):
    env_path = Path(env_file_path)
    lines = env_path.read_text().splitlines() if env_path.exists() else []

    replaced = False
    out = []
    for line in lines:
        if line.startswith("SECRET_KEY="):
            out.append(f"SECRET_KEY={secret_key}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(f"SECRET_KEY={secret_key}")

    env_path.write_text("\n".join(out) + "\n")
    try:
        os.chmod(env_path, 0o600)  # .env holds secrets: owner-only on Linux/macOS
    except OSError:
        pass  # Windows has no chmod semantics

if __name__ == "__main__":
    new_secret_key = generate_secret_key()
    update_env_file(new_secret_key)
    print("Secret key written to .env")

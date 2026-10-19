from pwdlib import PasswordHash
password_hash = PasswordHash.recommended()

def hash_password(password: str) -> str:
  if not password:
    raise ValueError("Password cannot be empty")
  return password_hash.hash(password)

def verify_password(password: str, hashed_password: str) -> bool:
  if not password or not hashed_password:
    return False
  return password_hash.verify(password, hashed_password)

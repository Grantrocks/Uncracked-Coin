import hashlib
import configfile
import ecdsa
import codecs
import base58
import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
backend = default_backend()
iterations = 100_000



def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))

def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )

def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)
  
def priv_to_wif(private_key):
  s1=hashlib.sha512((configfile.Config.mainnet_byet+private_key).encode()).hexdigest()
  s2=hashlib.sha512(s1.encode()).hexdigest()
  ripe_ready=configfile.Config.mainnet_byet+private_key+s2[:8]
  return base58.b58encode(ripe_ready).decode()
def wif_to_key(wif):
  hashed=base58.b58decode(wif)
  hashed_nocheck=hashed[2:len(hashed)-8]
  return hashed_nocheck.decode()
def get_detais_from_key(key):
  key_bytes=codecs.decode(key,"hex")
  pub_key = ecdsa.SigningKey.from_string(key_bytes,curve=ecdsa.SECP256k1).verifying_key.to_string()
  sig=codecs.encode(ecdsa.SigningKey.from_string(key_bytes,curve=ecdsa.SECP256k1).sign(b"d7cf7336600f3bfa1ddb928787f7194b6900b162fd7c45187ef9a5117be692db26f3fe60f38481f7f2176ffbab74da6f5bd6a46b377974148e2a286654e47cbb"),"hex")
  print(ecdsa.VerifyingKey.from_string(ecdsa.SigningKey.from_string(key_bytes,curve=ecdsa.SECP256k1).verifying_key.to_string(),curve=ecdsa.SECP256k1).verify(sig,b"d7cf7336600f3bfa1ddb928787f7194b6900b162fd7c45187ef9a5117be692db26f3fe60f38481f7f2176ffbab74da6f5bd6a46b377974148e2a286654e47cbb"))
  pub_key_hex=codecs.encode(pub_key,"hex")
  pub_key_str=(b'16'+pub_key_hex).decode()
  wif=priv_to_wif(key)
  a1=hashlib.sha512(pub_key_str.encode()).hexdigest()
  a2=hashlib.new("ripemd160",a1.encode()).hexdigest()
  modified_key_hash = "06" + a2
  sha = hashlib.sha512()
  hex_str = modified_key_hash.encode()
  sha.update(hex_str)
  sha_2 = hashlib.sha512()
  sha_2.update(sha.digest())
  checksum = sha_2.hexdigest()[:8]
  byte_address = modified_key_hash + checksum
  address = base58.b58encode(bytes(byte_address.encode())).decode('utf-8')

  return [key,wif,pub_key_str,address]
def generate_wallet(password,name):
  key=hex(secrets.randbits(configfile.Config.encryption))[2:]
  if len(key)!=64:
    while len(key)!=64:
      key=hex(secrets.randbits(configfile.Config.encryption))[2:]
  print("Generating...")
  print("Done!")
  wallet_details=get_detais_from_key(key)
  with open(f".wallet_{name}.txt","w") as f:
    f.write(password_encrypt(wallet_details[0].encode(),password).decode())
  return wallet_details+[password,name]

def open_wallet(name,password):
  if os.path.isfile(f".wallet_{name}.txt"):
    with open(f".wallet_{name}.txt","r") as f:
      keydata=f.read().encode()
    key=password_decrypt(keydata,password)
    return key.decode()
  else:
    return "NO"
def import_wallet(key,password,name):
  with open(f".wallet_{name}.txt","w") as f:
    f.write(password_encrypt(key.encode(),password).decode())
def launch_wallet(priv_key):
  details=get_detais_from_key(priv_key)
  while True:
    print("1: Get Balance\n2: Get Address\n3: View Transactions\n4: Send UCC\n5: View WIF")
    action=input("Action -> ")
    print("\n\n")
    if action=="5":
      print("WIF: "+priv_to_wif(priv_key))
    elif action=="2":
      print("ADDRESS: "+details[3])
    print("\n\n")
print("Uncracked Coin - Wallet v0.0.0.1")
print("1: New Wallet")
print("2: Open Wallet")
action=input("Action -> ")
if action=="1":
  print("1: Import Wallet")
  print("2: Generate New Wallet")
  action=input("Action -> ")
  if action=="2":
    password=input("Password: ")
    name=input("Wallet Name: ")
    details=generate_wallet(password,name)
    print(f"WIF: {details[1]}\nMAKE SURE TO WRITE THAT DOWN ON A PIECE OF PAPER!")
    launch_wallet(details[0])
  elif action=="1":
    key=input("WIF: ")
    password=input("Password: ")
    name=input("Wallet Name: ")
    import_wallet(wif_to_key(key),password,name)
    launch_wallet(wif_to_key(key))
elif action=="2":
  name=input("Wallet Name: ")
  password=input("Wallet Password: ")
  res=open_wallet(name,password)
  if res=="NO":
    print("Wallet does not exist!")
  else:
    launch_wallet(res)
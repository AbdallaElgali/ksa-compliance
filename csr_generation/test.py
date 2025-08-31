from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import base64

# Your EC private key PEM (secp256r1 / prime256v1)
priv_key_pem = b"""-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIGg466VhfqEocptdwQKMJup8+JuypJMz43moYwrT6fquoAcGBSuBBAAK
oUQDQgAEGQ6Zld9fMPlf1DAsaOMbPr2ZpkCdRsVdColSoBOSRNW75WE1+4W/CA8L
lOYNRIJVxdk7CICjzkqNfTOUzro2/w==
-----END EC PRIVATE KEY-----"""

# Load the private key from PEM
private_key = serialization.load_pem_private_key(priv_key_pem, password=None)

# Example: hash you want to sign (32-byte SHA-256 hash)
data_to_sign = b"Example invoice hash or any data"
digest = hashes.Hash(hashes.SHA256())
digest.update(data_to_sign)
hash_bytes = digest.finalize()

# Sign the hash using ECDSA + SHA-256
signature = private_key.sign(
    hash_bytes,
    ec.ECDSA(hashes.SHA256())
)

# Encode the signature in base64 (like for ds:SignatureValue)
signature_b64 = base64.b64encode(signature).decode()

print("✅ Signature bytes:", signature)
print("✅ Signature Base64:", signature_b64)

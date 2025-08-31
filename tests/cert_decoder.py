import base64
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pyasn1.type import univ, namedtype, tag
from pyasn1.codec.der.encoder import encode as der_encode

# ASN.1 structures
class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.NamedType('parameters', univ.ObjectIdentifier())
    )

class SubjectPublicKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', AlgorithmIdentifier()),
        namedtype.NamedType('subjectPublicKey', univ.BitString())
    )

def pem_to_base64(pem: str) -> str:
    """Extract base64 content from a PEM string."""
    lines = pem.strip().splitlines()
    b64 = "".join(line for line in lines if "-----" not in line)
    return b64


def compressed_spki_pem(compressed_point: bytes) -> str:
    algo = AlgorithmIdentifier()
    algo.setComponentByName('algorithm', univ.ObjectIdentifier('1.2.840.10045.2.1'))   # id-ecPublicKey
    algo.setComponentByName('parameters', univ.ObjectIdentifier('1.3.132.0.10')) # prime256v1

    spki = SubjectPublicKeyInfo()
    spki.setComponentByName('algorithm', algo)
    spki.setComponentByName('subjectPublicKey', univ.BitString.fromOctetString(compressed_point))

    der = der_encode(spki)
    b64 = base64.encodebytes(der).decode().replace("\n", "")
    pem = "-----BEGIN PUBLIC KEY-----\n"
    # wrap lines at 64 chars
    pem += "\n".join([b64[i:i+64] for i in range(0, len(b64), 64)])
    pem += "\n-----END PUBLIC KEY-----\n"
    return pem


def extract_pubkey_and_cert(cert_b64: str) -> tuple[str, str, str]:
    """
    Takes ZATCA double-base64 encoded certificate string.
    Returns (public_key_pem, raw_point_base64, certificate_base64)
    - public_key_pem: EC public key in PEM/SPKI format (compressed)
    - certificate_base64: DER-encoded certificate, Base64
    """

    # Step 1: Clean input
    cert_b64 = cert_b64.strip()
    cert_b64 += "=" * (-len(cert_b64) % 4)

    # Step 2: Decode first layer
    der_bytes = base64.b64decode(cert_b64)

    # Step 3: Sometimes ZATCA wraps another base64
    try:
        inner_b64 = der_bytes.decode("ascii").strip()
        inner_b64 += "=" * (-len(inner_b64) % 4)
        der_bytes = base64.b64decode(inner_b64)
    except (UnicodeDecodeError, ValueError):
        pass

    # Step 4: Load certificate
    cert = x509.load_der_x509_certificate(der_bytes)
    pub_key = cert.public_key()
    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        raise ValueError("Expected EC public key in certificate")

    # Uncompressed SPKI (default OpenSSL PEM if no -conv_form flag)
    pubkey_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")

    # Compressed EC point (33 bytes: 0x02/0x03 + X)
    compressed_point = pub_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )

    compressed_pem = compressed_spki_pem(compressed_point)

    b64key = pem_to_base64(compressed_pem)

    # DER certificate re-encoded in base64
    cert_b64_clean = base64.b64encode(der_bytes).decode("ascii")
    signature_b64 = base64.b64encode(cert.signature).decode("ascii")

    return b64key, cert_b64_clean, signature_b64

# Example usage:
#cert = "TUlJQ05EQ0NBZHVnQXdJQkFnSUdBWmpCQkdPVk1Bb0dDQ3FHU000OUJBTUNNQlV4RXpBUkJnTlZCQU1NQ21WSmJuWnZhV05wYm1jd0hoY05NalV3T0RFNU1EWXlPVEF5V2hjTk16QXdPREU0TWpFd01EQXdXakJwTVFzd0NRWURWUVFHRXdKVFFURVNNQkFHQTFVRUNnd0pkR1Z6ZENCeVpYTjBNUk13RVFZRFZRUUxEQW94TWpNME5UWTNPRGs0TVRFd0x3WURWUVFERENoVVUxUXRNbVUxTkdRek0yVXRZalUxTnkwMFpUWTFMVGcyT0dFdFpqTXdOekpoTkRZNU9ETTBNRll3RUFZSEtvWkl6ajBDQVFZRks0RUVBQW9EUWdBRS9saXdKSkNSYXRCVG9kM1JUT2xXd0t0UE1pRG51NWRUQm0xZUNsOVZwekM1NVd0Q0N1OVExSmNyZkkxempob3N1em5OekxWK0hqckJIQVlDNmFkODc2T0J4VENCd2pBTUJnTlZIUk1CQWY4RUFqQUFNSUd4QmdOVkhSRUVnYWt3Z2Fha2dhTXdnYUF4UWpCQUJnTlZCQVFNT1RFdFRXbGpjbTlRVDFOOE1pMHhMakF1TUh3ekxUSmxOVFJrTXpObExXSTFOVGN0TkdVMk5TMDROamhoTFdZek1EY3lZVFEyT1Rnek5ERWZNQjBHQ2dtU0pvbVQ4aXhrQVFFTUR6TXdNVEF4TWpReE5EVXhNREV5TXpFTk1Bc0dBMVVFREF3RU1UQXdNREVWTUJNR0ExVUVHZ3dNZEdWemRDQmhaR1J5WlhOek1STXdFUVlEVlFRUERBcFNaWE4wWVhWeVlXNTBNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJQzN2WnZIRDljT29xbnpFQ0U0cmRLNmd2WDJRUWM3RUJGSHU0Y2xrZGVtakFpQmNmZzBQMlhEQjlVWWQveVRnUFhMdlZNWTlWOXdDRnZydDdvMTJIYnlUZnc9PQ=="


import requests
from typing import TypedDict, List, Dict, Tuple, Union
from dataclasses import dataclass
from xml.sax.saxutils import escape as xml_escape
from datetime import datetime
import hashlib
import base64
import qrcode
from io import BytesIO
import uuid
from lxml import etree
from cert_decoder import extract_pubkey_and_cert
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import xmlsec


# ========== TYPES ==========
class AmountWithCurrency(TypedDict):
    value: str
    currencyID: str


class BinaryObject(TypedDict):
    value: str
    mimeCode: str


class SellerInfo(TypedDict):
    tax_number: str
    company_name: str
    street: str
    building: str
    city: str
    postal_code: str
    country_code: str
    crn: str


class InvoiceLine(TypedDict):
    name: str
    quantity: str
    unit_price: str
    vat_rate: str


def try_get_public_key_bytes(certificate_b64: str):
    """
    Extracts the public key (DER-encoded SubjectPublicKeyInfo) and
    certificate signature bytes from a base64-encoded X.509 certificate.

    Args:
        certificate_b64 (str): Base64-encoded certificate content.

    Returns:
        Tuple[bytes, bytes]: (public_key_bytes, certificate_signature_bytes)
    """
    try:
        # Decode the base64 certificate
        cert_bytes = base64.b64decode(certificate_b64)
        cert = x509.load_der_x509_certificate(cert_bytes, backend=default_backend())

        # Get DER-encoded SubjectPublicKeyInfo
        public_key_bytes = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Get raw signature from the certificate
        certificate_signature = cert.signature

        return public_key_bytes, certificate_signature

    except Exception as e:
        raise ValueError(f"[Error] Invalid Certificate: {e}")


# ========== CORE CLASS ==========
class ZatcaSimplifiedInvoice:
    def __init__(self, seller: SellerInfo, cert: str, priv_key: bytes):
        self.seller = seller
        self.cert = cert
        self.priv_key = priv_key  # PEM private key

        self.ns = {
            'invoice': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
            'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
            'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
            'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
            'ds': 'http://www.w3.org/2000/09/xmldsig#',
            'xades': 'http://uri.etsi.org/01903/v1.3.2#'
        }

    def sign_invoice_hash(self, invoice_hash: bytes) -> str:
        """
        Sign a 32-byte SHA-256 invoice hash (passed as hex) with ECDSA using secp256k1.
        Returns base64-encoded signature for ZATCA QR code (Tag 7).
        """

        # Load private key (DER PKCS8, base64-encoded)
        priv_key = serialization.load_pem_private_key(self.priv_key, password=None)

        # Sign the raw hash (already SHA-256)
        signature_bytes = priv_key.sign(
            invoice_hash,
            ec.ECDSA(hashes.SHA256())
        )

        return base64.b64encode(signature_bytes).decode()

    # --------- PHASE 2 SIGNING ---------
    from cryptography.hazmat.primitives import serialization

    def retrieve_public_key(self):
        # self.priv_key is a PEM string like:
        # -----BEGIN EC PRIVATE KEY-----
        # MHQCAQEEIGg466VhfqEocptd...
        # -----END EC PRIVATE KEY-----

        # Convert string to bytes
        priv_key_pem = self.priv_key.encode()

        # Load the private key from PEM
        priv_key = serialization.load_pem_private_key(priv_key_pem, password=None)

        # Derive the public key
        pub_key = priv_key.public_key()

        # Export public key as DER-encoded SubjectPublicKeyInfo (X.509)
        pub_key_der = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Base64 encode (this gives the "MFY…" format you want for QR)
        pub_key_b64 = base64.b64encode(pub_key_der).decode()

        return pub_key_b64

    def _canonicalize_xml(self, xml_bytes: str) -> bytes:
        import io
        parser = etree.XMLParser(remove_blank_text=True)
        root = etree.fromstring(xml_bytes.encode("utf-8"), parser)
        buf = io.BytesIO()
        # exclusive=False → Canonical XML 1.1
        root.getroottree().write_c14n(buf, exclusive=False, with_comments=False)
        return buf.getvalue()

    def get_signed_properties_hash(self, signingTime, digestValue, x509IssuerName, x509SerialNumber) -> str:
        xmlString = f"""<xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="xadesSignedProperties">
                            <xades:SignedSignatureProperties>
                                <xades:SigningTime>{signingTime}</xades:SigningTime>
                                <xades:SigningCertificate>
                                    <xades:Cert>
                                        <xades:CertDigest>
                                            <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                            <ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{digestValue}</ds:DigestValue>
                                        </xades:CertDigest>
                                        <xades:IssuerSerial>
                                            <ds:X509IssuerName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{x509IssuerName}</ds:X509IssuerName>
                                            <ds:X509SerialNumber xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{x509SerialNumber}</ds:X509SerialNumber>
                                        </xades:IssuerSerial>
                                    </xades:Cert>
                                </xades:SigningCertificate>
                            </xades:SignedSignatureProperties>
                        </xades:SignedProperties>""".replace("\r\n", "\n").strip()

        # Step 1: Hash XML string (UTF-8)
        hash_bytes = hashlib.sha256(xmlString.encode("utf-8")).digest()

        # Step 2: Convert to lowercase hex string
        hash_hex = hash_bytes.hex()

        # Step 3: Base64 encode the UTF-8 bytes of that hex string
        return base64.b64encode(hash_hex.encode("utf-8")).decode("utf-8")

    def _generate_signed_extensions(self, invoice_hash: str, signature_value: str, invoice_date: datetime) -> str:
        """
        Generate ZATCA-compliant UBL signature block with XAdES,
        fully using dynamically generated SignedProperties.
        """
        UBL_INVOICE_TEMPLATE = """
        <ext:UBLExtensions xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
                           xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
                           xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2">
                <ext:UBLExtension>
                    <ext:ExtensionURI>urn:oasis:names:specification:ubl:dsig:enveloped:xades</ext:ExtensionURI>
                    <ext:ExtensionContent>
                        <sig:UBLDocumentSignatures 
                            xmlns:sig="urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2"
                            xmlns:sac="urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2"
                            xmlns:sbc="urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2">

                            <sac:SignatureInformation>
                                <cbc:ID>{signature_id}</cbc:ID>
                                <sbc:ReferencedSignatureID>{referenced_signature_id}</sbc:ReferencedSignatureID>
                                <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="signature">
                                    <ds:SignedInfo>
                                        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                                        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
                                        <ds:Reference Id="invoiceSignedData" URI="">
                                            <ds:Transforms>
                                                <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                                                    <ds:XPath>not(//ancestor-or-self::ext:UBLExtensions)</ds:XPath>
                                                </ds:Transform>
                                                <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                                                    <ds:XPath>not(//ancestor-or-self::cac:Signature)</ds:XPath>
                                                </ds:Transform>
                                                <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                                                    <ds:XPath>not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])</ds:XPath>
                                                </ds:Transform>
                                                <ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                                            </ds:Transforms>
                                            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                            <ds:DigestValue>{invoice_digest}</ds:DigestValue>
                                        </ds:Reference>
                                        <ds:Reference Type="http://www.w3.org/2000/09/xmldsig#SignatureProperties" URI="#xadesSignedProperties">
                                            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                            <ds:DigestValue>{signed_props_digest}</ds:DigestValue>
                                        </ds:Reference>
                                    </ds:SignedInfo>

                                    <ds:SignatureValue>{signature_value}</ds:SignatureValue>
                                    <ds:KeyInfo>
                                        <ds:X509Data>
                                            <ds:X509Certificate>{certificate}</ds:X509Certificate>
                                        </ds:X509Data>
                                    </ds:KeyInfo>

                                    <ds:Object>
                                        <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="signature">
                                            <xades:SignedProperties Id="xadesSignedProperties">
                                                <xades:SignedSignatureProperties>
                                                    <xades:SigningTime>{signing_time}</xades:SigningTime>
                                                    <xades:SigningCertificate>
                                                        <xades:Cert>
                                                            <xades:CertDigest>
                                                                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                                                <ds:DigestValue>{cert_digest}</ds:DigestValue>
                                                            </xades:CertDigest>
                                                            <xades:IssuerSerial>
                                                                <ds:X509IssuerName>{issuer_name}</ds:X509IssuerName>
                                                                <ds:X509SerialNumber>{issuer_serial}</ds:X509SerialNumber>
                                                            </xades:IssuerSerial>
                                                        </xades:Cert>
                                                    </xades:SigningCertificate>
                                                </xades:SignedSignatureProperties>
                                            </xades:SignedProperties>
                                        </xades:QualifyingProperties>
                                    </ds:Object>
                                </ds:Signature>
                            </sac:SignatureInformation>
                        </sig:UBLDocumentSignatures>
                    </ext:ExtensionContent>
                </ext:UBLExtension>
            </ext:UBLExtensions>
        """

        cert_der = base64.b64decode(self.cert)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        digest_bytes = hashlib.sha256(cert_der).digest()
        digest_b64 = base64.b64encode(digest_bytes).decode()

        # 2. Issuer Name
        issuer_name = cert.issuer.rfc4514_string()  # e.g., "CN=..., O=..., C=..."

        # 3. Serial Number
        serial_number = str(cert.serial_number)  # decimal string

        signingTime = invoice_date.strftime("%Y-%m-%dT%H:%M:%S")
        signed_props_digest = self.get_signed_properties_hash(signingTime, invoice_hash, issuer_name, serial_number)

        return UBL_INVOICE_TEMPLATE.format(
            signature_id="urn:oasis:names:specification:ubl:signature:1",
            referenced_signature_id="urn:oasis:names:specification:ubl:signature:Invoice",
            invoice_digest=invoice_hash,
            signed_props_digest=signed_props_digest,
            signature_value=signature_value,
            certificate=self.cert,  # truncated
            signing_time=signingTime,
            cert_digest=digest_b64,
            issuer_name=issuer_name,
            issuer_serial=serial_number
        )

    def remove_tags(self, xml: str) -> str:
        root = etree.fromstring(xml.encode("utf-8"))

        # Collect namespaces
        nsmap = root.nsmap.copy()
        if None in nsmap:  # default namespace
            nsmap['ns'] = nsmap.pop(None)

        # Remove <UBLExtensions>
        for elem in root.xpath('//ns:UBLExtensions', namespaces=nsmap):
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)

        # Remove QR document reference
        for elem in root.xpath('//ns:AdditionalDocumentReference[ns:ID="QR"]', namespaces=nsmap):
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)

        # Remove <Signature>
        for elem in root.xpath('//ns:Signature', namespaces=nsmap):
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)

        return etree.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")

    def _remove_tags(self, xml: str) -> str:
        root = etree.fromstring(xml.encode("utf-8"))

        nsmap = root.nsmap.copy()
        if None in nsmap:
            nsmap['ns'] = nsmap.pop(None)

        for elem in root.xpath('//ns:UBLExtensions', namespaces=nsmap):
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)

        for elem in root.xpath('//ns:AdditionalDocumentReference[ns:ID="QR"]', namespaces=nsmap):
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)

        for elem in root.xpath('//ns:Signature', namespaces=nsmap):
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)

        # Serialize without declaration
        xml_str = etree.tostring(root, encoding="utf-8", xml_declaration=False).decode("utf-8")

        # Double-safety: remove any leftover xml declaration manually
        if xml_str.lstrip().startswith("<?xml"):
            xml_str = xml_str.split("?>", 1)[1].lstrip()

        return xml_str

    # --------- INVOICE GENERATION ---------
    def generate(self,
                 invoice_number: str,
                 invoice_date: datetime,
                 lines: List[InvoiceLine],
                 previous_invoice_hash: str = "") -> Tuple[str, str, str]:

        totals = self._calculate_totals(lines)
        invoice_uuid = str(uuid.uuid4())

        invoice_date = invoice_date.replace(microsecond=0)

        # Step 1: Build initial XML (placeholders for QR & PIH)
        xml_template = self._build_xml(
            invoice_number=invoice_number,
            invoice_date=invoice_date,
            lines=lines,
            totals=totals,
            qr_code="",  # placeholder
            pih="",  # placeholder
            previous_invoice_hash=previous_invoice_hash,
            invoice_uuid=invoice_uuid
        )

        cleaned_xml = self._remove_tags(xml_template)

        with open('invoice.xml', "w+") as f:
            f.write(cleaned_xml)

        # Step 2: Canonicalize the XML
        canonicalized_xml = self._canonicalize_xml(cleaned_xml)

        # Step 3: Compute the hash from canonicalized XML
        invoice_hash = hashlib.sha256(canonicalized_xml).digest()  # invoice hash raw #1

        invoice_hash_b64 = base64.b64encode(invoice_hash).decode()

        # Step 4: Sign the hash
        signature_value = self.sign_invoice_hash(invoice_hash)  # digital signature #2

        print('SIGNATURE VALUE: ', signature_value)

        signed_extensions = self._generate_signed_extensions(invoice_hash_b64, signature_value, invoice_date)

        # Step 5: Generate QR code using the invoice hash and signature
        qr_data = self._generate_qr_tlv_binary(
            seller_name=self.seller['company_name'],
            tax_number=self.seller['tax_number'],
            invoice_date=invoice_date,
            total_with_vat=totals['payable_amount'],
            vat_amount=totals['vat_amount'],
            invoice_hash=invoice_hash_b64,
            signature_value=signature_value
        )
        # qr_base64 = self._generate_qr_code(qr_data)
        qr_base64 = base64.b64encode(qr_data).decode("utf-8")

        # Step 7: Insert QR and PIH into XML
        xml_with_qr_pih = self.insert_signature_qr(cleaned_xml, signed_extensions, qr_base64)

        # Step 9: Insert signed extensions at the proper location
        final_xml = xml_with_qr_pih

        # Return final XML and hash that matches it
        return final_xml, invoice_uuid, invoice_hash_b64

    # --------- HELPERS ---------
    def insert_qr_pih(self, xml, pih, qr64):
        pass

    def _calculate_totals(self, lines: List[InvoiceLine]) -> Dict:
        total_excl_vat = 0.0
        vat_amount = 0.0
        vat_breakdown = {}  # key: vat_rate, value: {'taxable_amount': x, 'tax_amount': y}

        for line in lines:
            quantity = float(line['quantity'])
            unit_price = float(line['unit_price'])
            rate = float(line['vat_rate'])
            line_total = quantity * unit_price
            line_vat = line_total * rate / 100

            total_excl_vat += line_total
            vat_amount += line_vat

            # aggregate per VAT rate
            if rate not in vat_breakdown:
                vat_breakdown[rate] = {'taxable_amount': 0.0, 'tax_amount': 0.0, 'percent': rate}
            vat_breakdown[rate]['taxable_amount'] += line_total
            vat_breakdown[rate]['tax_amount'] += line_vat

        # convert values to strings with 2 decimals
        vat_list = [
            {
                'taxable_amount': f"{v['taxable_amount']:.2f}",
                'tax_amount': f"{v['tax_amount']:.2f}",
                'percent': v['percent']
            }
            for v in vat_breakdown.values()
        ]

        return {
            'total_excl_vat': f"{total_excl_vat:.2f}",
            'vat_amount': f"{vat_amount:.2f}",
            'payable_amount': f"{total_excl_vat + vat_amount:.2f}",
            'vat_breakdown': vat_list
        }

    def _generate_uuid(self, invoice_number: str, invoice_date: datetime) -> str:
        unix_timestamp = int(invoice_date.timestamp())
        return f"{self.seller['tax_number']}_{unix_timestamp}_{invoice_number}"

    def _generate_qr_tlv_binary(self, seller_name: str, tax_number: str, invoice_date: datetime,
                                total_with_vat: str, vat_amount: str,
                                invoice_hash: str, signature_value: str) -> bytes:
        """Generate ZATCA-compliant QR TLV binary data with robust debugging"""
        date_str = invoice_date.strftime('%Y-%m-%dT%H:%M:%S')

        def decode_tlv(data: bytes) -> dict:
            """Helper to decode TLV for debugging"""
            result = {}
            i = 0
            while i < len(data):
                try:
                    tag = data[i]
                    length = data[i + 1]
                    value_bytes = data[i + 2:i + 2 + length]

                    # Try UTF-8 decoding for text fields, show hex for binary
                    try:
                        value = value_bytes.decode('utf-8')
                        if len(value) > 50:
                            value = f"{value[:50]}... (truncated)"
                    except UnicodeDecodeError:
                        value = f"<binary data: {value_bytes.hex()[:50]}...>"

                    result[tag] = {
                        'length': length,
                        'value': value,
                        'raw_length': len(value_bytes)
                    }
                    i += 2 + length
                except IndexError:
                    break
            return result

        def encode_tlv(tag: int, value: Union[str, bytes]) -> bytes:
            """Safe TLV encoder with detailed error reporting"""
            try:
                if isinstance(value, str):
                    value_bytes = value.encode('utf-8')
                else:
                    value_bytes = value

                length = len(value_bytes)

                if length > 255:
                    print(f"\n⚠️ VALUE TOO LARGE FOR TAG {tag}:")
                    print(f"Length: {length} bytes (max 255 allowed)")
                    raise ValueError(f"Value for tag {tag} exceeds 255 bytes (got {length})")

                if length > 200:  # Warn for large values
                    print(f"⚠️ Large value for tag {tag}: {length} bytes")

                return bytes([tag]) + bytes([length]) + value_bytes
            except Exception as e:
                print(f"\n🔥 ERROR ENCODING TAG {tag}:")
                print(f"Type: {type(value)}")
                if isinstance(value, str):
                    print(f"String length: {len(value)}")
                else:
                    print(f"Bytes length: {len(value)}")
                raise

        try:
            cert_der = base64.b64decode(self.cert)
            certificate = x509.load_der_x509_certificate(cert_der, default_backend())

            public_key_der = certificate.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # This is the actual signature (hex bytes)
            signature_bytes = certificate.signature


            # Generate TLV parts with debugging
            tlv_parts = []
            for tag, value in [
                (1, seller_name),
                (2, tax_number),
                (3, date_str),
                (4, total_with_vat),
                (5, vat_amount),
                (6, invoice_hash),
                (7, signature_value),
                (8, public_key_der),
                (9, signature_bytes)
            ]:
                try:
                    part = encode_tlv(tag, value)
                    tlv_parts.append(part)
                    #print(f"✅ Encoded tag {tag}: {len(part)} bytes total")
                except Exception as e:
                    print(f"\n❌ FAILED TO ENCODE TAG {tag}:")
                    print(f"Value type: {type(value)}")
                    if isinstance(value, str):
                        print(f"String length: {len(value)} chars")
                        print(f"UTF-8 bytes: {len(value.encode('utf-8'))}")
                    else:
                        print(f"Bytes length: {len(value)}")
                    raise


            qr_data = b''.join(tlv_parts)
            total_size = len(qr_data)

            print("\n=== FINAL QR CODE ANALYSIS ===")
            print(f"Total QR size: {total_size} bytes")

            return qr_data
            """
            decoded = decode_tlv(qr_data)
            for tag, info in decoded.items():
                print(f"Tag {tag}: {info['length']} bytes (raw: {info['raw_length']}) - {info['value']}")

            if total_size > 500:
                print("\n⚠️ WARNING: QR code exceeds recommended 500 bytes")
                oversize = total_size - 500
                print(f"Exceeds by: {oversize} bytes")
                print("Consider reducing certificate or other field sizes")

            if total_size > 1000:
                print("\n❌ ERROR: QR code exceeds maximum 1000 bytes")
                raise ValueError(f"QR code too large: {total_size} bytes")
            """

        except Exception as e:
            print("\n=== DEBUGGING INFORMATION ===")
            print("Certificate content (first 200 chars):")
            print(self.cert[:200])
            raise

    def get_digital_signature(self, xml_hash_b64: str) -> str:
        """
        Signs a base64-encoded invoice hash using the secp256k1 private key.
        Returns the signature as base64 string.
        """
        # Step 1: Decode the base64 invoice hash
        invoice_hash_bytes = base64.b64decode(xml_hash_b64)

        # Step 2: Load private key
        priv_key_pem = self.priv_key.strip()
        if not priv_key_pem.startswith("-----BEGIN EC PRIVATE KEY-----"):
            priv_key_pem = "-----BEGIN EC PRIVATE KEY-----\n" + priv_key_pem + "\n-----END EC PRIVATE KEY-----\n"

        priv_key_base64 = self.priv_key

        # Decode your base64 string
        priv_key_bytes = base64.b64decode(priv_key_base64)

        # Load EC private key (assuming PKCS8 DER format)
        priv_key = serialization.load_der_private_key(
            priv_key_bytes,
            password=None
        )

        # Step 3: Sign the hash using ECDSA with SHA-256
        signature = priv_key.sign(
            invoice_hash_bytes,
            ec.ECDSA(hashes.SHA256())
        )

        # Step 4: Return Base64-encoded signature
        return base64.b64encode(signature).decode("utf-8")

    def _generate_qr_code(self, tlv_data: bytes) -> str:
        """Generate QR code from raw TLV binary"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=4,
            border=2
        )
        qr.add_data(tlv_data)
        qr.make(fit=True)

        buffered = BytesIO()
        qr.make_image().save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode('utf-8')

    def _generate_pih(self, totals: Dict, tlv_binary: bytes) -> str:
        """Generate PIH using raw TLV bytes."""
        hash_input = (
                             self.seller['tax_number'] +
                             totals['total_excl_vat'] +
                             totals['vat_amount'] +
                             totals['payable_amount']
                     ).encode('utf-8') + tlv_binary
        return base64.b64encode(hashlib.sha256(hash_input).digest()).decode('utf-8')

    def insert_signature_qr(self, invoice_xml: str, signed_extensions: str, qr64: str) -> str:
        from lxml import etree

        parser = etree.XMLParser(remove_blank_text=True, ns_clean=True)
        root = etree.fromstring(invoice_xml.encode("utf-8"), parser)

        nsmap = root.nsmap.copy()
        if None in nsmap:
            nsmap['inv'] = nsmap.pop(None)

        EXT_NS = nsmap.get('ext')
        CAC_NS = nsmap.get('cac')
        CBC_NS = nsmap.get('cbc')

        # 1. Ensure <ext:UBLExtensions> exists and insert signed extensions
        ubl_extensions_elem = root.find('.//ext:UBLExtensions', namespaces=nsmap)
        if ubl_extensions_elem is None:
            ubl_extensions_elem = etree.Element(f"{{{EXT_NS}}}UBLExtensions")
            root.insert(0, ubl_extensions_elem)

        ubl_extensions_elem.clear()
        wrapper_xml = f"""<wrapper xmlns:ext="{EXT_NS}" xmlns:cbc="{CBC_NS}" xmlns:cac="{CAC_NS}">
            {signed_extensions}
        </wrapper>"""
        wrapper_root = etree.fromstring(wrapper_xml.encode('utf-8'))
        signed_ext_elem = wrapper_root[0]
        for child in signed_ext_elem:
            ubl_extensions_elem.append(child)

        # 2. Create and insert QR code
        qr_node = etree.Element(f"{{{CAC_NS}}}AdditionalDocumentReference")
        id_elem = etree.SubElement(qr_node, f"{{{CBC_NS}}}ID")
        id_elem.text = "QR"
        attachment = etree.SubElement(qr_node, f"{{{CAC_NS}}}Attachment")
        emb_doc = etree.SubElement(
            attachment,
            f"{{{CBC_NS}}}EmbeddedDocumentBinaryObject",
            mimeCode="text/plain"
        )
        emb_doc.text = qr64

        additional_doc_refs = root.findall('.//cac:AdditionalDocumentReference', namespaces=nsmap)

        pih_node = None
        for doc_ref in additional_doc_refs:
            # Find the ID element within this AdditionalDocumentReference
            id_elem = doc_ref.find('cbc:ID', namespaces=nsmap)
            if id_elem is not None and id_elem.text == "PIH":
                pih_node = doc_ref

        if pih_node is not None:
            parent = pih_node.getparent()
            index = parent.index(pih_node)
            parent.insert(index + 1, qr_node)
        else:
            root.append(qr_node)

        # 3. Create and insert minimal signature after QR
        minimal_signature = etree.Element(f"{{{CAC_NS}}}Signature")
        id_sig = etree.SubElement(minimal_signature, f"{{{CBC_NS}}}ID")
        id_sig.text = "urn:oasis:names:specification:ubl:signature:Invoice"
        sig_method = etree.SubElement(minimal_signature, f"{{{CBC_NS}}}SignatureMethod")
        sig_method.text = "urn:oasis:names:specification:ubl:dsig:enveloped:xades"

        # Insert minimal signature after QR node
        parent = qr_node.getparent()
        index = parent.index(qr_node)
        parent.insert(index + 1, minimal_signature)

        return etree.tostring(
            root,
            pretty_print=True,
            encoding="utf-8",
            xml_declaration=True
        ).decode('utf-8')
    def _build_xml(self,
                   invoice_number: str,
                   invoice_date: datetime,
                   lines: List[InvoiceLine],
                   totals: Dict,
                   qr_code: str,
                   pih: str,
                   previous_invoice_hash: str,
                   invoice_uuid: str) -> str:

        # ASSUMING VAT RATE IS 15%, it is hardcoded under TaxTotal, Tax Category

        issue_date = invoice_date.strftime("%Y-%m-%d")
        issue_time = invoice_date.strftime("%H:%M:%S")

        xml_template = f"""<?xml version="1.0" encoding="UTF-8"?>
        <Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"><ext:UBLExtensions></ext:UBLExtensions>
            <cbc:ProfileID>reporting:1.0</cbc:ProfileID>
            <cbc:ID>{invoice_number}</cbc:ID>
            <cbc:UUID>{invoice_uuid}</cbc:UUID>
            <cbc:IssueDate>{issue_date}</cbc:IssueDate>
            <cbc:IssueTime>{issue_time}</cbc:IssueTime>
            <cbc:InvoiceTypeCode name="020000000">388</cbc:InvoiceTypeCode>
            <cbc:DocumentCurrencyCode>SAR</cbc:DocumentCurrencyCode>
            <cbc:TaxCurrencyCode>SAR</cbc:TaxCurrencyCode>
            <cac:AdditionalDocumentReference>
                <cbc:ID>ICV</cbc:ID>
                <cbc:UUID>1</cbc:UUID>
            </cac:AdditionalDocumentReference>
            <cac:AdditionalDocumentReference>
                <cbc:ID>PIH</cbc:ID>
                <cac:Attachment>
                    <cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN7ZiNTdlOQ==</cbc:EmbeddedDocumentBinaryObject>
                </cac:Attachment>
            </cac:AdditionalDocumentReference>
            <cac:AccountingSupplierParty>
                <cac:Party>
                    <cac:PartyIdentification>
                        <cbc:ID schemeID="CRN">{self.seller['crn']}</cbc:ID>
                    </cac:PartyIdentification>
                    <cac:PostalAddress>
                        <cbc:StreetName>{self.seller['street']}</cbc:StreetName>
                        <cbc:BuildingNumber>{self.seller['building'].zfill(4)}</cbc:BuildingNumber>
                        <cbc:CityName>{self.seller['city']}</cbc:CityName>
                        <cbc:PostalZone>{self.seller['postal_code']}</cbc:PostalZone>
                        <cac:Country>
                            <cbc:IdentificationCode>{self.seller['country_code']}</cbc:IdentificationCode>
                        </cac:Country>
                    </cac:PostalAddress>
                    <cac:PartyTaxScheme>
                        <cbc:CompanyID>{self.seller['tax_number']}</cbc:CompanyID>
                        <cac:TaxScheme>
                            <cbc:ID>VAT</cbc:ID>
                        </cac:TaxScheme>
                    </cac:PartyTaxScheme>
                    <cac:PartyLegalEntity>
                        <cbc:RegistrationName>{self.seller['company_name']}</cbc:RegistrationName>
                    </cac:PartyLegalEntity>
                </cac:Party>
            </cac:AccountingSupplierParty>
            <cac:AccountingCustomerParty>
                <cac:Party>
                    <cac:PartyIdentification>
                        <cbc:ID schemeID="NAT">SA</cbc:ID>
                    </cac:PartyIdentification>
                </cac:Party>
            </cac:AccountingCustomerParty>
            <cac:TaxTotal>
                <cbc:TaxAmount currencyID="SAR">{totals['vat_amount']}</cbc:TaxAmount>
                <cac:TaxSubtotal>
                    <cbc:TaxableAmount currencyID="SAR">{totals['total_excl_vat']}</cbc:TaxableAmount>
                    <cbc:TaxAmount currencyID="SAR">{totals['vat_amount']}</cbc:TaxAmount>
                    <cac:TaxCategory>
                        <cbc:ID>S</cbc:ID>
                        <cbc:Percent>15</cbc:Percent>
                        <cac:TaxScheme>
                            <cbc:ID>VAT</cbc:ID>
                        </cac:TaxScheme>
                    </cac:TaxCategory>
                </cac:TaxSubtotal>
            </cac:TaxTotal>
            <cac:LegalMonetaryTotal>
                <cbc:TaxExclusiveAmount currencyID="SAR">{totals['total_excl_vat']}</cbc:TaxExclusiveAmount>
                <cbc:TaxInclusiveAmount currencyID="SAR">{totals['payable_amount']}</cbc:TaxInclusiveAmount>
                <cbc:PayableAmount currencyID="SAR">{totals['payable_amount']}</cbc:PayableAmount>
            </cac:LegalMonetaryTotal>
            {self._build_invoice_lines(lines)}
        </Invoice>
        """
        return xml_template

    def _build_invoice_lines(self, lines: List[InvoiceLine]) -> str:
        invoice_lines_xml = ""
        for idx, line in enumerate(lines, start=1):
            line_total = float(line['unit_price']) * float(line['quantity'])
            line_vat = line_total * (float(line['vat_rate']) / 100)

            invoice_lines_xml += f"""<cac:InvoiceLine>
                    <cbc:ID>{idx}</cbc:ID>
                    <cbc:InvoicedQuantity unitCode="{xml_escape(line.get('unit_code', 'PCE'))}">{line['quantity']}</cbc:InvoicedQuantity>
                    <cbc:LineExtensionAmount currencyID="SAR">{line_total:.2f}</cbc:LineExtensionAmount>
                    <cac:TaxTotal>
                        <cbc:TaxAmount currencyID="SAR">{line_vat:.2f}</cbc:TaxAmount>
                    </cac:TaxTotal>
                    <cac:Item>
                        <cbc:Name>{xml_escape(line['name'])}</cbc:Name>
                        <cac:ClassifiedTaxCategory>
                            <cbc:ID>S</cbc:ID>
                            <cbc:Percent>{line['vat_rate']}</cbc:Percent>
                            <cac:TaxScheme>
                                <cbc:ID>VAT</cbc:ID>
                            </cac:TaxScheme>
                        </cac:ClassifiedTaxCategory>
                    </cac:Item>
                    <cac:Price>
                        <cbc:PriceAmount currencyID="SAR">{line['unit_price']}</cbc:PriceAmount>
                    </cac:Price>
                </cac:InvoiceLine>
                """
        return invoice_lines_xml


def main():
    seller_info = {
        'tax_number': "310000000000093",
        'company_name': "My Store",
        'street': "Main Street",
        'building': "123",
        'city': "Riyadh",
        'postal_code': "12345",
        'country_code': "SA",
        "crn": "1010010000"
    }

    cert = "TUlJQ05EQ0NBZHVnQXdJQkFnSUdBWmpIUGR1bk1Bb0dDQ3FHU000OUJBTUNNQlV4RXpBUkJnTlZCQU1NQ21WSmJuWnZhV05wYm1jd0hoY05NalV3T0RJd01URXlPVE14V2hjTk16QXdPREU1TWpFd01EQXdXakJwTVFzd0NRWURWUVFHRXdKVFFURVNNQkFHQTFVRUNnd0pkR1Z6ZENCeVpYTjBNUk13RVFZRFZRUUxEQW94TWpNME5UWTNPRGs0TVRFd0x3WURWUVFERENoVVUxUXRNekpoT1RsbU9ESXROamt3TlMwME5UUmhMVGxoTXpBdFl6bGpNbUZpWkRrNE56STNNRll3RUFZSEtvWkl6ajBDQVFZRks0RUVBQW9EUWdBRUdRNlpsZDlmTVBsZjFEQXNhT01iUHIyWnBrQ2RSc1ZkQ29sU29CT1NSTlc3NVdFMSs0Vy9DQThMbE9ZTlJJSlZ4ZGs3Q0lDanprcU5mVE9VenJvMi82T0J4VENCd2pBTUJnTlZIUk1CQWY4RUFqQUFNSUd4QmdOVkhSRUVnYWt3Z2Fha2dhTXdnYUF4UWpCQUJnTlZCQVFNT1RFdFRXbGpjbTlRVDFOOE1pMHhMakF1TUh3ekxUTXlZVGs1WmpneUxUWTVNRFV0TkRVMFlTMDVZVE13TFdNNVl6SmhZbVE1T0RjeU56RWZNQjBHQ2dtU0pvbVQ4aXhrQVFFTUR6TXdNVEF4TWpReE5EVXhNREV5TXpFTk1Bc0dBMVVFREF3RU1UQXdNREVWTUJNR0ExVUVHZ3dNZEdWemRDQmhaR1J5WlhOek1STXdFUVlEVlFRUERBcFNaWE4wWVhWeVlXNTBNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJQ3lHSkZhcm1xdUVoRW9DbTI5dGp2d1hIeGFNM3AwU0FxTlRxajFFWEFBS0FpQjRXUzFyQVN2MUtQcitLSE50UHdpTTMyQ2E0dHdFS2FoR1ZVVzRhVjZsVWc9PQ=="
    cert_b64 = base64.b64decode(cert).decode('ascii')

    priv_key = b"""-----BEGIN EC PRIVATE KEY-----
            MHQCAQEEIGg466VhfqEocptdwQKMJup8+JuypJMz43moYwrT6fquoAcGBSuBBAAK
            oUQDQgAEGQ6Zld9fMPlf1DAsaOMbPr2ZpkCdRsVdColSoBOSRNW75WE1+4W/CA8L
            lOYNRIJVxdk7CICjzkqNfTOUzro2/w==
            -----END EC PRIVATE KEY-----"""

    generator = ZatcaSimplifiedInvoice(seller_info, priv_key=priv_key, cert=cert_b64)
    invoice_lines = [
        {'name': "Product 1", 'quantity': "2", 'unit_price': "100.00", 'vat_rate': "15"},
        {'name': "Product 2", 'quantity': "1", 'unit_price': "50.00", 'vat_rate': "15"}
    ]

    xml_invoice, uuid, invoice_hash = generator.generate(
        invoice_number="SME00023",
        invoice_date=datetime.now(),
        lines=invoice_lines
    )

    with open("zatca_simplified_invoice.xml", "w", encoding="utf-8") as f:
        f.write(xml_invoice)

    print("Simplified e-Invoice generated successfully!")

    with open("zatca_simplified_invoice.xml", "rb") as f:
        xml_bytes = f.read().strip()
    encoded_invoice = base64.b64encode(xml_bytes).decode("utf-8")

    from invoice_compliance import check_invoice_compliance
    bst = "TUlJQ05EQ0NBZHVnQXdJQkFnSUdBWmpIUGR1bk1Bb0dDQ3FHU000OUJBTUNNQlV4RXpBUkJnTlZCQU1NQ21WSmJuWnZhV05wYm1jd0hoY05NalV3T0RJd01URXlPVE14V2hjTk16QXdPREU1TWpFd01EQXdXakJwTVFzd0NRWURWUVFHRXdKVFFURVNNQkFHQTFVRUNnd0pkR1Z6ZENCeVpYTjBNUk13RVFZRFZRUUxEQW94TWpNME5UWTNPRGs0TVRFd0x3WURWUVFERENoVVUxUXRNekpoT1RsbU9ESXROamt3TlMwME5UUmhMVGxoTXpBdFl6bGpNbUZpWkRrNE56STNNRll3RUFZSEtvWkl6ajBDQVFZRks0RUVBQW9EUWdBRUdRNlpsZDlmTVBsZjFEQXNhT01iUHIyWnBrQ2RSc1ZkQ29sU29CT1NSTlc3NVdFMSs0Vy9DQThMbE9ZTlJJSlZ4ZGs3Q0lDanprcU5mVE9VenJvMi82T0J4VENCd2pBTUJnTlZIUk1CQWY4RUFqQUFNSUd4QmdOVkhSRUVnYWt3Z2Fha2dhTXdnYUF4UWpCQUJnTlZCQVFNT1RFdFRXbGpjbTlRVDFOOE1pMHhMakF1TUh3ekxUTXlZVGs1WmpneUxUWTVNRFV0TkRVMFlTMDVZVE13TFdNNVl6SmhZbVE1T0RjeU56RWZNQjBHQ2dtU0pvbVQ4aXhrQVFFTUR6TXdNVEF4TWpReE5EVXhNREV5TXpFTk1Bc0dBMVVFREF3RU1UQXdNREVWTUJNR0ExVUVHZ3dNZEdWemRDQmhaR1J5WlhOek1STXdFUVlEVlFRUERBcFNaWE4wWVhWeVlXNTBNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJQ3lHSkZhcm1xdUVoRW9DbTI5dGp2d1hIeGFNM3AwU0FxTlRxajFFWEFBS0FpQjRXUzFyQVN2MUtQcitLSE50UHdpTTMyQ2E0dHdFS2FoR1ZVVzRhVjZsVWc9PQ=="
    sec = "5N73gCs++AE57F/Kvbbl/cAST/EpCJbzCkUPMyc9A88="
    check_invoice_compliance(invoice_hash, uuid, encoded_invoice, bst, sec)

    with open("e-invoice.txt", "w+") as f:
        f.write(encoded_invoice)

    print("Invoice hash value: ", invoice_hash)
    print(uuid)


# ========== USAGE EXAMPLE ==========
if __name__ == "__main__":
    main()
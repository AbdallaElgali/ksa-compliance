from typing import TypedDict, List, Dict, Tuple, Union
from xml.sax.saxutils import escape as xml_escape
from datetime import datetime
import hashlib
import base64
import qrcode
import uuid
from lxml import etree
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import io
import os

current_dir = os.getcwd()
XSL_FILE = f"{current_dir}\\invoice_utils\\Resources\\transform.xsl"
#XSL_FILE = f"{current_dir}\\Resources\\transform.xsl"


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
    def _canonicalize_xml(self, transformed_xml: str) -> str:
        """ Canonicalize the transformed XML. Returning the canonical xml string."""
        return etree.tostring(transformed_xml, method='c14n').decode('utf-8')

    def get_signed_properties_hash(self, signingTime, digestValue, x509IssuerName, x509SerialNumber) -> str:
        # Construct the XML string with exactly 36 spaces in front of <xades:SignedSignatureProperties>
        xml_string = f"""<xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="xadesSignedProperties">
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
                                        </xades:SignedProperties>"""

        print('SignedProperties xml: ', xml_string)

        # Clean up the XML string (normalize newlines and trim extra spaces)
        xml_string = xml_string.replace("\r\n", "\n").strip()
        # Generate the SHA256 hash of the XML string in binary format
        hash_bytes = hashlib.sha256(xml_string.encode('utf-8')).digest()

        # Convert the hash to hex and then base64 encode the result
        hash_hex = hash_bytes.hex()
        return base64.b64encode(hash_hex.encode('utf-8')).decode('utf-8')

    def _generate_signed_extensions(self, invoice_hash: str, signature_value: str, invoice_date: datetime) -> str:
        # Build UBL template but *leave a marker* where SignedProperties XML will be injected.
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
                                    <!-- use exclusive c14n consistently -->
                                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                                    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                                    <ds:Reference Id="invoiceSignedData" URI="">
                                        <ds:Transforms>
                                            <!-- keep your xpath filters -->
                                            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                                        </ds:Transforms>
                                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                        <ds:DigestValue>{invoice_digest}</ds:DigestValue>
                                    </ds:Reference>
                                    <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#xadesSignedProperties">
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
                                                <xades:SigningTime>{SIGNATURE_TIMESTAMP}</xades:SigningTime>
                                                <xades:SigningCertificate>
                                                    <xades:Cert>
                                                        <xades:CertDigest>
                                                            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                                            <ds:DigestValue>{PUBLICKEY_HASHING}</ds:DigestValue>
                                                        </xades:CertDigest>
                                                        <xades:IssuerSerial>
                                                            <ds:X509IssuerName>{ISSUER_NAME}</ds:X509IssuerName>
                                                            <ds:X509SerialNumber>{SERIAL_NUMBER}</ds:X509SerialNumber>
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

        # cert digest (bytes -> sha256 -> base64)
        cert_der = base64.b64decode(self.cert)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        cert_digest_b64 = base64.b64encode(hashlib.sha256(cert_der).digest()).decode()

        issuer_name = cert.issuer.rfc4514_string()
        serial_number = str(cert.serial_number)
        signingTime = invoice_date.strftime("%Y-%m-%dT%H:%M:%S")

        # Get signed properties digest and XML (note the correct arg: cert_digest_b64)
        signed_props_digest = self.get_signed_properties_hash(
            signingTime=signingTime,
            digestValue=self.generate_public_key_hashing(),
            x509IssuerName=issuer_name,
            x509SerialNumber=serial_number
        )

        # now fill the template using the digest and the signed_props_xml (serialized)
        return UBL_INVOICE_TEMPLATE.format(
            signature_id="urn:oasis:names:specification:ubl:signature:1",
            referenced_signature_id="urn:oasis:names:specification:ubl:signature:Invoice",
            invoice_digest=invoice_hash,
            signed_props_digest=signed_props_digest,
            signature_value=signature_value,
            certificate=self.cert,
            ISSUER_NAME=issuer_name,
            SIGNATURE_TIMESTAMP=signingTime,
            SERIAL_NUMBER=serial_number,
            PUBLICKEY_HASHING=self.generate_public_key_hashing()

        )

    def generate_public_key_hashing(self):
        x509_cert = self.cert
        hash_bytes = hashlib.sha256(x509_cert.encode('utf-8')).digest()
        hash_hex = hash_bytes.hex()
        return base64.b64encode(hash_hex.encode('utf-8')).decode('utf-8')

    def transform_xml(self, xml, xsl_file_path):
        """ Apply XSL transformation to an XML """
        xsl = etree.parse(xsl_file_path)
        transform = etree.XSLT(xsl)
        transformed_xml = transform(xml)
        if transformed_xml is None: raise Exception("XSL: Transformation Failed!!")
        return transformed_xml

    # --------- INVOICE GENERATION ---------
    def generate(self,
                 invoice_number: str,
                 invoice_date: datetime,
                 lines: List[InvoiceLine],
                 previous_invoice_hash: str) -> Tuple[str, str, str, str]:

        totals = self._calculate_totals(lines)
        invoice_uuid = str(uuid.uuid4())

        invoice_date = invoice_date.replace(microsecond=0)

        # Step 1: Build initial XML (placeholders for QR & PIH)
        xml_invoice = self._build_xml(
            invoice_number=invoice_number,
            invoice_date=invoice_date,
            lines=lines,
            totals=totals,
            pih=previous_invoice_hash,  # placeholder
            invoice_uuid=invoice_uuid
        )

        parser = etree.XMLParser(remove_blank_text=False)
        xml = etree.fromstring(xml_invoice.encode("utf-8"), parser)
        transfomred_xml = self.transform_xml(xml, XSL_FILE)

        # Step 2: Canonicalize the XML
        canonicalized_xml = self._canonicalize_xml(transfomred_xml)

        # Step 3: Compute the hash from canonicalized XML
        invoice_hash = hashlib.sha256(canonicalized_xml.encode()).digest()  # invoice hash raw #1

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
        xml_with_qr_pih = self.insert_signature_qr(xml_invoice, signed_extensions, qr_base64)

        # Step 9: Insert signed extensions at the proper location
        final_xml = xml_with_qr_pih
        final_b64 = base64.b64encode(final_xml.encode("utf-8")).decode("utf-8")


        # Step 10: generate qrcode as an image encoded in base64
        qr_img = qrcode.make(qr_data)
        buffer = io.BytesIO()
        qr_img.save(buffer, format="PNG")
        qr_img_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

        # Return final XML and hash that matches it
        return final_xml, invoice_uuid, invoice_hash_b64, qr_img_base64

    # --------- HELPERS ---------
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

    def _generate_qr_tlv_binary(self, seller_name: str, tax_number: str, invoice_date: datetime,
                                total_with_vat: str, vat_amount: str,
                                invoice_hash: str, signature_value: str) -> bytes:
        """Generate ZATCA-compliant QR TLV binary data with robust debugging"""
        date_str = invoice_date.strftime('%Y-%m-%dT%H:%M:%S')

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
            return qr_data

        except Exception as e:
            print("\n=== DEBUGGING INFORMATION ===")
            print("Certificate content (first 200 chars):")
            print(self.cert[:200])
            raise

    def insert_signature_qr(self, invoice_xml: str, signed_extensions: str, qr64: str) -> str:
        from lxml import etree

        parser = etree.XMLParser(remove_blank_text=False)
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
            pretty_print=False,
            encoding="UTF-8"
        ).decode('utf-8')

    def _build_xml(self,
                   invoice_number: str,
                   invoice_date: datetime,
                   lines: List[InvoiceLine],
                   totals: Dict,
                   pih: str,
                   invoice_uuid: str) -> str:

        # ASSUMING VAT RATE IS 15%, it is hardcoded under TaxTotal, Tax Category

        issue_date = invoice_date.strftime("%Y-%m-%d")
        issue_time = invoice_date.strftime("%H:%M:%S")

        xml_template = f"""<?xml version="1.0" encoding="UTF-8"?>
        <Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">
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
                    <cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">{pih}</cbc:EmbeddedDocumentBinaryObject>
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


def main(env):
    seller_info = {
        'tax_number': "399999999900003",
        'company_name': "Gandofly",
        'street': "Main Street",
        'building': "123",
        'city': "Riyadh",
        'postal_code': "12345",
        'country_code': "SA",
        "crn": "1010010000"
    }

    prod_cert = "TUlJRDNqQ0NBNFNnQXdJQkFnSVRFUUFBT0FQRjkwQWpzL3hjWHdBQkFBQTRBekFLQmdncWhrak9QUVFEQWpCaU1SVXdFd1lLQ1pJbWlaUHlMR1FCR1JZRmJHOWpZV3d4RXpBUkJnb0praWFKay9Jc1pBRVpGZ05uYjNZeEZ6QVZCZ29Ka2lhSmsvSXNaQUVaRmdkbGVIUm5ZWHAwTVJzd0dRWURWUVFERXhKUVVscEZTVTVXVDBsRFJWTkRRVFF0UTBFd0hoY05NalF3TVRFeE1Ea3hPVE13V2hjTk1qa3dNVEE1TURreE9UTXdXakIxTVFzd0NRWURWUVFHRXdKVFFURW1NQ1FHQTFVRUNoTWRUV0Y0YVcxMWJTQlRjR1ZsWkNCVVpXTm9JRk4xY0hCc2VTQk1WRVF4RmpBVUJnTlZCQXNURFZKcGVXRmthQ0JDY21GdVkyZ3hKakFrQmdOVkJBTVRIVlJUVkMwNE9EWTBNekV4TkRVdE16azVPVGs1T1RrNU9UQXdNREF6TUZZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUFvRFFnQUVvV0NLYTBTYTlGSUVyVE92MHVBa0MxVklLWHhVOW5QcHgydmxmNHloTWVqeThjMDJYSmJsRHE3dFB5ZG84bXEwYWhPTW1Obzhnd25pN1h0MUtUOVVlS09DQWdjd2dnSURNSUd0QmdOVkhSRUVnYVV3Z2FLa2daOHdnWnd4T3pBNUJnTlZCQVFNTWpFdFZGTlVmREl0VkZOVWZETXRaV1F5TW1ZeFpEZ3RaVFpoTWkweE1URTRMVGxpTlRndFpEbGhPR1l4TVdVME5EVm1NUjh3SFFZS0NaSW1pWlB5TEdRQkFRd1BNems1T1RrNU9UazVPVEF3TURBek1RMHdDd1lEVlFRTURBUXhNVEF3TVJFd0R3WURWUVFhREFoU1VsSkVNamt5T1RFYU1CZ0dBMVVFRHd3UlUzVndjR3g1SUdGamRHbDJhWFJwWlhNd0hRWURWUjBPQkJZRUZFWCtZdm1tdG5Zb0RmOUJHYktvN29jVEtZSzFNQjhHQTFVZEl3UVlNQmFBRkp2S3FxTHRtcXdza0lGelZ2cFAyUHhUKzlObk1Ic0dDQ3NHQVFVRkJ3RUJCRzh3YlRCckJnZ3JCZ0VGQlFjd0FvWmZhSFIwY0RvdkwyRnBZVFF1ZW1GMFkyRXVaMjkyTG5OaEwwTmxjblJGYm5KdmJHd3ZVRkphUlVsdWRtOXBZMlZUUTBFMExtVjRkR2RoZW5RdVoyOTJMbXh2WTJGc1gxQlNXa1ZKVGxaUFNVTkZVME5CTkMxRFFTZ3hLUzVqY25Rd0RnWURWUjBQQVFIL0JBUURBZ2VBTUR3R0NTc0dBUVFCZ2pjVkJ3UXZNQzBHSlNzR0FRUUJnamNWQ0lHR3FCMkUwUHNTaHUyZEpJZk8reG5Ud0ZWbWgvcWxaWVhaaEQ0Q0FXUUNBUkl3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdNR0NDc0dBUVVGQndNQ01DY0dDU3NHQVFRQmdqY1ZDZ1FhTUJnd0NnWUlLd1lCQlFVSEF3TXdDZ1lJS3dZQkJRVUhBd0l3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUxFL2ljaG1uV1hDVUtVYmNhM3ljaThvcXdhTHZGZEhWalFydmVJOXVxQWJBaUE5aEM0TThqZ01CQURQU3ptZDJ1aVBKQTZnS1IzTEUwM1U3NWVxYkMvclhBPT0="
    c_cert = "TUlJQ1NEQ0NBZTZnQXdJQkFnSUdBWmtHOEp1VU1Bb0dDQ3FHU000OUJBTUNNQlV4RXpBUkJnTlZCQU1NQ21WSmJuWnZhV05wYm1jd0hoY05NalV3T1RBeE1qQXlNRFV3V2hjTk16QXdPRE14TWpFd01EQXdXakJyTVFzd0NRWURWUVFHRXdKVFFURVJNQThHQTFVRUNnd0lSMkZ1Wkc5bWJIa3hGakFVQmdOVkJBc01EVXBoWkdSaGFDQkNjbUZ1WTJneE1UQXZCZ05WQkFNTUtGUlRWQzFoWkdWbFlUUXdZaTAyT1RZM0xUUmtOVFF0WW1Fek55MW1OREpqTkRFME9USTJOamN3VmpBUUJnY3Foa2pPUFFJQkJnVXJnUVFBQ2dOQ0FBVHRRUjY5NElaNHVMbHpnR05VQ0lYbUsxS3dJdHFTaXVjYVNsM0E4dXpYNTh0MUp6VkY2MkZDS2U1SW5QOGtuREJFUnRwazZ4cnpDRDBvSDllQmd5d2JvNEhXTUlIVE1Bd0dBMVVkRXdFQi93UUNNQUF3Z2NJR0ExVWRFUVNCdWpDQnQ2U0J0RENCc1RGQ01FQUdBMVVFQkF3NU1TMU5hV055YjFCUFUzd3lMVEV1TUM0d2ZETXRZV1JsWldFME1HSXROamsyTnkwMFpEVTBMV0poTXpjdFpqUXlZelF4TkRreU5qWTNNUjh3SFFZS0NaSW1pWlB5TEdRQkFRd1BNems1T1RrNU9UazVPVEF3TURBek1RMHdDd1lEVlFRTURBUXhNREF3TVNZd0pBWURWUVFhREIxTGFXNW5JRVpoYUdRZ1VtOWhaQ3dnVW1sNVlXUm9MQ0F4TWpNME5URVRNQkVHQTFVRUR3d0tjbVZ6ZEdGMWNtRnVkREFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUVBdHMzd25JU3ExUmNDRlNKdmEvYldQQVBOcDBNVDU2c0ZUc3kwM1c1empUWUNJQndrZ1BVYmpEYXBhN0NmM0YxZHRaN2FMaXljbXlDbE1XOVZPQUVwaXM2Nw=="

    if env == "prod":
        cert = prod_cert
    else:
        cert = c_cert
    cert_b64 = base64.b64decode(cert).decode('ascii')

    priv_key = b"""-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIJwgywYAxEEieb/lBMPp7lYwAZkGlXyd/Nwx9RrVauD+oAcGBSuBBAAK
oUQDQgAExG21O6Ob1Ne9djsNtO38FDc8SCGb7mMLlsdk3JGMxrMK9iu8Ak7YEdMK
x56T7WpAYFa4Hi2DBB+5RQ2O9yTVxA==
-----END EC PRIVATE KEY-----"""

    generator = ZatcaSimplifiedInvoice(seller_info, priv_key=priv_key, cert=cert_b64)
    invoice_lines = [
        {'name': "Product 1", 'quantity': "2", 'unit_price': "100.00", 'vat_rate': "15"},
        {'name': "Product 2", 'quantity': "1", 'unit_price': "50.00", 'vat_rate': "15"}
    ]

    xml_invoice, uuid, invoice_hash, qr = generator.generate(
        invoice_number="SME00023",
        invoice_date=datetime.now(),
        lines=invoice_lines,
        previous_invoice_hash="vLGQoYNoM3tf1XAxKpoNTSz/8pkdidXy47HWh0VQmu8="
    )

    with open("zatca_simplified_invoice.xml", "w", encoding="utf-8") as f:
        f.write(xml_invoice)

    print("Simplified e-Invoice generated successfully!")

    with open("zatca_simplified_invoice.xml", "rb") as f:
        xml_bytes = f.read().strip()
    encoded_invoice = base64.b64encode(xml_bytes).decode("utf-8")

    from invoice_compliance import check_invoice_compliance
    prod_bst = "TUlJRDNqQ0NBNFNnQXdJQkFnSVRFUUFBT0FQRjkwQWpzL3hjWHdBQkFBQTRBekFLQmdncWhrak9QUVFEQWpCaU1SVXdFd1lLQ1pJbWlaUHlMR1FCR1JZRmJHOWpZV3d4RXpBUkJnb0praWFKay9Jc1pBRVpGZ05uYjNZeEZ6QVZCZ29Ka2lhSmsvSXNaQUVaRmdkbGVIUm5ZWHAwTVJzd0dRWURWUVFERXhKUVVscEZTVTVXVDBsRFJWTkRRVFF0UTBFd0hoY05NalF3TVRFeE1Ea3hPVE13V2hjTk1qa3dNVEE1TURreE9UTXdXakIxTVFzd0NRWURWUVFHRXdKVFFURW1NQ1FHQTFVRUNoTWRUV0Y0YVcxMWJTQlRjR1ZsWkNCVVpXTm9JRk4xY0hCc2VTQk1WRVF4RmpBVUJnTlZCQXNURFZKcGVXRmthQ0JDY21GdVkyZ3hKakFrQmdOVkJBTVRIVlJUVkMwNE9EWTBNekV4TkRVdE16azVPVGs1T1RrNU9UQXdNREF6TUZZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUFvRFFnQUVvV0NLYTBTYTlGSUVyVE92MHVBa0MxVklLWHhVOW5QcHgydmxmNHloTWVqeThjMDJYSmJsRHE3dFB5ZG84bXEwYWhPTW1Obzhnd25pN1h0MUtUOVVlS09DQWdjd2dnSURNSUd0QmdOVkhSRUVnYVV3Z2FLa2daOHdnWnd4T3pBNUJnTlZCQVFNTWpFdFZGTlVmREl0VkZOVWZETXRaV1F5TW1ZeFpEZ3RaVFpoTWkweE1URTRMVGxpTlRndFpEbGhPR1l4TVdVME5EVm1NUjh3SFFZS0NaSW1pWlB5TEdRQkFRd1BNems1T1RrNU9UazVPVEF3TURBek1RMHdDd1lEVlFRTURBUXhNVEF3TVJFd0R3WURWUVFhREFoU1VsSkVNamt5T1RFYU1CZ0dBMVVFRHd3UlUzVndjR3g1SUdGamRHbDJhWFJwWlhNd0hRWURWUjBPQkJZRUZFWCtZdm1tdG5Zb0RmOUJHYktvN29jVEtZSzFNQjhHQTFVZEl3UVlNQmFBRkp2S3FxTHRtcXdza0lGelZ2cFAyUHhUKzlObk1Ic0dDQ3NHQVFVRkJ3RUJCRzh3YlRCckJnZ3JCZ0VGQlFjd0FvWmZhSFIwY0RvdkwyRnBZVFF1ZW1GMFkyRXVaMjkyTG5OaEwwTmxjblJGYm5KdmJHd3ZVRkphUlVsdWRtOXBZMlZUUTBFMExtVjRkR2RoZW5RdVoyOTJMbXh2WTJGc1gxQlNXa1ZKVGxaUFNVTkZVME5CTkMxRFFTZ3hLUzVqY25Rd0RnWURWUjBQQVFIL0JBUURBZ2VBTUR3R0NTc0dBUVFCZ2pjVkJ3UXZNQzBHSlNzR0FRUUJnamNWQ0lHR3FCMkUwUHNTaHUyZEpJZk8reG5Ud0ZWbWgvcWxaWVhaaEQ0Q0FXUUNBUkl3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdNR0NDc0dBUVVGQndNQ01DY0dDU3NHQVFRQmdqY1ZDZ1FhTUJnd0NnWUlLd1lCQlFVSEF3TXdDZ1lJS3dZQkJRVUhBd0l3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUxFL2ljaG1uV1hDVUtVYmNhM3ljaThvcXdhTHZGZEhWalFydmVJOXVxQWJBaUE5aEM0TThqZ01CQURQU3ptZDJ1aVBKQTZnS1IzTEUwM1U3NWVxYkMvclhBPT0="
    prod_sec = "CkYsEXfV8c1gFHAtFWoZv73pGMvh/Qyo4LzKM2h/8Hg="
    c_bst = "TUlJQ1NEQ0NBZTZnQXdJQkFnSUdBWmtHOEp1VU1Bb0dDQ3FHU000OUJBTUNNQlV4RXpBUkJnTlZCQU1NQ21WSmJuWnZhV05wYm1jd0hoY05NalV3T1RBeE1qQXlNRFV3V2hjTk16QXdPRE14TWpFd01EQXdXakJyTVFzd0NRWURWUVFHRXdKVFFURVJNQThHQTFVRUNnd0lSMkZ1Wkc5bWJIa3hGakFVQmdOVkJBc01EVXBoWkdSaGFDQkNjbUZ1WTJneE1UQXZCZ05WQkFNTUtGUlRWQzFoWkdWbFlUUXdZaTAyT1RZM0xUUmtOVFF0WW1Fek55MW1OREpqTkRFME9USTJOamN3VmpBUUJnY3Foa2pPUFFJQkJnVXJnUVFBQ2dOQ0FBVHRRUjY5NElaNHVMbHpnR05VQ0lYbUsxS3dJdHFTaXVjYVNsM0E4dXpYNTh0MUp6VkY2MkZDS2U1SW5QOGtuREJFUnRwazZ4cnpDRDBvSDllQmd5d2JvNEhXTUlIVE1Bd0dBMVVkRXdFQi93UUNNQUF3Z2NJR0ExVWRFUVNCdWpDQnQ2U0J0RENCc1RGQ01FQUdBMVVFQkF3NU1TMU5hV055YjFCUFUzd3lMVEV1TUM0d2ZETXRZV1JsWldFME1HSXROamsyTnkwMFpEVTBMV0poTXpjdFpqUXlZelF4TkRreU5qWTNNUjh3SFFZS0NaSW1pWlB5TEdRQkFRd1BNems1T1RrNU9UazVPVEF3TURBek1RMHdDd1lEVlFRTURBUXhNREF3TVNZd0pBWURWUVFhREIxTGFXNW5JRVpoYUdRZ1VtOWhaQ3dnVW1sNVlXUm9MQ0F4TWpNME5URVRNQkVHQTFVRUR3d0tjbVZ6ZEdGMWNtRnVkREFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUVBdHMzd25JU3ExUmNDRlNKdmEvYldQQVBOcDBNVDU2c0ZUc3kwM1c1empUWUNJQndrZ1BVYmpEYXBhN0NmM0YxZHRaN2FMaXljbXlDbE1XOVZPQUVwaXM2Nw=="
    c_sec = "w1mQespdD7gqA9VLN+B//VwY7Z6QTQkmh4i8q45KNb4="

    if env == "prod":
        from invoice_compliance import report_invoice
        bst = prod_bst
        sec = prod_sec
        report_invoice(invoice_hash, uuid, encoded_invoice, bst, sec)
    else:
        from invoice_compliance import check_invoice_compliance
        bst = c_bst
        sec = c_sec
        check_invoice_compliance(invoice_hash, uuid, encoded_invoice, bst, sec)

    with open("e-invoice.txt", "w+") as f:
        f.write(encoded_invoice)

    print("Invoice hash value: ", invoice_hash)
    print(uuid)


def extract_vat_from_cert(cert_b64: str) -> str:
    from cryptography.x509.oid import NameOID, ObjectIdentifier
    """
    Extract VAT number from a base64 DER-encoded X.509 certificate.
    Works with ZATCA-issued production & test certificates.
    """
    # Decode certificate
    cert_der = base64.b64decode(cert_b64)
    cert = x509.load_der_x509_certificate(cert_der, default_backend())

    subject = cert.subject

    vat_number = None

    # 1. Sometimes it's in the SerialNumber (OID 2.5.4.5)
    try:
        serial_number_attr = subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
        if serial_number_attr:
            vat_number = serial_number_attr[0].value
            if vat_number.isdigit():
                return vat_number
    except Exception:
        pass

    # 2. Sometimes it's encoded in OrganizationIdentifier (OID 2.5.4.97)
    try:
        org_id_oid = ObjectIdentifier("2.5.4.97")
        org_id_attr = subject.get_attributes_for_oid(org_id_oid)
        if org_id_attr:
            val = org_id_attr[0].value
            # Example: "VATKSA-310122393500003"
            if "VATKSA" in val:
                vat_number = val.split("-")[-1]
                return vat_number
    except Exception:
        pass

    # 3. As a fallback, scan the full RDN string
    subj_str = subject.rfc4514_string()
    for part in subj_str.split(","):
        if "VATKSA" in part:
            vat_number = part.split("-")[-1].strip()
            return vat_number

    return vat_number  # None if not found

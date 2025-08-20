from lxml import etree
from typing import List


class InvoiceObject:
    def __init__(self, invoice_data: dict, lines: List[dict]):
        self.ID = invoice_data.get("ID", "INV-001")
        self.UUID = invoice_data.get("UUID", "uuid-001")
        self.IssueDate = invoice_data.get("IssueDate", "2025-08-18")
        self.IssueTime = invoice_data.get("IssueTime", "12:00:00")
        self.ProfileID = invoice_data.get("ProfileID", "Standard")
        self.InvoiceTypeCode = invoice_data.get("InvoiceTypeCode", "01")
        self.DocumentCurrencyCode = invoice_data.get("DocumentCurrencyCode", "SAR")
        self.TaxCurrencyCode = invoice_data.get("TaxCurrencyCode", "SAR")
        self.AccountingSupplierParty = invoice_data.get("AccountingSupplierParty", {})
        self.AccountingCustomerParty = invoice_data.get("AccountingCustomerParty", {})
        self.InvoiceLines = lines  # list of dicts, each with 'name', 'quantity', 'unit_price', 'vat_rate', etc.

    def to_xml(self, namespaces):
        """
        Converts the InvoiceObject to an lxml.Element with proper namespaces.
        """
        # Root element in default namespace (no prefix)
        invoice_elem = etree.Element(
            "Invoice",
            nsmap={None: "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2", **namespaces}
        )

        # Basic elements
        etree.SubElement(invoice_elem, "{%s}ID" % namespaces["cbc"]).text = self.ID
        etree.SubElement(invoice_elem, "{%s}UUID" % namespaces["cbc"]).text = self.UUID
        etree.SubElement(invoice_elem, "{%s}IssueDate" % namespaces["cbc"]).text = self.IssueDate
        etree.SubElement(invoice_elem, "{%s}IssueTime" % namespaces["cbc"]).text = self.IssueTime
        etree.SubElement(invoice_elem, "{%s}ProfileID" % namespaces["cbc"]).text = self.ProfileID
        etree.SubElement(invoice_elem, "{%s}DocumentCurrencyCode" % namespaces["cbc"]).text = self.DocumentCurrencyCode
        etree.SubElement(invoice_elem, "{%s}TaxCurrencyCode" % namespaces["cbc"]).text = self.TaxCurrencyCode

        # Supplier/Customer placeholders
        etree.SubElement(invoice_elem, "{%s}AccountingSupplierParty" % namespaces["cac"])
        etree.SubElement(invoice_elem, "{%s}AccountingCustomerParty" % namespaces["cac"])

        # Add invoice lines
        for line_xml in self._build_invoice_lines(self.InvoiceLines):
            invoice_elem.append(etree.fromstring(line_xml))

        return invoice_elem

    def _build_invoice_lines(self, lines: List[dict]) -> List[str]:
        """
        Returns a list of XML strings for each invoice line.
        """
        invoice_lines_xml = []
        for idx, line in enumerate(lines, start=1):
            line_total = float(line['unit_price']) * float(line['quantity'])
            line_vat = line_total * (float(line['vat_rate']) / 100)
            xml_str = f"""
                <cac:InvoiceLine xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
                                 xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
                    <cbc:ID>{idx}</cbc:ID>
                    <cbc:InvoicedQuantity unitCode="{line.get('unit_code', 'PCE')}">{line['quantity']}</cbc:InvoicedQuantity>
                    <cbc:LineExtensionAmount currencyID="SAR">{line_total:.2f}</cbc:LineExtensionAmount>

                    <cac:TaxTotal>
                        <cbc:TaxAmount currencyID="SAR">{line_vat:.2f}</cbc:TaxAmount>
                        <cbc:RoundingAmount currencyID="SAR">{line_total + line_vat:.2f}</cbc:RoundingAmount>
                    </cac:TaxTotal>

                    <cac:Item>
                        <cbc:Name>{line['name']}</cbc:Name>
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
            invoice_lines_xml.append(xml_str)
        return invoice_lines_xml

def get_clean_invoice_xml(invoice_object, apply_xsl=True):
        """
        Generate a clean, namespaced XML string from an invoice object.

        Args:
            invoice_object: Your invoice data object with a `.to_xml(namespaces)` method.
            apply_xsl (bool): Whether to apply the ZATCA XSLT.

        Returns:
            str: Formatted XML string or None on failure.
        """
        try:
            # Define namespaces
            namespaces = {
                "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
                "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                "ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
            }

            # Convert invoice object to XML (you need to implement this method)
            # It should return an lxml Element
            invoice_xml_element = invoice_object.to_xml(namespaces=namespaces)

            # Apply XSLT if needed
            if apply_xsl:
                xslt_path = "ZatcaDataInvoice.xsl"
                xslt_doc = etree.parse(xslt_path)
                transform = etree.XSLT(xslt_doc)
                invoice_xml_element = transform(invoice_xml_element)

            # Return formatted XML string
            return etree.tostring(invoice_xml_element, pretty_print=True, encoding="utf-8",
                                  xml_declaration=True).decode("utf-8")

        except Exception as e:
            print(f"Error in get_clean_invoice_xml: {e}")
            return None
def insert_external_xml(invoice_elem, signature_xml_path, ubl_ext_xml_path, qr_xml_path):
    """
    Inserts external XML snippets into the invoice:
      - signature_xml_path: usually <Signature> XML
      - ubl_ext_xml_path: <ext:UBLExtensions> XML
      - qr_xml_path: QR code XML snippet
    """
    # Parse external XMLs
    signature_elem = etree.parse(signature_xml_path).getroot()
    ubl_ext_elem = etree.parse(ubl_ext_xml_path).getroot()
    qr_elem = etree.parse(qr_xml_path).getroot()

    nsmap = invoice_elem.nsmap
    cac_ns = nsmap.get("cac")

    # 1. Insert <ext:UBLExtensions> after <cbc:ProfileID>
    profile_id_elem = invoice_elem.find(".//cbc:ProfileID", namespaces=nsmap)
    if profile_id_elem is not None:
        profile_id_index = invoice_elem.index(profile_id_elem)
        invoice_elem.insert(profile_id_index + 1, ubl_ext_elem)

    # 2. Insert QR code under <cac:AccountingSupplierParty>
    supplier_elem = invoice_elem.find(".//cac:AccountingSupplierParty", namespaces=nsmap)
    if supplier_elem is not None:
        supplier_elem.append(qr_elem)

    # 3. Insert signature under <cac:AccountingSupplierParty> (optional, depends on schema)
    # In C# you inserted signature right after QR code
    if supplier_elem is not None:
        supplier_elem.append(signature_elem)

    return invoice_elem

lines = [
    {"name": "Item 1", "quantity": 2, "unit_price": 100, "vat_rate": 15},
    {"name": "Item 2", "quantity": 1, "unit_price": 200, "vat_rate": 15},
]

invoice_data = {
    "ID": "INV-1001",
    "UUID": "uuid-123",
    "IssueDate": "2025-08-18",
    "IssueTime": "14:30:00",
    "ProfileID": "Standard"
}

invoice_obj = InvoiceObject(invoice_data, lines)
invoice_elem = invoice_obj.to_xml(namespaces={
    "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
    "ext": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
})

# Insert external XMLs
invoice_elem = insert_external_xml(
    invoice_elem,
    signature_xml_path="Signature.xml",
    ubl_ext_xml_path="ZatcaDataUbl.xml",
    qr_xml_path="ZatcaQr.xml"
)

# Optional: apply XSLT after insertion
xml_string = get_clean_invoice_xml(invoice_obj, apply_xsl=True)
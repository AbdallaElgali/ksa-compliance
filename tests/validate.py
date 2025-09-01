# python_c14n_lxml_best_effort.py
import base64, hashlib
from lxml import etree

ZATCA_FILE = "zatca_simplified_invoice.xml"
XSL_FILE = "../api/invoice_utils/Resources/transform.xsl"

def transform_xml(xml, xsl_file_path):
    """ Apply XSL transformation to an XML """
    xsl = etree.parse(xsl_file_path)
    transform = etree.XSLT(xsl)
    transformed_xml = transform(xml)
    if transformed_xml is None: raise Exception("XSL: Transformation Failed!!")
    return transformed_xml

def canonicalize(transformed_xml):
    """ Canonicalize the transformed XML. Returning the canonical xml string."""
    return etree.tostring(transformed_xml, method='c14n').decode('utf-8')

def main():
    parser = etree.XMLParser(remove_blank_text=False)
    xml = etree.parse(ZATCA_FILE, parser)
    print(xml)
    transformed_xml = transform_xml(xml, XSL_FILE)
    canonicalized_xml = canonicalize(transformed_xml)
    hashed_xml = hashlib.sha256(canonicalized_xml.encode()).digest()
    base64_hash = base64.b64encode(hashed_xml).decode('utf-8')
    print(base64_hash)


if __name__ == "__main__":
    main()

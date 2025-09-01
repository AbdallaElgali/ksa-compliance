from flask import Flask, request, jsonify
from datetime import datetime
from invoice_utils.invoice_generator import ZatcaSimplifiedInvoice
import base64

app = Flask(__name__)


# Example route
@app.route("/")
def index():
    return {"message": "KSA Compliance API is running!"}


# Example POST route
@app.route("/generate-invoice", methods=["POST"])
def generate_invoice():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON body provided"}), 400

        # Required params
        seller_info = data.get("seller_info")
        cert = data.get("cert")
        priv_key_64 = data.get("priv_key")  # Must be base64 of the pem file
        priv_key = base64.b64decode(priv_key_64)
        invoice_number = data.get("invoice_number")
        invoice_lines = data.get("invoice_lines")
        pih = data.get("pih")

        # Basic validation
        if not all([seller_info, cert, priv_key, invoice_number, invoice_lines]):
            return jsonify({"error": "Missing required parameters"}), 400

        # Decode certificate (if it’s base64 encoded)
        try:
            cert_b64 = base64.b64decode(cert).decode("ascii")
        except Exception:
            cert_b64 = cert  # assume plain string PEM if decode fails

        # Initialize invoice generator
        generator = ZatcaSimplifiedInvoice(
            seller=seller_info,
            priv_key=priv_key,
            cert=cert_b64
        )

        # Generate invoice
        xml_invoice, invoice_uuid, invoice_hash, qrcode = generator.generate(
            invoice_number=invoice_number,
            invoice_date=datetime.now(),
            lines=invoice_lines,
            previous_invoice_hash=pih
        )

        return jsonify({
            "status": "success",
            "invoice_uuid": invoice_uuid,
            "invoice_hash": invoice_hash,
            "xml_invoice": xml_invoice,
            "xml_invoice_b64": base64.b64encode(xml_invoice.encode()).decode('utf-8'),
            "qr_code": qrcode
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)


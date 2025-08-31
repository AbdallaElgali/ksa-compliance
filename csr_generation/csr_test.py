import os
import uuid
from zatca_csr_gen import GenerateCSR

def generate_user_csr(user_info, egs_uuid):
    """
    Generates CSR + keys for a single user (restaurant unit) using zatca_csr_generator.
    user_info should be a dict with keys:
      csr_type, C, CN, O, OU, SN, UID, TITLE, CATEGORY, ADDRESS
    """
    # Set working directory to current directory
    working_dir = os.getcwd()

    generator = GenerateCSR()

    try:
        # Generate CSR using library
        result = generator.generate_csr(
            csr_type=user_info["csr_type"],
            C=user_info["C"],
            CN=user_info["CN"],
            O=user_info["O"],
            OU=user_info["OU"],
            SN=user_info["SN"],
            UID=user_info["UID"],
            TITLE=user_info["TITLE"],
            CATEGORY=user_info["CATEGORY"],
            ADDRESS=user_info["ADDRESS"],
            egs_uuid=user_info["egs_uuid"]
        )

        if result["status"] == 200:
            return {
                "certificate_signing_request": result["certificate_signing_request"],  # already base64-encoded with headers
                "private_key": result["private_key"],
                "public_key": result["public_key"]
            }
        else:
            raise Exception(f"CSR generation failed: {result}")
    except Exception as e:
        return {"status": 500, "error": str(e)}


# ===== Example usage =====
if __name__ == "__main__":
    egs_uuid = str(uuid.uuid4())
    vat_reg_number = "300000000000003"
    user_info = {
        "csr_type": "sandbox",
        "C": "SA",
        "CN": f"TST-{egs_uuid}",
        "O": "Gandofly",
        "OU": "Jaddah Branch",
        "SN": f"1-MicroPOS|2-1.0.0|3-{egs_uuid}",
        "UID": vat_reg_number,
        "TITLE": "1000",  # B2C
        "CATEGORY": "restaurant",
        "ADDRESS": "King Fahd Road, Riyadh, 12345",
        "egs_uuid": egs_uuid
    }

    csr_data = generate_user_csr(user_info, egs_uuid)
    print(csr_data)

    if csr_data.get("status") != 500:
        print("EGS UUID:", egs_uuid)
        print("Private Key:", csr_data["private_key"][:30] + "...")  # preview
        print("CSR: ", csr_data["certificate_signing_request"])
    else:
        print("Error:", csr_data["error"])

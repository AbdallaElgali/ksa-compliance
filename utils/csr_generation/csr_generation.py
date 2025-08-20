from utils.csr_generation.zatca_csr_gen import GenerateCSR  # the class from previous code

text_info = {
    "vat_reg_number": "301012414510123",
    "rest_name": "test name",
    "branch_name": "test branch",
    "address": "test address"
}

def generate_client_csr(info):
    """
    Generates CSR + keys for a single user (restaurant unit)
    user_info should be a dict with keys:
      csr_type, C, CN, O, OU, SN, UID, TITLE, CATEGORY, ADDRESS
    """

    import uuid

    # Example restaurant user info
    egs_unit_uuid = str(uuid.uuid4())

    user_info = {
        "csr_type": "sandbox",
        "C": "SA",
        "CN": f"TST-{egs_unit_uuid}",
        "O": info["rest_name"],
        "OU": info["tin"],
        "SN": f"1-MicroPOS|2-1.0.0|3-{egs_unit_uuid}",
        "UID": info["vat_reg_number"],
        "TITLE": "1000",  # B2C
        "CATEGORY": "Restaurant",
        "ADDRESS": info["address"]
    }

    generator = GenerateCSR()
    try:
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
            egs_uuid=egs_unit_uuid
        )
        if result["status"] == 200:
            return {
                "status": result["status"],
                "csr_base64": result["certificate_signing_request"],
                "private_key": result["private_key"],
                "public_key": result["public_key"],
                "egs_uuid": result["egs_uuid"]
            }
        else:
            raise Exception(f"CSR generation failed: {result}")
    except Exception as e:
        return {"status": 500, "error": str(e)}

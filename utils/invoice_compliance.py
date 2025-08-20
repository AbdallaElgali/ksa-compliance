import requests
from config import API_EXT, EINVOICING_URL
from requests.auth import HTTPBasicAuth

def get_compliance_csid(csr_base64, otp):
    url = f"{EINVOICING_URL}/{API_EXT}/compliance"
    headers = {
        "OTP": otp,
        "Content-Type": "application/json",
        "Accept-Version": "V2"
    }
    payload = {
        "csr": csr_base64
    }

    response = requests.post(url, json=payload, headers=headers)

    if response.status_code == 200:
        print("Compliance CSID Response:", response.json())
    else:
        print(f"Failed to get Compliance CSID: {response.status_code}")
        try:
            error_json = response.json()
            if "errors" in error_json:
                print("Errors:", error_json["errors"])
            else:
                print("Response JSON:", error_json)
        except ValueError:
            # If the response is not JSON
            print("Response text:", response.text)


def get_production_csid(request_id, binarySecurityToken, secret):
    url = f"{EINVOICING_URL}/{API_EXT}/production/csids"

    # Create Basic Auth header
    auth = HTTPBasicAuth(binarySecurityToken, secret)

    headers = {
        "Content-Type": "application/json",
        "Accept-Version": "V2"
    }

    payload = {
        "request_id": request_id
    }

    # Include auth in the request
    response = requests.post(url, json=payload, headers=headers, auth=auth)

    if response.status_code == 200:
        print("Compliance CSID Response:", response.json())
        return response.json()
    else:
        print(f"Failed to get Compliance CSID: {response.status_code}")
        try:
            error_json = response.json()
            if "errors" in error_json:
                print("Errors:", error_json["errors"])
            else:
                print("Response JSON:", error_json)
        except ValueError:
            print("Response text:", response.text)
        return None

def check_invoice_compliance(invoice_hash, uuid, invoice_b64, binarySecurityToken, secret):
    #url = f"{EINVOICING_URL}/{API_EXT}/compliance/invoices"
    url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance/invoices"
    # Create Basic Auth header
    auth = HTTPBasicAuth(binarySecurityToken, secret)

    headers = {
        "Content-Type": "application/json",
        "Accept-Version": "V2",
        "Accept-Language": "en"
    }

    payload = {
        "invoice_hash": invoice_hash,
        "uuid": uuid,
        "invoice": invoice_b64
    }

    # Include auth in the request
    response = requests.post(url, json=payload, headers=headers, auth=auth)

    if response.status_code == 200:
        print("Compliance Invoices Response:", response.json())
        return response.json()
    else:
        print(f"Compliance check failed with: {response.status_code}")
        try:
            error_json = response.json()
            if "errors" in error_json:
                print("Errors:", error_json["errors"])
            else:
                errors = error_json["validationResults"]["errorMessages"]
                for error in errors:
                    print(error)
                print(len(errors))
        except ValueError:
            print("Response text:", response.text)
        return None
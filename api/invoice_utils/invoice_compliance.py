import requests
from cli.config import API_EXT, EINVOICING_URL
from requests.auth import HTTPBasicAuth

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
        "invoiceHash": invoice_hash,
        "uuid": uuid,
        "invoice": invoice_b64
    }

    # Include auth in the request
    response = requests.post(url, json=payload, headers=headers, auth=auth)

    if response.status_code in [200, 202]:
        print("Compliance invoices Response:", response.json())
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

def report_invoice(invoice_hash, uuid, invoice_b64, binarySecurityToken, secret) -> (dict | None, int):
    url = f"{EINVOICING_URL}/{API_EXT}/invoices/reporting/single"
    #url = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/invoices/reporting/single"
    # Create Basic Auth header
    auth = HTTPBasicAuth(binarySecurityToken, secret)

    headers = {
        "Content-Type": "application/json",
        "Accept-Version": "V2",
        "Accept-Language": "en"
    }

    payload = {
        "invoiceHash": invoice_hash,
        "uuid": uuid,
        "invoice": invoice_b64
    }

    # Include auth in the request
    response = requests.post(url, json=payload, headers=headers, auth=auth)

    if response.status_code in [200, 202]:
        print("Reporting invoice Response:", response.json())
        return response.json(), response.status_code
    else:
        print(f"Reporting failed with: {response.status_code}")
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
        return None, 500
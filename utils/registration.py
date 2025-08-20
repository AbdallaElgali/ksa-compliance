import requests
from config import API_EXT, EINVOICING_URL

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



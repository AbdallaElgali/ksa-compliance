from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from utils.csr_generation.csr_generation import generate_client_csr
import requests
from config import API_EXT, EINVOICING_URL
import requests
from requests.auth import HTTPBasicAuth
import logging
import os

# Ensure the logs folder exists
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)

log_file = os.path.join(log_dir, "csr_generation.log")

logger = logging.getLogger("csr_logger")
logger.setLevel(logging.INFO)

# Remove previous handlers if any
if logger.hasHandlers():
    logger.handlers.clear()

file_handler = logging.FileHandler(log_file)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


router = APIRouter()

class GenerateCSRReq(BaseModel):
    info: dict

class ComplianceCSIDReq(BaseModel):
    csr_base64: str
    otp: str

class ProductionCSIDReq(BaseModel):
    binary_security_token: str  # From Compliance CSID response
    secret: str                # From Compliance CSID response
    request_id: str            # Unique request identifier

@router.post("/generate-csr", summary="Generate CSR for a restaurant unit")
async def generate_csr(data: GenerateCSRReq):
    """
    Generates a Certificate Signing Request (CSR) along with public/private keys
    for a restaurant unit. The `info` field must include:
        - vat_reg_number
        - rest_name
        - branch_name
        - address
    """
    try:
        # Log incoming request (mask sensitive info if needed)
        logger.info("Received CSR generation request for VAT: %s", data.info.get("vat_reg_number"))

        # Generate the CSR
        csr_result = generate_client_csr(info=data.info)

        # Check if generation succeeded
        if csr_result.get("status") != 200:
            logger.error("CSR generation failed: %s", csr_result)
            raise HTTPException(status_code=500, detail="CSR generation failed")

        logger.info("CSR generation successful, UUID: %s", csr_result.get("egs_uuid"))
        return csr_result

    except KeyError as ke:
        logger.error("Missing required field: %s", str(ke))
        raise HTTPException(status_code=422, detail=f"Missing field: {ke}")

    except Exception as e:
        logger.exception("Unexpected error during CSR generation")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/get-compliance-csid", summary="Get Compliance CSID from CSR")
async def get_compliance_csid_endpoint(data: ComplianceCSIDReq):
    """
    Sends a CSR to ZATCA Compliance API to retrieve the CSID.
    Requires:
        - csr_base64: Base64-encoded CSR
        - otp: One-time password from ZATCA
    """
    try:
        logger.info("Sending CSR to Compliance API")
        url = f"{EINVOICING_URL}/{API_EXT}/compliance"
        logger.info(url)
        headers = {
            "OTP": data.otp,
            "Content-Type": "application/json",
            "Accept-Version": "V2"
        }
        payload = {"csr": data.csr_base64}

        response = requests.post(url, json=payload, headers=headers)

        if response.status_code != 200:
            logger.error("Compliance API returned status %s", response.status_code)
            try:
                error_json = response.json()
                logger.error("Compliance API error: %s", error_json.get("errors", error_json))
            except ValueError:
                logger.error("Compliance API response is not JSON: %s", response.text)
            raise HTTPException(status_code=500, detail="Failed to get Compliance CSID")

        result = response.json()
        logger.info("Compliance CSID response: %s", result)
        return result

    except requests.RequestException as e:
        logger.exception("HTTP request failed")
        raise HTTPException(status_code=500, detail="Compliance API request failed")

    except Exception as e:
        logger.exception("Unexpected error in Compliance CSID endpoint")
        raise HTTPException(status_code=500, detail=f"Internal server error, {str(e)}")


@router.post("/get-production-csid", summary="Get Production CSID from ZATCA")
async def get_production_csid_endpoint(data: ProductionCSIDReq):
    """
    Retrieves the Production CSID from ZATCA's API using:
    - binary_security_token: Received from Compliance CSID response
    - secret: Received from Compliance CSID response
    - request_id: Unique identifier for the request
    """
    try:
        logger.info("Requesting Production CSID for request_id: %s", data.request_id)

        url = f"{EINVOICING_URL}/{API_EXT}/production/csids"

        # Basic Authentication using binary token and secret
        auth = HTTPBasicAuth(data.binary_security_token, data.secret)

        headers = {
            "Content-Type": "application/json",
            "Accept-Version": "V2"
        }

        payload = {
            "compliance_request_id": data.request_id
        }

        response = requests.post(
            url,
            json=payload,
            headers=headers,
            auth=auth
        )

        if response.status_code == 200:
            result = response.json()
            logger.info("Successfully received Production CSID")
            return {
                "status": "success",
                "data": result
            }
        else:
            error_detail = f"ZATCA API returned {response.status_code}"
            try:
                error_json = response.json()
                logger.error("ZATCA Production API error: %s", error_json)
                error_detail = error_json.get("errors", error_json)
            except ValueError:
                logger.error("Non-JSON response: %s", response.text)
                error_detail = response.text

            raise HTTPException(
                status_code=response.status_code,
                detail=error_detail
            )

    except requests.RequestException as e:
        logger.exception("HTTP request to ZATCA failed")
        raise HTTPException(
            status_code=500,
            detail="Connection to ZATCA API failed"
        )

    except Exception as e:
        logger.exception("Unexpected error in Production CSID endpoint")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )
@router.get("/")
async def get_onboarding():
    return {"message": "Onboarding endpoint"}

@router.get("/test")
async def test_onboarding():
    return {"message": "Onboarding test successful"}

import base64
from datetime import datetime
import click
from csr_generation.zatca_csr_gen import GenerateCSR
import uuid
from invoices.invoice_compliance import get_compliance_csid, get_production_csid
import os
import json
from typing import TypedDict, List

current_dir = os.getcwd()

@click.group()
def mycommands():
    pass


@click.command()
@click.option("--csr_type", default="sandbox", help="Type of CSR: sandbox/simulation/production")
@click.option("--C", default="SA", help="Country code")
@click.option("--CN", default=None, help="Common Name")
@click.option("--O", default="Gandofly", help="Organization Name")
@click.option("--OU", default="Jaddah Branch", help="Organizational Unit")
@click.option("--SN", default=None, help="Serial Number")
@click.option("--UID", required=True, help="VAT registration number")
@click.option("--TITLE", default="1000", help="Title")
@click.option("--CATEGORY", default="restaurant", help="Category")
@click.option("--ADDRESS", default="King Fahd Road, Riyadh, 12345", help="Address")
@click.option("--egs_uuid", default=None, help="Unique ID for this CSR")
@click.option("--output_dir", default=current_dir, help="Directory to save generated files")
def generate_csr(csr_type, c, cn, o, ou, sn, uid, title, category, address, egs_uuid, output_dir):
    if egs_uuid is None:
        egs_uuid = str(uuid.uuid4())
    if cn is None:
        if csr_type == 'sandbox':
            cn = f"TST-{egs_uuid}"
        elif csr_type == "simulation":
            cn = f"SIM-{egs_uuid}"
        else:
            cn = f"PRD-{egs_uuid}"

    if sn is None:
        sn = f"1-MicroPOS|2-1.0.0|3-{egs_uuid}"

    generator = GenerateCSR()
    result = generator.generate_csr(
        csr_type=csr_type,
        C=c,
        CN=cn,
        O=o,
        OU=ou,
        SN=sn,
        UID=uid,
        TITLE=title,
        CATEGORY=category,
        ADDRESS=address,
        egs_uuid=egs_uuid,
        output_dir=output_dir + '/csrs'
    )
    click.echo(result)

mycommands.add_command(generate_csr)

@click.command()
@click.option("--csr-dir", required=True, default=f"{current_dir}\csrs", help="The directory where the CSR certificate is present.")
@click.option("--otp", required=True, default="123345", help="The OTP provided by ZATACA.")
@click.option("--output-dir", default=current_dir, help="The output directory.")
def generate_csid(csr_dir: str, otp: str, output_dir: str):
    if type(otp) != "str":
        click.UsageError("OTP Must be of type string.")
    if len(otp) != 6:
        click.UsageError("OTP Must be 6 digits")

    with open(f"{csr_dir}\certificate.csr", "rb") as inf:  # read as bytes
        cert_bytes = inf.read()
        cert_64 = base64.b64encode(cert_bytes).decode('utf-8')

    try:
        response = get_compliance_csid(cert_64, otp)

        req_id = response.get('requestID')
        secret = response.get('secret')
        token = response.get('binarySecurityToken')

        output_data = {
            "req_id": req_id,
            "secret": secret,
            "token": token
        }


        with open(f"{output_dir}/compliance_auth.json", "w+") as outf:
            outf.write(json.dumps(output_data, indent=4))

        click.echo(f"Compliance CSID retrieved, details saved at {output_dir}/compliance_auth.json")

    except Exception as e:
        click.UsageError(str(e))

mycommands.add_command(generate_csid)

@click.command()
@click.option("--csid-dir", required=True, default=current_dir, help="The directory where the CSID json response is present.")
@click.option("--output-dir", default=current_dir, help="The output directory.")
def generate_psid(csid_dir: str, output_dir: str):

    with open(f"{current_dir}\compliance_auth.json", "r") as inf:  # read as bytes
        data = json.load(inf)

    req_id = data["req_id"]
    token = data["token"]
    secret = data["secret"]

    try:
        response = get_production_csid(req_id, token, secret)

        req_id = response.get('requestID')
        secret = response.get('secret')
        token = response.get('binarySecurityToken')

        output_data = {
            "req_id": req_id,
            "secret": secret,
            "token": token
        }


        with open(f"{output_dir}/productionn_auth.json", "w+") as outf:
            outf.write(json.dumps(output_data, indent=4))

        click.echo(f"Compliance CSID retrieved, details saved at {output_dir}/compliance_auth.json")

    except Exception as e:
        click.UsageError(str(e))

mycommands.add_command(generate_psid)

class InvoiceLine(TypedDict):
    name: str
    quantity: str
    unit_price: str
    vat_rate: str


if __name__ == "__main__":
    mycommands()
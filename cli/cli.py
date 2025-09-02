import base64
from datetime import datetime
import click
import uuid
import os
import json
from typing import TypedDict
from pathlib import Path
from cli.csr_generation.zatca_csr_gen import GenerateCSR
from cli.invoices.invoice_compliance import get_compliance_csid, get_production_csid

current_dir = os.getcwd()

# ---------------- GLOBAL APP ---------------- #
@click.group()
@click.option("--env", type=click.Choice(["sandbox", "simulation", "production"]), default="sandbox",
              help="The environment to use for commands.")
@click.pass_context
def mycommands(ctx, env):
    """CLI for ZATCA CSR & CSID workflows."""
    ctx.ensure_object(dict)
    ctx.obj["env"] = env
    ctx.obj["base_dir"] = current_dir


# ---------------- COMMAND: CSR ---------------- #
@mycommands.command()
@click.option("--C", default="SA", help="Country code")
@click.option("--CN", default=None, help="Common Name")
@click.option("--O", default="Gandofly", help="Organization Name")
@click.option("--OU", default="Jaddah Branch", help="Organizational Unit")
@click.option("--SN", default=None, help="Serial Number")
@click.option("--UID", required=True, default="399999999900003", help="VAT registration number")
@click.option("--TITLE", default="1000", help="Title")
@click.option("--CATEGORY", default="restaurant", help="Category")
@click.option("--ADDRESS", default="King Fahd Road, Riyadh, 12345", help="Address")
@click.option("--egs_uuid", default=None, help="Unique ID for this CSR")
@click.option("--output-dir", default=current_dir, help="Directory to save generated files")
@click.pass_context
def generate_csr(ctx, c, cn, o, ou, sn, uid, title, category, address, egs_uuid, output_dir):
    """Step 1: Generate a CSR based on environment."""
    env = ctx.obj["env"]

    if egs_uuid is None:
        egs_uuid = str(uuid.uuid4())
    if cn is None:
        prefix = {"sandbox": "TST", "simulation": "SIM", "production": "PRD"}[env]
        cn = f"{prefix}-{egs_uuid}"
    if sn is None:
        sn = f"1-MicroPOS|2-1.0.0|3-{egs_uuid}"

    generator = GenerateCSR()
    result = generator.generate_csr(
        csr_type=env,
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
        output_dir=os.path.join(output_dir, "csrs")
    )
    click.echo(result)


def resolve_dir_path(dir: str) -> Path:
    dir_path = Path(dir)

    # If user gave a relative path → make it relative to current_dir
    if not dir_path.is_absolute():
        dir_path = Path(current_dir) / dir_path

    return dir_path.resolve()

# ---------------- COMMAND: CCSID ---------------- #
@mycommands.command()
@click.option("--csr-dir", default=os.path.join(current_dir, "csrs"), help="Directory containing CSR file.")
@click.option("--otp", required=True, help="The OTP provided by ZATCA.")
@click.option("--output-dir", default=current_dir, help="Output directory.")
@click.pass_context
def generate_ccsid(ctx, csr_dir, otp, output_dir):
    """Step 2: Request Compliance CSID using CSR + OTP."""
    env = ctx.obj["env"]

    if not otp.isdigit() or len(otp) != 6:
        raise click.UsageError("OTP must be a 6-digit string.")

    csr_path = resolve_dir_path(csr_dir) / "csrs" / "certificate.csr"

    if not os.path.exists(csr_path):
        raise click.UsageError(f"CSR file not found at {csr_path}")

    with open(csr_path, "rb") as inf:
        cert_bytes = inf.read()
        cert_64 = base64.b64encode(cert_bytes).decode("utf-8")

    try:
        response = get_compliance_csid(cert_64, otp)
        output_data = {
            "req_id": response.get("requestID"),
            "secret": response.get("secret"),
            "token": response.get("binarySecurityToken"),
            "env": env
        }

        out_file = os.path.join(output_dir, "compliance_auth.json")
        with open(out_file, "w+") as outf:
            json.dump(output_data, outf, indent=4)

        click.echo(f"Compliance CSID retrieved, saved at {out_file}")

    except Exception as e:
        raise click.ClickException(str(e))


# ---------------- COMMAND: PRODUCTION CSID ---------------- #
@mycommands.command()
@click.option("--csid-dir", default=current_dir, help="Directory containing compliance_auth.json.")
@click.option("--output-dir", default=current_dir, help="Output directory.")
@click.pass_context
def generate_pcsid(ctx, csid_dir, output_dir):
    """Step 3: Request Production CSID using Compliance CSID."""

    auth_path = resolve_dir_path(csid_dir) / "compliance_auth.json"

    if not os.path.exists(auth_path):
        raise click.UsageError(f"Compliance auth file not found at {auth_path}")

    with open(auth_path, "r") as inf:
        data = json.load(inf)

    try:
        response = get_production_csid(data["req_id"], data["token"], data["secret"])
        output_data = {
            "req_id": response.get("requestID"),
            "secret": response.get("secret"),
            "token": response.get("binarySecurityToken"),
            "env": ctx.obj["env"]
        }

        out_file = os.path.join(output_dir, "production_auth.json")
        with open(out_file, "w+") as outf:
            json.dump(output_data, outf, indent=4)

        click.echo(f"Production CSID retrieved, saved at {out_file}")

    except Exception as e:
        raise click.ClickException(str(e))


# ---------------- CLI ENTRY ---------------- #
class InvoiceLine(TypedDict):
    name: str
    quantity: str
    unit_price: str
    vat_rate: str


if __name__ == "__main__":
    mycommands(obj={})

import os
import subprocess
import base64
import tempfile
import uuid


class GenerateCSR:
    def run_command(self, command, cwd=None):
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd)
        if result.returncode != 0:
            raise Exception(f"Command failed: {result.stderr.strip()}")
        return result

    def generate_keys(self, working_dir):
        priv_file = os.path.join(working_dir, "PrivateKey.pem")
        pub_file = os.path.join(working_dir, "PublicKey.pem")

        # Generate EC private key
        self.run_command(
            ['openssl', 'ecparam', '-name', 'secp256k1', '-genkey', '-noout', '-out', priv_file],
            cwd=working_dir
        )
        # Generate public key
        self.run_command(
            ['openssl', 'ec', '-in', priv_file, '-pubout', '-out', pub_file],
            cwd=working_dir
        )
        return priv_file, pub_file

    def create_configuration(self, working_dir, egs_uuid, ctn, **data):
        default_cnf = os.path.join(os.path.dirname(__file__), "default.cnf")
        cfg_path = os.path.join(working_dir, f"openssl_config.cnf")

        with open(default_cnf, "r") as f:
            content = f.read()

        replacements = {
            "{{COMMON_NAME}}": data.get("CN", ""),
            "{{ORG_NAME}}": data.get("O", ""),
            "{{ORG_UNIT}}": data.get("OU", ""),
            "{{SERIAL_NUMBER}}": data.get("SN", ""),
            "{{UID}}": data.get("UID", ""),
            "{{ADDRESS}}": data.get("ADDRESS", ""),
            "{{CATEGORY}}": data.get("CATEGORY", ""),
            "{{COUNTRY}}": data.get("C", "SA"),
            "{{CERTIFICATE_TEMPLATE_NAME}}": ctn,

        }

        for k, v in replacements.items():
            content = content.replace(k, v)


        with open(cfg_path, "w") as f:
            f.write(content)

        return cfg_path

    def generate_csr(
            self,
            csr_type,
            C,
            CN,
            O,
            OU,
            SN,
            UID,
            TITLE,
            CATEGORY,
            ADDRESS,
            egs_uuid,
            output_dir=None  # 👈 new argument
    ):
        # If no directory is passed, fall back to current directory
        if output_dir is None:
            output_dir = os.getcwd()

        os.makedirs(output_dir, exist_ok=True)

        # 🔑 Generate key pair
        key_file, pub_file = self.generate_keys(output_dir)

        # 📛 Select certificate template name
        if csr_type == "sandbox":
            ctn = "TSTZATCA"
        elif csr_type == "simulation":
            ctn = "PREZATCA"
        else:
            ctn = "ZATCA"

        # ⚙️ Create config file
        cfg_path = self.create_configuration(
            output_dir, egs_uuid, ctn=ctn,
            C=C, CN=CN, O=O, OU=OU, SN=SN,
            UID=UID, TITLE=TITLE, CATEGORY=CATEGORY,
            ADDRESS=ADDRESS
        )

        csr_file = os.path.join(output_dir, f"certificate.csr")

        try:
            self.run_command([
                "openssl", "req", "-new", "-sha256",
                "-key", key_file,
                "-config", cfg_path,
                "-out", csr_file
            ], cwd=output_dir)
        except Exception as e:
            print("[ERROR] OpenSSL failed while generating CSR")
            print(str(e))
            return {"status": 500, "error": str(e)}

        # Read outputs
        with open(csr_file, "rb") as f:
            csr_base64 = base64.b64encode(f.read()).decode("ascii")

        with open(key_file, "r") as f:
            private_key = f.read()
        with open(pub_file, "r") as f:
            public_key = f.read()

        return {
            "status": 200,
            "certificate_signing_request": csr_base64,
            "private_key": private_key,
            "public_key": public_key,
            "egs_uuid": egs_uuid,
            "csr_file": csr_file,
            "config_file": cfg_path,
            "private_key_file": key_file,
            "public_key_file": pub_file
        }


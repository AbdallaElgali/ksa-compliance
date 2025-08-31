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

    def generate_keys(self, working_dir, egs_uuid):
        priv_file = os.path.join(working_dir, f"PrivateKey_{egs_uuid}.pem")
        pub_file = os.path.join(working_dir, f"PublicKey_{egs_uuid}.pem")

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
        cfg_path = os.path.join(working_dir, f"openssl_{egs_uuid}.cnf")

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

    def generate_csr(self, csr_type, C, CN, O, OU, SN, UID, TITLE, CATEGORY, ADDRESS, egs_uuid):


        with tempfile.TemporaryDirectory() as tmpdir:
            key_file, pub_file = self.generate_keys(tmpdir, egs_uuid)

            if csr_type == "sandbox":
                ctn = "TSTZATCA"
            elif csr_type == "simulation":
                ctn = "PREZATCA"
            else:
                ctn = "ZATCA"

            cfg_path = self.create_configuration(
                tmpdir, egs_uuid, ctn=ctn,
                C=C, CN=CN, O=O, OU=OU, SN=SN,
                UID=UID, TITLE=TITLE, CATEGORY=CATEGORY,
                ADDRESS=ADDRESS
            )

            # 🔹 Show the generated OpenSSL config
            print(f"\n[INFO] Generated OpenSSL config at: {cfg_path}")
            with open(cfg_path, "r") as f:
                pass
                #print(f.read())

            csr_file = os.path.join(tmpdir, f"cert_{egs_uuid}.csr")

            try:
                self.run_command([
                    "openssl", "req", "-new", "-sha256",
                    "-key", key_file,
                    "-config", cfg_path,
                    "-out", csr_file
                ], cwd=tmpdir)

            except Exception as e:
                print("[ERROR] OpenSSL failed while generating CSR")
                print(str(e))
                return {"status": 500, "error": str(e)}

            with open(csr_file, "rb") as f:
                print(csr_file)
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
                "egs_uuid": egs_uuid
            }

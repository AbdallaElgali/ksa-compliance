import os
from dotenv import load_dotenv

# 1️⃣ Load the base ".env" first
load_dotenv(".env")  # common/shared values

# 2️⃣ Determine specific environment
ENV = os.getenv("APP_ENV", "sandbox").lower()  # default to sandbox

env_file_map = {
    "sandbox": ".env.sandbox",
    "simulation": ".env.simulation",
    "prod": ".env.prod"
}

# 3️⃣ Load the specific env file, overriding base values
specific_env_file = env_file_map.get(ENV)
if specific_env_file:
    load_dotenv(specific_env_file, override=True)

# 4️⃣ Access variables
EINVOICING_URL = os.getenv("EINVOICING_API")
API_EXT = os.getenv("API_EXT")

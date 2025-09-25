"""
gitleaks_prod.py

Gitleaks is not available on Debian which streamlit community clouds uses.

This is utility functions for managing the Gitleaks binary in production environments
(e.g., Streamlit Community Cloud) where direct package installation via apt/brew
is not possible.

This module ensures that the Gitleaks CLI tool is available at runtime by:

1. Checking if Gitleaks is already installed on the system.
2. Downloading the official prebuilt Linux binary from GitHub Releases if not.
3. Extracting it into a writable directory (/tmp) and making it executable.
4. Returning the path to the binary so it can be invoked with subprocess.

Notes:
- Pin the `GITLEAKS_VERSION` environment variable (default: v8.18.4) to control
  which release is downloaded.
- This approach avoids relying on apt/brew and keeps the app portable across
  cloud deployments.
- On Streamlit Community, binaries should be placed under `/tmp` since it is
  writable at runtime.

"""
import os
import shutil
import subprocess
import logging

GITLEAKS_VERSION = os.getenv("GITLEAKS_VERSION", "v8.18.4")
GITLEAKS_PATH = "/tmp/gitleaks"

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def ensure_gitleaks():
    if shutil.which("gitleaks"):
        return "gitleaks"

    if not os.path.exists(GITLEAKS_PATH):
        logger.info("Fetching gitleaks from github")
        url = f"https://github.com/gitleaks/gitleaks/releases/download/{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_linux_x64.tar.gz"
        tar_path = "/tmp/gitleaks.tar.gz"

        logger.info("set temperory path for logger")
        subprocess.run(["wget", "-q", url, "-O", tar_path], check=True)
        subprocess.run(["tar", "-xzf", tar_path, "-C", "/tmp"], check=True)

        logger.info("setting up gitleaks")
        if not os.path.exists(GITLEAKS_PATH):
            for f in os.listdir("/tmp"):
                if f == "gitleaks" or f.startswith("gitleaks"):
                    os.rename(os.path.join("/tmp", f), GITLEAKS_PATH)
                    break
        os.chmod(GITLEAKS_PATH, 0o755)
        logger.info("Gitleaks setup seccessfull")

    return GITLEAKS_PATH

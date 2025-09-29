"""
Prod Shift file contains changes needed to be done on prod which are different from local host

Gitleaks is not available on Debian which streamlit community cloud uses.

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

Secondly Class Extract is used to extract zip files on the prod as accepting folder path is not possible only accepting zip file is possible

"""

import os
import shutil
import subprocess
import logging
import zipfile
import tempfile
from pathlib import Path
from typing import Iterable
from termcolor import colored
from dotenv import load_dotenv

load_dotenv()


GITLEAKS_VERSION = os.getenv("GITLEAKS_VERSION", "v8.18.4")
GITLEAKS_PATH = os.getenv("GITLEAKS_PATH", "/tmp/gitleaks")

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


def ensure_gitleaks():
    if shutil.which("gitleaks"):
        return "gitleaks"

    if not os.path.exists(GITLEAKS_PATH):
        logger.info("Fetching gitleaks from github")
        url = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_linux_x64.tar.gz"
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

    return str(GITLEAKS_PATH)


class Extract:
    CODE_EXTS = (".py",)

    @staticmethod
    def resolve_dest_folder(arg: str):
        host = os.getenv("HOST", "localhost").lower()

        base_path_lh = Path.cwd() / "user_project"
        base_path_prod = Path(tempfile.gettempdir()) / "user_project"

        if host == "localhost":
            base = base_path_lh
        elif host == "prod":
            base = base_path_prod
        else:
            raise ValueError(f"Unsupported HOST: {host}")

        return base / "single_file" if arg == "file" else base

    @staticmethod
    def safe_extract_zip(zf: zipfile.ZipFile, dest: Path, ignore_hidden_top_level=True):
        """Safely extract ZIP into dest, preventing zip-slip.
        Optionally skip top-level hidden/metadata entries ('.*', likely junk).
        """
        dest = dest.resolve()
        for member in zf.infolist():
            # Normalize and guard against traversal
            member_path = Path(member.filename)
            # Optionally skip hidden top-level entries (e.g., .git/, .DS_Store, __MACOSX/)
            if ignore_hidden_top_level and len(member_path.parts) > 0:
                top = member_path.parts[0]
                if top.startswith("."):
                    continue  # skip .git, .DS_Store, etc.

            # Final resolved path
            target_path = (dest / member.filename).resolve()
            if not str(target_path).startswith(str(dest)):
                raise RuntimeError(f"Blocked unsafe path: {member.filename}")

            if member.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
            else:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(target_path, "wb") as out:
                    out.write(src.read())

    @staticmethod
    def count_code_files(root: Path, exts: Iterable[str]) -> int:
        n = 0
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in exts:
                n += 1
        return n

    @staticmethod
    def find_best_project_root(base: Path, exts: Iterable[str] = CODE_EXTS) -> Path:
        """Heuristic:
        1) If base has code files directly, use base.
        2) Else, among base's subdirs, pick the one with the most code files.
        3) If tie or none have code, fall back to base.
        This avoids relying on specific folder names like __MACOSX.
        """
        # 1) Code at base?
        if any(
            p.is_file() and p.suffix.lower() in exts
            for p in base.iterdir()
            if p.is_file()
        ):
            return base

        # 2) Choose subdir with most code files
        candidates = [d for d in base.iterdir() if d.is_dir()]
        if not candidates:
            return base

        best = None
        best_count = -1
        for d in candidates:
            cnt = Extract.count_code_files(d, exts)
            if cnt > best_count:
                best = d
                best_count = cnt

        # 3) Fallback
        return best if best and best_count > 0 else base

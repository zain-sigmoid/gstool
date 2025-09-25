import streamlit as st
import subprocess
import json
import os
import requests
from datetime import datetime, timedelta

# --- CONFIGURATION ---
UNMAINTAINED_THRESHOLD_DAYS = 365
# Define problematic licenses (case-insensitive)
PROBLEMATIC_LICENSES = {"gpl", "lgpl", "agpl"}

st.title("🔍 Python Dependency Security & Maintenance Audit")

uploaded_path = st.text_input("📂 Enter path to folder or requirements.txt file")

def run_pip_audit(req_path):
    result = subprocess.run(
        ["pip-audit", "--local", "-r", req_path, "--format", "json"],
        capture_output=True,
        text=True
    )
    try:
        return json.loads(result.stdout).get("dependencies", [])
    except json.JSONDecodeError:
        st.error("⚠️ Failed to parse pip-audit output as JSON.")
        st.code(result.stdout)
        return []

def run_pip_licenses(req_path):
    try:
        with open(req_path) as f:
            packages = [line.strip().split("==")[0] for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        st.error(f"Failed to read requirements.txt: {e}")
        return []
    command = [
        "pip-licenses",
        "--from=mixed",
        "--format=json",
        "--packages",
        *packages
    ]
    result = subprocess.run(
        command,
        cwd=os.path.dirname(req_path) or None,
        capture_output=True,
        text=True
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        st.error("⚠️ Failed to parse pip-licenses output as JSON.")
        st.code(result.stdout)
        return []

def check_unmaintained(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return None
        data = resp.json()
        latest_upload = None
        for version, files in data.get("releases", {}).items():
            for file in files:
                upload_time = datetime.fromisoformat(file["upload_time_iso_8601"].rstrip("Z"))
                if not latest_upload or upload_time > latest_upload:
                    latest_upload = upload_time
        if latest_upload:
            age = datetime.utcnow() - latest_upload
            return age.days > UNMAINTAINED_THRESHOLD_DAYS, latest_upload.date()
        return None
    except requests.RequestException:
        return None

if uploaded_path:
    if os.path.isdir(uploaded_path):
        req_path = os.path.join(uploaded_path, "requirements.txt")
    else:
        req_path = uploaded_path

    if not os.path.isfile(req_path):
        st.error(f"`requirements.txt` not found at: {req_path}")
    else:
        # --- Vulnerability Report ---
        st.header("🛡️ Vulnerability Report")
        with st.spinner("Running pip-audit..."):
            deps = run_pip_audit(req_path)
        vulnerable = [d for d in deps if d.get("vulns")]
        non_vulnerable = [d for d in deps if not d.get("vulns")]
        
        # Problematic Section
        st.subheader("🚨 Problematic Packages")
        if vulnerable:
            st.error(f"❌ Detected {len(vulnerable)} vulnerable package{'s' if len(vulnerable) > 1 else ''}!")
            for d in vulnerable:
                with st.expander(f"📦 {d['name']} v{d['version']}", expanded=True):
                    for v in d["vulns"]:
                        st.warning(f"**Vulnerability ID:** {v['id']}")
                        st.markdown(f"- **Aliases:** {', '.join(v.get('aliases', [])) or 'None'}")
                        st.markdown(f"- **Description:** {v.get('description', 'N/A')}")
                        fixes = v.get("fix_versions", [])
                        st.markdown(f"- **Fix Version:** {fixes[0] if fixes else 'None'}")
                        st.markdown("---")
        else:
            st.success("✅ No vulnerable packages found!")
        
        # Non-Problematic Section
        st.subheader("✅ Non-Problematic Packages")
        if non_vulnerable:
            st.info(f"ℹ️ {len(non_vulnerable)} package{'s' if len(non_vulnerable) > 1 else ''} with no known vulnerabilities.")
            for d in non_vulnerable:
                with st.expander(f"📦 {d['name']} v{d['version']}", expanded=False):
                    st.info("✅ No vulnerabilities detected for this package.")
        else:
            st.info("ℹ️ No non-vulnerable packages to display.")

        # --- License Report ---
        st.header("📜 License Report")
        with st.spinner("Gathering license information with pip-licenses…"):
            licenses = run_pip_licenses(req_path)
        if licenses:
            problematic_licenses = [
                pkg for pkg in licenses
                if pkg.get("License") and any(
                    pl.lower() in pkg.get("License", "").lower()
                    for pl in PROBLEMATIC_LICENSES
                )
            ]
            non_problematic_licenses = [
                pkg for pkg in licenses if pkg not in problematic_licenses
            ]
            
            # Problematic Section
            st.subheader("🚨 Problematic Licenses")
            if problematic_licenses:
                st.error(f"❌ Found {len(problematic_licenses)} package{'s' if len(problematic_licenses) > 1 else ''} with problematic licenses!")
                for pkg in problematic_licenses:
                    name = pkg.get("Name") or pkg.get("name")
                    lic = pkg.get("License") or "Unknown"
                    ver = pkg.get("Version") or "Unknown"
                    with st.expander(f"📦 {name} v{ver}", expanded=True):
                        st.warning(f"- **License:** {lic} (Problematic)")
            else:
                st.success("✅ No problematic licenses (e.g., GPL, LGPL, AGPL) found!")
            
            # Non-Problematic Section
            st.subheader("✅ Non-Problematic Licenses")
            if non_problematic_licenses:
                st.info(f"ℹ️ {len(non_problematic_licenses)} package{'s' if len(non_problematic_licenses) > 1 else ''} with non-problematic licenses.")
                for pkg in non_problematic_licenses:
                    name = pkg.get("Name") or pkg.get("name")
                    lic = pkg.get("License") or "Unknown"
                    ver = pkg.get("Version") or "Unknown"
                    with st.expander(f"📦 {name} v{ver}", expanded=False):
                        st.info(f"- **License:** {lic}")
            else:
                st.info("ℹ️ No non-problematic licenses to display.")
        else:
            st.warning("⚠️ No license information retrieved.")

        # --- Unmaintained Packages Report ---
        st.header("🕰️ Unmaintained Packages Report")
        with st.spinner("Checking for unmaintained packages via PyPI…"):
            unmaintained_packages = []
            maintained_packages = []
            unknown_status = []
            for d in deps:
                name = d["name"]
                unmaintained = check_unmaintained(name)
                if unmaintained is None:
                    unknown_status.append(name)
                else:
                    is_old, last_date = unmaintained
                    if is_old:
                        unmaintained_packages.append((name, last_date))
                    else:
                        maintained_packages.append((name, last_date))
            
            # Problematic Section
            st.subheader("🚨 Problematic (Unmaintained) Packages")
            if unmaintained_packages:
                st.error(f"❌ Found {len(unmaintained_packages)} unmaintained package{'s' if len(unmaintained_packages) > 1 else ''}!")
                for name, last_date in unmaintained_packages:
                    with st.expander(f"📦 {name}", expanded=True):
                        st.warning(f"- **Last Updated:** {last_date}")
                        st.markdown(f"- **Status:** Not updated in over {UNMAINTAINED_THRESHOLD_DAYS} days")
            else:
                st.success(f"✅ No packages found unmaintained (older than {UNMAINTAINED_THRESHOLD_DAYS} days)!")
            
            # Non-Problematic Section
            st.subheader("✅ Non-Problematic (Maintained) Packages")
            if maintained_packages:
                st.info(f"ℹ️ {len(maintained_packages)} package{'s' if len(maintained_packages) > 1 else ''} are actively maintained.")
                for name, last_date in maintained_packages:
                    with st.expander(f"📦 {name}", expanded=False):
                        st.info(f"- **Last Updated:** {last_date}")
                        st.markdown("- **Status:** Actively maintained")
            else:
                st.info("ℹ️ No maintained packages to display.")
            
            # Unknown Status
            if unknown_status:
                st.subheader("⚠️ Unknown Maintenance Status")
                st.warning(f"⚠️ Could not determine maintenance status for {len(unknown_status)} package{'s' if len(unknown_status) > 1 else ''}:")
                for name in unknown_status:
                    with st.expander(f"📦 {name}", expanded=True):
                        st.markdown("- **Status:** Unable to retrieve maintenance information")
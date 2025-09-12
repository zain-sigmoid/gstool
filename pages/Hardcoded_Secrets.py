import subprocess
import json
import os
import streamlit as st
from typing import List, Dict, Optional
import pandas as pd


def map_rule_to_cwe(rule_id: str) -> Dict[str, str]:
    """
    Map Gitleaks rule IDs to CWE codes and provide web links.
    """
    cwe_mapping = {
        # AWS and Cloud credentials
        "aws-access-token": {
            "cwe": "CWE-798",
            "description": "Hardcoded Credentials",
            "url": "https://cwe.mitre.org/data/definitions/798.html",
        },
        "aws-secret-key": {
            "cwe": "CWE-798",
            "description": "Hardcoded Credentials",
            "url": "https://cwe.mitre.org/data/definitions/798.html",
        },
        "aws-mws-key": {
            "cwe": "CWE-798",
            "description": "Hardcoded Credentials",
            "url": "https://cwe.mitre.org/data/definitions/798.html",
        },
        "aws-session-token": {
            "cwe": "CWE-522",
            "description": "Insufficiently Protected Credentials",
            "url": "https://cwe.mitre.org/data/definitions/522.html",
        },
        # API Keys and Tokens
        "github-pat": {
            "cwe": "CWE-522",
            "description": "Insufficiently Protected Credentials",
            "url": "https://cwe.mitre.org/data/definitions/522.html",
        },
        "github-oauth": {
            "cwe": "CWE-522",
            "description": "Insufficiently Protected Credentials",
            "url": "https://cwe.mitre.org/data/definitions/522.html",
        },
        "gitlab-pat": {
            "cwe": "CWE-522",
            "description": "Insufficiently Protected Credentials",
            "url": "https://cwe.mitre.org/data/definitions/522.html",
        },
        "google-api-key": {
            "cwe": "CWE-321",
            "description": "Use of Hard-coded Cryptographic Key",
            "url": "https://cwe.mitre.org/data/definitions/321.html",
        },
        "slack-access-token": {
            "cwe": "CWE-522",
            "description": "Insufficiently Protected Credentials",
            "url": "https://cwe.mitre.org/data/definitions/522.html",
        },
        "discord-api-token": {
            "cwe": "CWE-522",
            "description": "Insufficiently Protected Credentials",
            "url": "https://cwe.mitre.org/data/definitions/522.html",
        },
        # Database credentials
        "mysql": {
            "cwe": "CWE-798",
            "description": "Hardcoded Credentials",
            "url": "https://cwe.mitre.org/data/definitions/798.html",
        },
        "postgres": {
            "cwe": "CWE-798",
            "description": "Hardcoded Credentials",
            "url": "https://cwe.mitre.org/data/definitions/798.html",
        },
        "mongodb": {
            "cwe": "CWE-798",
            "description": "Hardcoded Credentials",
            "url": "https://cwe.mitre.org/data/definitions/798.html",
        },
        # Generic passwords and keys
        "password": {
            "cwe": "CWE-259",
            "description": "Use of Hard-coded Password",
            "url": "https://cwe.mitre.org/data/definitions/259.html",
        },
        "private-key": {
            "cwe": "CWE-321",
            "description": "Use of Hard-coded Cryptographic Key",
            "url": "https://cwe.mitre.org/data/definitions/321.html",
        },
        "jwt": {
            "cwe": "CWE-522",
            "description": "Insufficiently Protected Credentials",
            "url": "https://cwe.mitre.org/data/definitions/522.html",
        },
        "api-key": {
            "cwe": "CWE-321",
            "description": "Use of Hard-coded Cryptographic Key",
            "url": "https://cwe.mitre.org/data/definitions/321.html",
        },
        "secret": {
            "cwe": "CWE-798",
            "description": "Hardcoded Credentials",
            "url": "https://cwe.mitre.org/data/definitions/798.html",
        },
    }

    # Check for partial matches if exact match not found
    for key in cwe_mapping:
        if key.lower() in rule_id.lower():
            return cwe_mapping[key]

    # Default mapping if no match found
    return {
        "cwe": "CWE-798",
        "description": "Hardcoded Credentials",
        "url": "https://cwe.mitre.org/data/definitions/798.html",
    }


def scan_secrets_with_gitleaks(source_path: str) -> Optional[List[Dict]]:
    """
    Run Gitleaks on the specified source path and return parsed results.

    Args:
        source_path (str): Path to the file or folder to scan

    Returns:
        List[Dict]: List of detected secrets with their details, or None if error
    """
    try:
        # Verify the source path exists
        if not os.path.exists(source_path):
            st.error(f"Path does not exist: {source_path}")
            return None

        # Create a temporary file for the report
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".json", delete=False
        ) as temp_file:
            temp_report_path = temp_file.name
        gitleaks_toml_path = "../utils/gitleaks.toml"
        try:
            # Construct the gitleaks command with output to file
            # cmd = [
            #     "gitleaks",
            #     "detect",
            #     "--source",
            #     source_path,
            #     "--no-git",
            #     "--report-format",
            #     "json",
            #     "--report-path",
            #     temp_report_path,
            # ]
            cmdv2 = [
                "gitleaks",
                "dir",
                source_path,
                "-c",
                gitleaks_toml_path,
                "-f",
                "json",
                "-r",
                temp_report_path,
            ]

            # Run the command
            result = subprocess.run(
                cmdv2, capture_output=True, text=True, timeout=60  # 60 second timeout
            )

            # # Debug information
            # st.write(f"**Debug Info:**")
            # st.write(f"- Exit code: {result.returncode}")
            # st.write(f"- Stdout length: {len(result.stdout) if result.stdout else 0}")
            # st.write(f"- Stderr length: {len(result.stderr) if result.stderr else 0}")

            # if result.stderr:
            #     st.write(f"- Stderr content: {result.stderr[:500]}...")

            # Gitleaks returns exit code 1 when secrets are found, 0 when none found
            if result.returncode == 0:
                st.info("✅ No secrets detected!")
                return []
            elif result.returncode == 1:
                # Check if report file was created and has content
                if os.path.exists(temp_report_path):
                    with open(temp_report_path, "r") as f:
                        report_content = f.read().strip()

                    st.write(f"- Report file size: {len(report_content)} characters")

                    if report_content:
                        try:
                            secrets_data = json.loads(report_content)
                            return (
                                secrets_data
                                if isinstance(secrets_data, list)
                                else [secrets_data]
                            )
                        except json.JSONDecodeError as e:
                            st.error(f"Failed to parse JSON from report file: {e}")
                            st.text("Raw report content:")
                            st.text(
                                report_content[:1000]
                                + ("..." if len(report_content) > 1000 else "")
                            )
                            return None
                    else:
                        st.warning("Report file is empty despite exit code 1")

                # Fallback: try to parse stdout if available
                if result.stdout.strip():
                    try:
                        secrets_data = json.loads(result.stdout)
                        return (
                            secrets_data
                            if isinstance(secrets_data, list)
                            else [secrets_data]
                        )
                    except json.JSONDecodeError:
                        pass

                # Fallback: try to parse stderr as some versions output there
                if result.stderr.strip():
                    try:
                        # Sometimes gitleaks outputs JSON to stderr
                        secrets_data = json.loads(result.stderr)
                        return (
                            secrets_data
                            if isinstance(secrets_data, list)
                            else [secrets_data]
                        )
                    except json.JSONDecodeError:
                        pass

                st.warning(
                    "Gitleaks found issues but couldn't parse the output. This might be a gitleaks version issue."
                )
                st.info(
                    "Try running gitleaks manually: `gitleaks detect --source /your/path --no-git -v`"
                )
                return None

            else:
                # Other error codes
                st.error(f"Gitleaks failed with exit code {result.returncode}")
                if result.stderr:
                    st.error(f"Error details: {result.stderr}")
                return None

        finally:
            # Clean up temporary file
            if os.path.exists(temp_report_path):
                os.unlink(temp_report_path)

    except subprocess.TimeoutExpired:
        st.error("Gitleaks scan timed out after 60 seconds")
        return None
    except FileNotFoundError:
        st.error("Gitleaks not found. Please install Gitleaks first.")
        st.markdown(
            "Install instructions: https://github.com/gitleaks/gitleaks#installation"
        )
        return None
    except Exception as e:
        st.error(f"Unexpected error: {e}")
        return None


def format_secrets_summary(secrets: List[Dict]) -> List[Dict]:
    """
    Parse and format the secrets data into a human-readable summary.

    Args:
        secrets (List[Dict]): Raw secrets data from Gitleaks

    Returns:
        List[Dict]: Formatted summary of secrets
    """
    formatted_secrets = []

    for secret in secrets:
        rule_id = secret.get("RuleID", "Unknown")
        cwe_info = map_rule_to_cwe(rule_id)

        formatted_secret = {
            "Rule ID": rule_id,
            "Secret Type": secret.get("Description", "Unknown"),
            "File": secret.get("File", "Unknown"),
            "Start Line": secret.get("StartLine", "Unknown"),
            "End Line": secret.get("EndLine", "Unknown"),
            "Match": secret.get("Match", "Redacted"),
            "CWE Code": cwe_info["cwe"],
            "CWE Description": cwe_info["description"],
            "CWE URL": cwe_info["url"],
        }
        formatted_secrets.append(formatted_secret)

    return formatted_secrets


def main():
    st.set_page_config(
        page_title="Gitleaks Secret Scanner", page_icon="🔐", layout="wide"
    )

    st.title("🔐 Gitleaks Secret Scanner")
    st.markdown(
        "Scan your code for hardcoded secrets, API keys, passwords, and credentials"
    )

    # Sidebar with information
    with st.sidebar:
        st.header("About")
        st.markdown(
            """
        This tool uses **Gitleaks** to scan your code for:
        - API keys and tokens
        - Passwords and credentials  
        - AWS/Cloud secrets
        - Database connection strings
        - Private keys and certificates
        
        **CWE Mappings:**
        - **CWE-798**: Hardcoded Credentials
        - **CWE-321**: Hardcoded Cryptographic Keys
        - **CWE-259**: Hardcoded Passwords
        - **CWE-522**: Insufficiently Protected Credentials
        """
        )

        st.header("Prerequisites")
        st.markdown(
            """
        Make sure you have **Gitleaks** installed:
        ```bash
        # macOS
        brew install gitleaks
        
        # Linux/Windows
        # Download from: github.com/gitleaks/gitleaks/releases
        ```
        """
        )

    # Main interface
    st.header("Scan Configuration")

    # Path input
    source_path = st.text_input(
        "Enter path to scan:",
        placeholder="/path/to/your/code or /path/to/file.py",
        help="Enter the full path to a file or folder you want to scan",
    )

    # Additional options
    st.subheader("Scan Options")
    show_matches = st.checkbox(
        "Show actual secret values (⚠️ Security Risk)", value=False
    )

    # Scan button
    if st.button("🔍 Start Scan", type="primary", disabled=not source_path):
        if source_path:
            with st.spinner(f"Scanning {source_path} for secrets..."):
                secrets = scan_secrets_with_gitleaks(source_path)

            if secrets is not None:
                if len(secrets) == 0:
                    st.success("🎉 No secrets found! Your code looks clean.")
                else:
                    st.error(f"⚠️ Found {len(secrets)} potential secret(s)!")

                    # Format the results
                    formatted_secrets = format_secrets_summary(secrets)

                    # Display summary statistics
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Total Secrets Found", len(secrets))
                    with col2:
                        unique_files = len(set(s["File"] for s in formatted_secrets))
                        st.metric("Files Affected", unique_files)
                    with col3:
                        unique_rules = len(set(s["Rule ID"] for s in formatted_secrets))
                        st.metric("Secret Types", unique_rules)

                    # Display detailed results
                    st.subheader("🔍 Detailed Results")

                    for i, secret in enumerate(formatted_secrets, 1):
                        with st.expander(
                            f"Secret #{i}: {secret['Secret Type']} in {os.path.basename(secret['File'])}"
                        ):
                            col1, col2 = st.columns(2)

                            with col1:
                                st.markdown(f"**Rule ID:** `{secret['Rule ID']}`")
                                st.markdown(f"**File:** `{secret['File']}`")
                                st.markdown(
                                    f"**Lines:** {secret['Start Line']}-{secret['End Line']}"
                                )

                            with col2:
                                st.markdown(
                                    f"**CWE Code:** [{secret['CWE Code']}]({secret['CWE URL']})"
                                )
                                st.markdown(
                                    f"**Description:** {secret['CWE Description']}"
                                )

                                if show_matches and secret["Match"] != "Redacted":
                                    st.markdown(f"**Match:** `{secret['Match']}`")
                                else:
                                    st.markdown("**Match:** `[Redacted for security]`")

                    # Export options
                    st.subheader("📊 Export Results")

                    # Convert to DataFrame for export
                    df = pd.DataFrame(formatted_secrets)
                    if not show_matches:
                        df = df.drop("Match", axis=1)

                    col1, col2 = st.columns(2)
                    with col1:
                        csv = df.to_csv(index=False)
                        st.download_button(
                            label="📄 Download as CSV",
                            data=csv,
                            file_name="gitleaks_scan_results.csv",
                            mime="text/csv",
                        )

                    with col2:
                        json_data = json.dumps(formatted_secrets, indent=2)
                        st.download_button(
                            label="📋 Download as JSON",
                            data=json_data,
                            file_name="gitleaks_scan_results.json",
                            mime="application/json",
                        )

                    # Display table
                    st.subheader("📋 Summary Table")
                    display_df = df.copy()
                    if "CWE URL" in display_df.columns:
                        display_df = display_df.drop("CWE URL", axis=1)
                    st.dataframe(display_df, use_container_width=True)


if __name__ == "__main__":
    main()

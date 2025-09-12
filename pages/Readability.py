import streamlit as st
import subprocess
import os
import json

st.set_page_config(page_title="Readable Pylint", layout="wide")
st.title("📘 Pylint Code Analyzer — Readability Focused")

path = st.text_input("Enter a Python file or folder path:")

report_type = st.radio(
    "Choose Report Type:",
    ("Full report", "Readability-focused report"),
    horizontal=True
)

READABILITY_IDS = {
    "unused-import": "📦 Unused import",
    "invalid-name": "🔤 Bad naming",
    "bad-indentation": "⛔ Bad indentation",
    "missing-function-docstring": "📄 Missing function docstring",
    "missing-class-docstring": "📄 Missing class docstring",
    "bad-inline-comment": "💬 Poor inline comment formatting",
}

def run_pylint(file_path):
    try:
        result = subprocess.run(
            ["pylint", file_path, "-f", "json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.stderr:
            st.error(result.stderr)
        return json.loads(result.stdout) if result.stdout else []
    except Exception as e:
        st.exception(f"Error running pylint: {e}")
        return []

if st.button("Analyze"):
    if not os.path.exists(path):
        st.error("❌ Path does not exist.")
    else:
        with st.spinner("Running analysis..."):
            files = []
            if os.path.isdir(path):
                for root, dirs, filenames in os.walk(path):
                    for f in filenames:
                        if f.endswith(".py"):
                            files.append(os.path.join(root, f))
            elif path.endswith(".py"):
                files = [path]

            if not files:
                st.warning("⚠️ No Python files found.")
            else:
                for file in files:
                    st.markdown(f"### 📄 `{file}`")
                    messages = run_pylint(file)

                    if not messages:
                        st.success("✅ No issues found!")
                        continue

                    if report_type == "Readability-focused report":
                        filtered = [m for m in messages if m["symbol"] in READABILITY_IDS]
                        if not filtered:
                            st.success("✅ No readability issues found.")
                        else:
                            for msg in filtered:
                                kind = READABILITY_IDS.get(msg["symbol"], "🟢")
                                st.markdown(f"- {kind} at line {msg['line']}: `{msg['message']}`")
                    else:
                        for msg in messages[:20]:  # show top 20 messages only for full
                            st.markdown(f"- **{msg['type'].capitalize()}** `{msg['symbol']}` at line {msg['line']}: {msg['message']}")

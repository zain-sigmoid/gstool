import streamlit as st
import os
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from analyzers import ANALYZERS, SEVERITY_ORDER
from common.file_utils import find_python_files
from common.file_utils import AnalyzerOutput, Issue, run_single_analyzer
from pillars import cards_data


st.set_page_config(
    page_title="Code Quality and Security Dashboard",
    layout="wide",
)

CARD_CSS = """
<style>
.metric-card {
  border: 1px solid rgba(0,0,0,0.08);
  border-radius: 16px;
  padding: 18px 20px;
  background: white;
  box-shadow: 0 2px 10px rgba(0,0,0,0.03);
}
.metric-title {
  font-weight: 700;
  font-size: 1.05rem;
  display: flex; align-items: center; gap: .5rem;
}
.metric-score {
  font-weight: 800;
  font-size: 2.4rem;
  margin-top: 10px;
}
.metric-sub {
  color: #6b7280;
  font-weight: 600;
}
.pill {
  display: inline-block;
  background: #eef2ff;
  color: #4338ca;
  padding: 2px 10px;
  border-radius: 999px;
  font-size: .82rem;
  font-weight: 600;
}
.finding-card {
  border-left: 4px solid #f59e0b; /* orange for HIGH (demo) */
  border-radius: 10px;
  padding: 14px 16px;
  background: #fff;
  box-shadow: 0 2px 10px rgba(0,0,0,0.03);
}
.finding-title {
  font-weight: 700;
  font-size: 1.05rem;
}
.finding-path {
  color: #6b7280; font-size: .9rem; margin-top: 6px;
}
.finding-hint {
  margin-top: 8px; color: #1d4ed8; font-style: italic;
}
.badge-high   { background:#fef3c7; color:#b45309; }
.badge-med    { background:#e0f2fe; color:#075985; }
.badge-low    { background:#ecfdf5; color:#065f46; }
</style>
"""
st.markdown(CARD_CSS, unsafe_allow_html=True)

st.title("🧪 Code Quality Analyzer")

st.caption(
    "Provide a folder path. I’ll scan `*.py` recursively and run your analyzers. "
    "You’ll see live progress and a results dashboard with detailed findings."
)

with st.container(border=True):
    col1, col2 = st.columns([3, 1])
    folder = col1.text_input("Folder path", value="", placeholder="/path/to/your/repo-or-module")
    run_btn = col2.button("Run Analysis", type="primary", use_container_width=True, disabled=not folder)

if "results" not in st.session_state:
    st.session_state.results = None
if "raw_issues" not in st.session_state:
    st.session_state.raw_issues = []

if run_btn:
    if not os.path.isdir(folder):
        st.error("That path doesn’t look like a folder I can read. Please check and try again.")
        st.stop()

    py_files = find_python_files(folder)
    if not py_files:
        st.warning("No Python files found in this folder.")
        st.stop()

    st.session_state.results = None
    st.session_state.raw_issues = []

    st.subheader("⏳ Analysis in Progress")
    step_area = st.container()
    bar = st.progress(0)
    progress_val = 0.0
    per_step = 1.0 / max(1, len(ANALYZERS))

    with step_area:
        r1, r2, r3, r4, r5 = st.columns(5)
        dep = r1.status("Dependency Analysis", state="running")
        sec = r2.status("Security Analysis", state="running")
        rob = r3.status("Robustness Analysis", state="running")
        mai = r4.status("Maintainability Analysis", state="running")
        rea = r5.status("Readability Analysis", state="running")
        perf_placeholder = st.empty()  # extra row if you like
        perf = perf_placeholder.status("Performance Analysis", state="running")

    order_for_status = ["maintainability","performance"]
    status_map = {
        "dependency": dep, "security": sec, "robustness": rob,
        "maintainability": mai, "readability": rea, "performance": perf
    }

    for key in order_for_status:
        print(key)
        status_map[key].update(state="running")

    results: Dict[str, AnalyzerOutput] = {}
    with ThreadPoolExecutor(max_workers=min(6, len(ANALYZERS))) as ex:
        futures = {}
        for key, (_, fn) in ANALYZERS.items():
            status_map[key].update(state="running")
            futures[ex.submit(run_single_analyzer, key, fn, py_files)] = key

        for fut in as_completed(futures):
            key, out = fut.result()
            results[key] = out
            status_map[key].update(state="complete")
            progress_val = min(1.0, progress_val + per_step)
            bar.progress(progress_val)  # type: ignore[attr-defined]

    # persist
    st.session_state.results = results
    # flatten issues
    all_issues: List[Issue] = []
    for out in results.values():
        all_issues.extend(out.issues)
    st.session_state.raw_issues = all_issues
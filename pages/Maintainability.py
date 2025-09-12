import streamlit as st
import os
import re
from collections import Counter
from maintainability.maintainability_analyzer import MaintainabilityAnalyzer

# Styling for cards
st.markdown(
    """
    <style>
    .summary-cards {
        display: flex;
        gap: 1rem;
        margin: 1rem 0 2rem 0;
        justify-content: center;
        flex-wrap: wrap;
    }
    .summary-cards .card {
        flex: 1;
        min-width: 120px;
        max-width: 180px;
        text-align: start;
        padding: 1rem;
        border-radius: 10px;
        font-weight: bold;
        color: white;
        font-size: 1rem;
        box-shadow: 0 2px 6px rgba(0,0,0,0.1);
    }
    .card span {
        font-size: 1.5rem;
        display: block;
        margin-top: 0.3rem;
    }
    .card.high { background-color: #d32f2f; }
    .card.medium { background-color: #f57c00; }
    .card.low { background-color: #388e3c; }
    .card.info { background-color: #1976d2; }
    .finding-card {
        border-left: 6px solid orange;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 8px;
        background-color: #fff;
        box-shadow: 0 1px 4px rgba(0,0,0,0.05);
    }
    .finding-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: #f6f6f6;
        padding: 0.5rem 1rem;
        border-radius: 6px;
        margin-bottom: 0.5rem;
    }
    .finding-type {
        display: flex;
        gap: 10px;
    }
    .category-badge {
        background: #1976d2;
        color: white;
        padding: 2px 10px;
        border-radius: 5px;
        font-size: 0.85rem;
    }
    .type-badge {
        background: #dcdcdc;
        padding: 2px 10px;
        border-radius: 5px;
        font-size: 0.85rem;
    }
    .severity-badge {
        font-weight: bold;
        color: white;
        padding: 4px 12px;
        border-radius: 6px;
    }
    .severity-low { background-color: green; }
    .severity-medium { background-color: orange; }
    .severity-high { background-color: red; }
    .severity-info {background-color:#1976d2;}
    .finding-description {
        font-weight: 500;
        font-size: 1.05rem;
        margin-bottom: 0.3rem;
    }
    .finding-location {
        color: #555;
        font-size: 14px !important;
        margin-bottom: 0.5rem !important;
    }
    .finding-suggestion {
        background: #f4f6ff;
        padding-left:2rem;
        border-radius: 5px;
        color: #3b5bdb;
        font-style: italic;
    }
    .mi-scale {
        position: relative;
        height: 8px;
        width: 100%;
        background: linear-gradient(
            to right,
            #4CAF50 0%,      /* Green */
            #4CAF50 80%,     /* Green until 20 */
            #FF9800 81%,     /* Orange 19–10 */
            #FF9800 90%,
            #F44336 91%,     /* Red 9–0 */
            #F44336 100%
        );
        border-radius: 8px;
        margin-bottom: 0.5rem;
    }
    .mi-marker {
        position: absolute;
        top: -20px;
        transform: translateX(-50%);
        font-size: 18px;
        font-weight: bold;
        color: black;
    }
    .mi-labels {
        display: flex;
        justify-content: space-between;
        font-size: 0.7rem;
        margin-top: 4px;
        margin-bottom:10px;
    }
    .metric-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 8px;
        margin-top: 8px;
    }

    .metric-box {
        display: flex;
        justify-content: space-between;
        padding: 6px;
        background: white;
        border-radius: 4px;
        border: 1px solid #ddd;
    }

    .key {
        font-weight: bold;
        color: #555;
    }

    .value {
        color: #333;
    }
    .function-locations {
        padding: 10px 15px;
        border-radius: 6px;
        margin-top: 10px;
        font-size: 0.9rem;
    }
    .function-locations ul {
        padding-left: 1.2rem;
        margin: 0;
    }
    .function-locations .fun {
        padding: 2px 6px;
        border-radius: 4px;
        font-family: monospace;
        font-size:14px;
    }
    .code-fragment {
        color: #f8f8f2;
        padding: 10px;
        border-radius: 6px;
        font-size: 0.85rem;
        overflow-x: auto;
        white-space: pre-wrap;
        margin-top: 5px;
    }

    code {
        background-color: #e6f4ea;
        color: #22863a;
        padding: 2px 6px;
        border-radius: 4px;
        font-family: monospace;
        font-size: 0.95em;
    }
    </style>
""",
    unsafe_allow_html=True,
)

st.title("🧰 Maintainability Analyzer")

# For now, you can manually input the directory or set it
directory = st.text_input("📁 Enter path to Python project directory")

if directory and os.path.isdir(directory):
    analyzer = MaintainabilityAnalyzer(config={})
    analyzer.analyze(directory)
    findings = analyzer.findings
    severity_counts = Counter(f.get("severity", "unknown").lower() for f in findings)
    count_high = severity_counts.get("high", 0)
    count_medium = severity_counts.get("medium", 0)
    count_low = severity_counts.get("low", 0)
    count_info = severity_counts.get("info", 0)
    all_severities = ["All", "High", "Medium", "Low", "Info"]
    unique_files = ["All"] + sorted({f["file"] for f in findings if f.get("file")})
    st.markdown("## 🔍 Findings")
    st.markdown(
        f"""
            <div class="summary-cards">
                <div class="card high">🔥 High<br><span style="font-size:30px">{count_high}</span></div>
                <div class="card medium">⚠️ Medium<br><span style="font-size:30px">{count_medium}</span></div>
                <div class="card low">🟢 Low<br><span style="font-size:30px">{count_low}</span></div>
                <div class="card info">ℹ️ Info<br><span style="font-size:30px">{count_info}</span></div>
            </div>
        """,
        unsafe_allow_html=True,
    )

    # file maps for showing Short names
    file_map = {
        os.path.basename(f["file"]): f["file"] for f in findings if f.get("file")
    }
    type_display_map = {
        t: t.replace("_", " ").title()
        for t in {f["type"] for f in findings if f.get("type")}
    }
    all_metrics = ["All"] + sorted(type_display_map[t] for t in type_display_map)
    file_names_display = ["All"] + sorted(file_map.keys())
    # UI filters

    col1, col2, col3 = st.columns(3)

    with col1:
        selected_severity = st.selectbox("🔍 Filter by Severity", all_severities)
    with col2:
        selected_metric = st.selectbox("📊 Filter by Metric", all_metrics)
    with col3:
        selected_file = st.selectbox("📄 Filter by File", file_names_display)

    severity_order = {"high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(
        findings,
        key=lambda x: severity_order.get(x.get("severity", "medium").lower(), 99),
    )
    display_to_type = {v: k for k, v in type_display_map.items()}
    filtered_findings = findings_sorted

    if selected_severity != "All":
        filtered_findings = [
            f
            for f in filtered_findings
            if f.get("severity", "").lower() == selected_severity.lower()
        ]
    if selected_metric != "All":
        selected_type = display_to_type[selected_metric]
        filtered_findings = [
            f for f in filtered_findings if f.get("type") == selected_type
        ]

    if selected_file != "All":
        full_path = file_map[selected_file]
        filtered_findings = [f for f in filtered_findings if f.get("file") == full_path]

    # Sort findings by severity priority

    # Pagination setup
    per_page = 10
    total_pages = len(filtered_findings)
    start_idx = 0
    end_idx = 0
    if total_pages == 0:
        st.warning("No findings match the selected filters.")
    else:
        total_pages = (total_pages - 1) // per_page + 1
        page = st.number_input(
            "📄 Page", min_value=1, max_value=total_pages, value=1, step=1
        )

        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page

    findings_to_show = filtered_findings[start_idx:end_idx]

    # Display cards
    for f in findings_to_show:
        # category = f.get("category", "maintainability").capitalize()
        type_ = type_display_map.get(f.get("type", "unknown"), f.get("type", "Unknown"))
        severity = f.get("severity", "medium").lower()
        description = f.get("description", "No description available")
        description = re.sub(
            r'Function\s+"([^"]+)"', r"Function <code>\1</code>", description
        )
        description = re.sub(
            r'File\s+"([^"]+)"',
            r"File <code>\1</code>",
            description,
        )
        file_loc = f"{f.get('file', '')}:{f.get('line', '')}" if f.get("file") else ""
        suggestion = f.get("suggestion", "")
        mi_score = f.get("mi_score", None)
        locations = f.get("locations", "")
        details = f.get("details", {})
        # print(details)
        percentages = details.get("percentages", {})
        functions_by_risk = details.get("functions_by_risk", {})
        total_loc = details.get("total_loc")
        rank = details.get("rank")

        details_html = ""

        if percentages:
            details_html += "<div class='finding-details'><p><strong>Risk LOC Percentages:</strong></p><ul style='padding-left:4%'>"
            for level in ["moderate", "high", "very_high"]:
                if level in percentages:
                    details_html += f"<li>{level.title()}: {percentages[level]}%</li>"
            details_html += "</ul>"

        if functions_by_risk:
            details_html += "<p><strong>Functions by Risk Level:</strong></p><ul style='padding-left:4%'>"
            for level, funcs in functions_by_risk.items():
                details_html += f"<li><strong>{level.title()}:</strong><ul style='padding-left:6%;'>"
                for func in funcs:
                    details_html += f"<li>{func}</li>"
                details_html += "</ul></li>"
            details_html += "</ul>"

        if total_loc:
            details_html += f"<p><strong>Total LOC:</strong> {total_loc}</p>"
        if rank:
            details_html += (
                f"<p style='margin-top:-3%;'><strong>Rank:</strong> {rank}</p>"
            )

        details_html += "</div>" if details_html else ""

        if "loc" in details or "nesting_depth" in details or "tokens" in details:
            details_html = """
            <div class="finding-details">
            <p><strong>Details:</strong></p>
            <div class="metric-grid">
            """

            for k, v in details.items():
                pretty_key = k.replace("_", " ").title()
                details_html += f"""
                <div class="metric-box">
                <span class="key">{pretty_key}</span>
                <span class="value">{v}</span>
                </div>
                """

            details_html += """
            </div>
            </div>
            """

        scale_html = ""
        if f.get("type") == "maintainability_index" and mi_score is not None:
            marker_position = 100 - mi_score  # Reverse position: higher score on left

            scale_html = f"""
            <div class="mi-scale">
                <div class="mi-marker" style="left: {marker_position}%;">↓</div>
            </div>
            <div class="mi-labels">
                <span>High (100–20)</span>
                <span>Moderate (19–10)</span>
                <span>Low (9–0)</span>
            </div>
            """
        if isinstance(suggestion, str):
            suggestion = [suggestion]
        suggestion_html = ""
        if suggestion:
            suggestion_html = (
                "<div class='finding-suggestion'><strong>💡 Suggestions:</strong>"
                "<ul>"
            )
            for s in suggestion:
                suggestion_html += f"<li>{s}</li>"
            suggestion_html += "</ul></div>"

        location_html = """
        <div class="function-locations">
        <ul>
        """
        for loc in locations:
            location_html += f"<li class='fun'>{loc}</li>"
        location_html += "</ul></div>"

        card_html = f"""
        <div class="finding-card">
            <div class="finding-header">
                <div class="finding-type">
                    <span class="type-badge">{type_}</span>
                </div>
                <span class="severity-badge severity-{severity}">{severity.upper()}</span>
            </div>
            <div class="finding-content">
                <div>{scale_html}</div>
                <p class="finding-description">{description}</p>
                <div>{location_html}</div>
                <div>{details_html}</div>
                {'<p class="finding-location" style="margin-top:10px">📄 ' + file_loc + '</p>' if file_loc else ''}
                <div>{suggestion_html}</div>
            </div>
        </div>
        """
        # st.markdown(card_html, unsafe_allow_html=True)
        st.html(card_html)

    # Show navigation
    if total_pages > 0:
        st.markdown(f"Page {page} of {total_pages}")

elif directory:
    st.error("Invalid directory")

import streamlit as st
import os
import re
from collections import Counter
from analyzers.performance_analyzer import PerformanceAnalyzer

st.sidebar.title("🧭 Navigation")
page = st.sidebar.radio("Go to", ["Introduction", "Analyzer Dashboard"])
if page == "Introduction":
    st.title("⚡ Performance Analyzer")
    st.markdown(
        """
    This tool analyzes your Python codebase for maintainability and performance issues.

    ### 🔍 What it checks:
    - **Recursive Functions**: Detects self-calling functions
    - **Naive Search**:  Flags linear search patterns using `for + if + return/break`, suggesting more efficient alternatives like `set` or `dict`.
    - **Naive Sorting**: Finds usage of inefficient sort logic
    - **Regex Patterns**: Highlights potentially problematic regular expressions
    - **String Concatenation**: Discourages inefficient `+=` usage in loops in favor of `list + ''.join()`.
    - **Inefficient Data Structures**: Flags bad usage patterns
        - Membership checks (x in list)
        - List growing via append in loops
        - Sorting inside loops
        - Repeated list concatenation
    - **Time Complexity Estimation**: Statistically estimates time complexity `(e.g., O(n), O(n^2), O(2^n))` based on `loop depth`, `recursion`, and `.apply()` patterns using AST analysis.

    ### 📂 How to use:
    Go to the **Analyzer Dashboard** from the sidebar and enter the path to your Python project.
    """
    )
else:
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
            padding: 0.6rem;
            border-radius: 5px;
            color: #3b5bdb;
            font-style: italic;
        }
        code {
            background-color: #e6f4ea;
            color: #22863a;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.8em;
        }
        </style>
    """,
        unsafe_allow_html=True,
    )

    st.title("⚡ Performance Analyzer")

    # For now, you can manually input the directory or set it
    directory = st.text_input(
        "📁 Enter path to Python project directory",
        placeholder="/users/documents/python-folder",
    )

    if directory and os.path.isdir(directory):
        analyzer = PerformanceAnalyzer(config={})
        analyzer.analyze(directory)
        findings = analyzer.findings
        severity_counts = Counter(
            f.get("severity", "unknown").lower() for f in findings
        )
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
        # Display names shown in UI
        ALL_METRIC_DISPLAY = [
            "All",
            # "Nested Loops",
            "Naive Search",
            "Naive Sorting",
            "Recursive Functions",
            "String Concatenation",
            "Inefficient Data Structure",
            "Regex Patterns",
            "Time Complexity",
        ]
        DISPLAY_TO_TYPE = {
            # "Nested Loops": "nested_loops",
            "Naive Search": "naive_search",
            "Naive Sorting": "naive_sorting",
            "Recursive Functions": "recursive_without_memoization",
            "String Concatenation": "string_concatenation",
            "Inefficient Data Structure": "inefficient_data_structure",
            "Regex Patterns": "regex_compilation",
            "Time Complexity": "complexity",
            "All": None,
        }

        all_metrics = ["All"] + sorted(type_display_map[t] for t in type_display_map)
        file_names_display = ["All"] + sorted(file_map.keys())
        # UI filters
        col1, col2, col3 = st.columns(3)

        with col1:
            selected_severity = st.selectbox("🔍 Filter by Severity", all_severities)
        with col2:
            selected_metric = st.selectbox("📊 Filter by Metric", ALL_METRIC_DISPLAY)
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
        # if selected_metric != "All":
        #     selected_type = display_to_type[selected_metric]
        #     filtered_findings = [
        #         f for f in filtered_findings if f.get("type") == selected_type
        #     ]
        if selected_metric != "All":
            selected_type = DISPLAY_TO_TYPE[selected_metric]
            filtered_findings = [
                f for f in filtered_findings if f.get("type") == selected_type
            ]

        if selected_file != "All":
            full_path = file_map[selected_file]
            filtered_findings = [
                f for f in filtered_findings if f.get("file") == full_path
            ]

        if not filtered_findings:
            st.warning(
                f"❌ No findings for **{selected_metric}** in your code for {selected_severity} severity and {selected_file} file/s"
            )
            # return  # Or skip rendering

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
            # category = f.get("category", "performance").capitalize()
            type_ = type_display_map.get(
                f.get("type", "unknown"), f.get("type", "Unknown")
            )
            severity = f.get("severity", "medium").lower()
            description = f.get("description", "No description available")
            description = re.sub(
                r'Function\s+"([^"]+)"', r"Function <code>\1</code>", description
            )
            description = re.sub(r'"([^"]+\.py)"', r"<code>\1</code>", description)
            description = re.sub(r'"([^"]+\.py)"', r"<code>\1</code>", description)
            description = re.sub(
                r"detected at (\d+) locations",
                r"detected at <code>\1</code> locations",
                description,
            )
            file_loc = (
                f"{f.get('file', '')}:{f.get('line', '')}" if f.get("file") else ""
            )
            suggestion = f.get("suggestion", "")
            details = f.get("details", {})
            percentages = details.get("percentages", {})
            functions_by_risk = details.get("functions_by_risk", {})
            total_loc = details.get("total_loc")

            details_html = ""

            if percentages:
                details_html += "<div class='finding-details'><p><strong>Risk LOC Percentages:</strong></p><ul>"
                for level in ["moderate", "high", "very_high"]:
                    if level in percentages:
                        details_html += (
                            f"<li>{level.title()}: {percentages[level]}%</li>"
                        )
                details_html += "</ul>"

            if functions_by_risk:
                details_html += "<p><strong>Functions by Risk Level:</strong></p><ul>"
                for level, funcs in functions_by_risk.items():
                    details_html += f"<li><strong>{level.title()}:</strong><ul>"
                    for func in funcs:
                        details_html += f"<li>{func}</li>"
                    details_html += "</ul></li>"
                details_html += "</ul>"

            if total_loc:
                details_html += f"<p><strong>Total LOC:</strong> {total_loc}</p>"

            details_html += "</div>" if details_html else ""

            card_html = f"""
            <div class="finding-card">
                <div class="finding-header">
                    <div class="finding-type">
                        <span class="type-badge">{type_}</span>
                    </div>
                    <span class="severity-badge severity-{severity}">{severity.upper()}</span>
                </div>
                <div class="finding-content">
                    <p class="finding-description">{description}</p>
                    <div>{details_html}</div>
                    {'<p class="finding-location">📄 ' + file_loc + '</p>' if file_loc else ''}
                    {'<p class="finding-suggestion">💡 ' + suggestion + '</p>' if suggestion else ''}
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

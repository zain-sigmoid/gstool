#!/usr/bin/env python3
"""
Streamlit application for checking Python code robustness using multiple tools.
"""

import streamlit as st
import os
import subprocess
import json
import re
import tempfile
from pathlib import Path
from typing import List, Tuple, Dict
from collections import defaultdict
import textwrap


def find_python_files(path: str) -> List[str]:
    """Recursively find all .py files under the given path."""
    python_files = []
    
    if not os.path.exists(path):
        return python_files
    
    if os.path.isfile(path) and path.endswith('.py'):
        python_files.append(path)
    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
    
    return python_files


def run_bandit(files: List[str]) -> List[Tuple[str, str, int]]:
    """
    Run Bandit security checks and return issues for B110 and B113 test IDs.
    Returns list of (filename, message, line_number) tuples.
    """
    issues = []
    
    for file_path in files:
        try:
            result = subprocess.run(
                ['bandit', '-f', 'json', '-q', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout if result.stdout else result.stderr
            
            if not output:
                continue
                
            try:
                data = json.loads(output)
                results = data.get('results', [])
                for issue in results:
                    test_id = issue.get('test_id', '')
                    if test_id in ['B110', 'B113']:
                        line_number = issue.get('line_number', 0)
                        test_name = issue.get('test_name', 'Security issue')
                        filename = os.path.basename(file_path)
                        message = f"{test_id}: {test_name}"
                        issues.append((filename, message, line_number))
                        
            except json.JSONDecodeError:
                if 'B110' in output or 'B113' in output:
                    filename = os.path.basename(file_path)
                    issues.append((filename, "Bandit security issue detected", 0))
                    
        except subprocess.TimeoutExpired:
            filename = os.path.basename(file_path)
            issues.append((filename, "Bandit timeout", 0))
        except FileNotFoundError:
            st.error("Bandit not found. Please install with: pip install bandit")
            break
        except Exception as e:
            filename = os.path.basename(file_path)
            issues.append((filename, f"Bandit error: {str(e)}", 0))
    print(issues)
    return issues


def run_mypy(files: List[str]) -> List[Tuple[str, str, int]]:
    """
    Run mypy in strict mode and parse output for type checking issues.
    Returns list of (filename, message, line_number) tuples.
    """
    issues = []
    
    if not files:
        return issues
    
    try:
        result = subprocess.run(
            ['mypy', '--strict'] + files,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        pattern = r'^(.+\.py):(\d+):\s*(error|warning|note):\s*(.+?)(?:\s+\[([^\]]+)\])?$'
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            match = re.match(pattern, line)
            if match:
                filepath, line_num, level, message, error_code = match.groups()
                basename = os.path.basename(filepath)
                
                formatted_msg = message
                if error_code:
                    formatted_msg += f" [{error_code}]"
                    
                issues.append((basename, formatted_msg, int(line_num)))
        
    except subprocess.TimeoutExpired:
        issues.append(("", "MyPy timeout", 0))
    except FileNotFoundError:
        st.error("MyPy not found. Please install with: pip install mypy")
    except Exception as e:
        issues.append(("", f"MyPy error: {str(e)}", 0))
    
    return issues


def run_semgrep(files: List[str]) -> List[Tuple[str, str, int]]:
    """
    Run Semgrep with a custom rule to find open() calls not inside try/except.
    Returns list of (filename, message, line_number).
    """
    issues = []

    semgrep_rule = textwrap.dedent("""
rules:
  - id: open-without-try-except
    pattern: open(...)
    pattern-not-inside: |
      try:
        ...
    message: "open() call should be wrapped in a try/except block"
    languages:
      - python
    severity: WARNING
    """)

    for file_path in files:
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as temp_rule:
                temp_rule.write(semgrep_rule)
                temp_rule_path = temp_rule.name

            try:
                result = subprocess.run(
                    ['semgrep', '--config', temp_rule_path, '--json', file_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.stdout:
                    try:
                        data = json.loads(result.stdout)
                        for finding in data.get("results", []):
                            line = finding.get("start", {}).get("line", 0)
                            msg = finding.get("extra", {}).get("message", "open() without try/except")
                            file_name = os.path.basename(file_path)
                            issues.append((file_name, msg, line))
                    except json.JSONDecodeError:
                        issues.append((os.path.basename(file_path), "Failed to parse Semgrep output", 0))

            finally:
                try:
                    os.remove(temp_rule_path)
                except OSError:
                    pass

        except subprocess.TimeoutExpired:
            issues.append((os.path.basename(file_path), "Semgrep timeout", 0))
        except FileNotFoundError:
            raise RuntimeError("❌ Semgrep not found. Install it using: pip install semgrep")
        except Exception as e:
            issues.append((os.path.basename(file_path), f"Semgrep error: {str(e)}", 0))
    print(issues)
    return issues


def find_dict_access_without_get(files: List[str]) -> List[Tuple[str, str, int]]:
    """
    Find dictionary access patterns like mydict["key"] without .get() usage.
    Returns list of (filename, message, line_number) tuples.
    """
    issues = []
    dict_access_pattern = r'\w+\s*\[\s*["\'][^"\']*["\']\s*\]'
    
    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            basename = os.path.basename(file_path)
            
            for line_num, line in enumerate(lines, 1):
                line_content = line.strip()
                
                if not line_content or line_content.startswith('#'):
                    continue
                
                if re.search(dict_access_pattern, line_content):
                    if '.get(' not in line_content:
                        message = "Dictionary access without .get() method"
                        issues.append((basename, message, line_num))
                        
        except UnicodeDecodeError:
            basename = os.path.basename(file_path)
            issues.append((basename, "File encoding error - could not read", 0))
        except Exception as e:
            basename = os.path.basename(file_path)
            issues.append((basename, f"Error reading file: {str(e)}", 0))
    
    return issues



def group_issues_by_message(issues: List[Tuple[str, int]]) -> Dict[str, List[int]]:
    """Group issues by message type and collect line numbers."""
    grouped = defaultdict(list)
    
    for message, line_num in issues:
        # base_message = message.split(':')[0] if ':' in message else message
        base_message = message
        grouped[base_message].append(line_num)
    
    return dict(grouped)


def display_file_check_block(check_name: str, emoji: str, file_issues: List[Tuple[str, int]], show_lines: bool = True):
    """Display a single check block for a specific file."""
    
    if not file_issues:
        # No issues found
        st.success(f"{emoji} **{check_name}** - ✅ No issues found")
        return
    
    # Group similar issues
    grouped_issues = group_issues_by_message(file_issues)
    total_issues = len(file_issues)
    
    # Create expandable section for issues
    with st.expander(f"{emoji} **{check_name}** - ❌ {total_issues} issue(s) found", expanded=False):
        for issue_type, line_numbers in grouped_issues.items():
            if len(line_numbers) >= 3:
                # Group frequent issues
                valid_lines = [ln for ln in line_numbers if ln > 0]
                if valid_lines:
                    st.markdown(f"**🔄 {issue_type}** ({len(line_numbers)} occurrences)")
                    st.markdown(f"Lines: {', '.join(map(str, sorted(valid_lines)))}")
                else:
                    st.markdown(f"**🔄 {issue_type}** ({len(line_numbers)} occurrences)")
            else:
                # Show individual issues
                for line_num in line_numbers:
                    if line_num > 0:
                        st.markdown(f"- **Line {line_num}:** {issue_type}")
                    else:
                        st.markdown(f"- {issue_type}")


def display_file_results(filename: str, file_path: str, all_issues: Dict[str, List[Tuple[str, str, int]]]):
    """Display all check results for a single file."""
    
    # Filter issues for this specific file
    bandit_issues = [(msg, line) for fname, msg, line in all_issues['bandit'] if fname == filename]
    mypy_issues = [(msg, line) for fname, msg, line in all_issues['mypy'] if fname == filename]
    semgrep_issues = [(msg, line) for fname, msg, line in all_issues['semgrep'] if fname == filename]
    dict_issues = [(msg, line) for fname, msg, line in all_issues['dict'] if fname == filename]
    
    total_file_issues = len(bandit_issues) + len(mypy_issues) + len(semgrep_issues) + len(dict_issues) 
    
    # File header
    if total_file_issues == 0:
        st.markdown(f"## 📄 {filename}")
        st.success("🎉 All checks passed! No issues found in this file.")
    else:
        st.markdown(f"## 📄 {filename}")
        st.info(f"📊 **Total Issues:** {total_file_issues}")
    
    st.markdown(f"**Path:** `{file_path}`")
    st.markdown("---")
    
    # Display the 5 check blocks
    col1, col2 = st.columns(2)
    
    with col1:
        display_file_check_block("Dictionary Access", "📚", dict_issues)
        display_file_check_block("File Handling", "📁", semgrep_issues)
    
    with col2:
        display_file_check_block("Type Safety", "🏷️", mypy_issues)
        display_file_check_block("Other Issues", "🔒", bandit_issues)
        print(bandit_issues)
    
    st.markdown("---")


def main():
    """Main Streamlit application."""
    st.title("🔍 Python Code Robustness Checker")
    st.write("Comprehensive file-by-file analysis of Python code for security, type safety, and robustness issues.")
    
    # Input for file/directory path
    path_input = st.text_input(
        "Enter path to Python file or directory:",
        placeholder="/path/to/your/code.py or /path/to/your/project/",
        help="Provide a filesystem path to a single .py file or a directory containing Python files"
    )
    
    if st.button("🚀 Run All Checks", type="primary"):
        if not path_input.strip():
            st.error("Please enter a valid path.")
            return
        
        path = path_input.strip()
        
        # Find Python files
        with st.spinner("🔍 Finding Python files..."):
            python_files = find_python_files(path)
        
        if not python_files:
            st.warning(f"No Python files found at path: {path}")
            return
        
        st.success(f"Found {len(python_files)} Python file(s) to analyze")
        
        # Show files being analyzed
        with st.expander("📂 Files to be analyzed", expanded=False):
            for file_path in python_files:
                st.text(f"• {file_path}")
        
        st.markdown("---")
        
        # Run all checks
        with st.spinner("🔒 Running security analysis..."):
            bandit_issues = run_bandit(python_files)
        
        with st.spinner("🏷️ Running type safety analysis..."):
            mypy_issues = run_mypy(python_files)
        
        with st.spinner("📁 Checking file handling patterns..."):
            semgrep_issues = run_semgrep(python_files)
        
        with st.spinner("📚 Checking dictionary access patterns..."):
            dict_issues = find_dict_access_without_get(python_files)
      
        
        # Organize all issues
        all_issues = {
            'bandit': bandit_issues,
            'mypy': mypy_issues,
            'semgrep': semgrep_issues,
            'dict': dict_issues,
        }
        
        # Display results by file
        st.markdown("## 📊 Analysis Results")
        
        # Get unique filenames from all issues
        all_filenames = set()
        for issue_list in all_issues.values():
            for filename, _, _ in issue_list:
                if filename:  # Skip empty filenames
                    all_filenames.add(filename)
        
        # Add files with no issues
        for file_path in python_files:
            filename = os.path.basename(file_path)
            all_filenames.add(filename)
        
        # Sort filenames and display results
        for filename in sorted(all_filenames):
            # Find the full path for this filename
            full_path = next((fp for fp in python_files if os.path.basename(fp) == filename), filename)
            display_file_results(filename, full_path, all_issues)
        
        # Overall Summary
        total_all_issues = sum(len(issues) for issues in all_issues.values())
        files_with_issues = len([f for f in all_filenames if any(
            any(fname == f for fname, _, _ in issue_list) 
            for issue_list in all_issues.values()
        )])
        
        st.markdown("## 📈 Overall Summary")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Files", len(python_files))
        with col2:
            st.metric("Files with Issues", files_with_issues)
        with col3:
            st.metric("Total Issues", total_all_issues)
        
        if total_all_issues == 0:
            st.success("🎉 Congratulations! No robustness issues found in any files.")
            st.balloons()
        else:
            # Issue breakdown
            st.markdown("### Issue Breakdown by Type")
            col1, col2, col3, col4, col5 = st.columns(5)
            
            with col1:
                st.metric("🔒 Security", len(bandit_issues))
            with col2:
                st.metric("🏷️ Type Safety", len(mypy_issues))
            with col3:
                st.metric("📁 File Handling", len(semgrep_issues))
            with col4:
                st.metric("📚 Dict Access", len(dict_issues))


if __name__ == "__main__":
    main()
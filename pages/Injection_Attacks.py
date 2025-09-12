import streamlit as st
import os
import re
import ast
import pandas as pd
from pathlib import Path
from typing import List, Dict, Tuple, Any
import tempfile

class InjectionScanner:
    def __init__(self):
        # SQL Injection patterns
        self.sql_patterns = [
            # Direct SQL concatenation
            r'["\'].*\+.*["\'].*WHERE|SELECT|INSERT|UPDATE|DELETE',
            r'f["\'].*{.*}.*WHERE|SELECT|INSERT|UPDATE|DELETE',
            r'%s.*WHERE|SELECT|INSERT|UPDATE|DELETE',
            r'format\(.*WHERE|SELECT|INSERT|UPDATE|DELETE',
            
            # Dangerous SQL operations
            r'execute\s*\(\s*["\'].*\+',
            r'executemany\s*\(\s*["\'].*\+',
            r'raw\s*\(\s*["\'].*\+',
            
            # ORM query building without parameterization
            r'\.extra\s*\(\s*where\s*=.*\+',
            r'\.raw\s*\(\s*["\'].*\+',
        ]
        
        # XSS patterns
        self.xss_patterns = [
            # Direct HTML output without escaping
            r'render_template_string\s*\(.*\+',
            r'HttpResponse\s*\(.*\+',
            r'Response\s*\(.*\+',
            
            # Unsafe HTML generation
            r'["\']<[^>]*{.*}[^>]*>["\']',
            r'innerHTML.*=.*\+',
            r'document\.write\s*\(.*\+',
            
            # Template injection
            r'{{\s*.*\|safe\s*}}',
            r'mark_safe\s*\(.*\+',
        ]
        
        # Command Injection patterns
        self.command_patterns = [
            # Direct command execution
            r'os\.system\s*\(.*\+',
            r'subprocess\.call\s*\(.*\+',
            r'subprocess\.run\s*\(.*\+',
            r'subprocess\.Popen\s*\(.*\+',
            r'os\.popen\s*\(.*\+',
            r'commands\.getoutput\s*\(.*\+',
            
            # Shell execution
            r'shell=True.*\+',
            r'eval\s*\(.*input',
            r'exec\s*\(.*input',
        ]
        
        # Path Traversal patterns
        self.path_traversal_patterns = [
            r'open\s*\(.*\+.*\)',
            r'file\s*\(.*\+.*\)',
            r'os\.path\.join\s*\(.*input',
            r'Path\s*\(.*\+.*\)',
            r'\.\./',
            r'\.\.\\\\',
        ]
        
        # LDAP Injection patterns
        self.ldap_patterns = [
            r'ldap.*search.*\+',
            r'LDAPConnection.*search.*\+',
            r'ldap_search.*\+',
        ]
        
        # Code Injection patterns
        self.code_injection_patterns = [
            r'eval\s*\(.*input\(',
            r'exec\s*\(.*input\(',
            r'compile\s*\(.*input\(',
            r'__import__\s*\(.*input\(',
        ]
        
        # XPATH Injection patterns
        self.xpath_patterns = [
            r'xpath\s*\(.*\+',
            r'selectNodes\s*\(.*\+',
            r'evaluate\s*\(.*\+.*xpath',
        ]

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a single Python file for injection vulnerabilities."""
        vulnerabilities = []
        found_vulnerabilities = set()  # Track unique vulnerabilities to avoid duplicates
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
            # Check each line for patterns
            for line_num, line in enumerate(lines, 1):
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith('#'):
                    continue
                
                # SQL Injection
                sql_found = False
                for pattern in self.sql_patterns:
                    if re.search(pattern, line, re.IGNORECASE) and not sql_found:
                        vuln_key = (file_path, line_num, 'SQL Injection')
                        if vuln_key not in found_vulnerabilities:
                            vulnerabilities.append({
                                'file': file_path,
                                'line': line_num,
                                'type': 'SQL Injection',
                                'severity': 'High',
                                'code': line.strip(),
                                'description': 'Potential SQL injection vulnerability detected'
                            })
                            found_vulnerabilities.add(vuln_key)
                            sql_found = True
                            break
                
                # XSS
                xss_found = False
                for pattern in self.xss_patterns:
                    if re.search(pattern, line, re.IGNORECASE) and not xss_found:
                        vuln_key = (file_path, line_num, 'XSS')
                        if vuln_key not in found_vulnerabilities:
                            vulnerabilities.append({
                                'file': file_path,
                                'line': line_num,
                                'type': 'XSS',
                                'severity': 'High',
                                'code': line.strip(),
                                'description': 'Potential Cross-Site Scripting vulnerability detected'
                            })
                            found_vulnerabilities.add(vuln_key)
                            xss_found = True
                            break
                
                # Command Injection
                cmd_found = False
                for pattern in self.command_patterns:
                    if re.search(pattern, line, re.IGNORECASE) and not cmd_found:
                        vuln_key = (file_path, line_num, 'Command Injection')
                        if vuln_key not in found_vulnerabilities:
                            vulnerabilities.append({
                                'file': file_path,
                                'line': line_num,
                                'type': 'Command Injection',
                                'severity': 'Critical',
                                'code': line.strip(),
                                'description': 'Potential command injection vulnerability detected'
                            })
                            found_vulnerabilities.add(vuln_key)
                            cmd_found = True
                            break
                
                # Path Traversal
                path_found = False
                for pattern in self.path_traversal_patterns:
                    if re.search(pattern, line, re.IGNORECASE) and not path_found:
                        vuln_key = (file_path, line_num, 'Path Traversal')
                        if vuln_key not in found_vulnerabilities:
                            vulnerabilities.append({
                                'file': file_path,
                                'line': line_num,
                                'type': 'Path Traversal',
                                'severity': 'Medium',
                                'code': line.strip(),
                                'description': 'Potential path traversal vulnerability detected'
                            })
                            found_vulnerabilities.add(vuln_key)
                            path_found = True
                            break
                
                # LDAP Injection
                ldap_found = False
                for pattern in self.ldap_patterns:
                    if re.search(pattern, line, re.IGNORECASE) and not ldap_found:
                        vuln_key = (file_path, line_num, 'LDAP Injection')
                        if vuln_key not in found_vulnerabilities:
                            vulnerabilities.append({
                                'file': file_path,
                                'line': line_num,
                                'type': 'LDAP Injection',
                                'severity': 'High',
                                'code': line.strip(),
                                'description': 'Potential LDAP injection vulnerability detected'
                            })
                            found_vulnerabilities.add(vuln_key)
                            ldap_found = True
                            break
                
                # Code Injection
                code_found = False
                for pattern in self.code_injection_patterns:
                    if re.search(pattern, line, re.IGNORECASE) and not code_found:
                        vuln_key = (file_path, line_num, 'Code Injection')
                        if vuln_key not in found_vulnerabilities:
                            vulnerabilities.append({
                                'file': file_path,
                                'line': line_num,
                                'type': 'Code Injection',
                                'severity': 'Critical',
                                'code': line.strip(),
                                'description': 'Potential code injection vulnerability detected'
                            })
                            found_vulnerabilities.add(vuln_key)
                            code_found = True
                            break
                
                # XPATH Injection
                xpath_found = False
                for pattern in self.xpath_patterns:
                    if re.search(pattern, line, re.IGNORECASE) and not xpath_found:
                        vuln_key = (file_path, line_num, 'XPATH Injection')
                        if vuln_key not in found_vulnerabilities:
                            vulnerabilities.append({
                                'file': file_path,
                                'line': line_num,
                                'type': 'XPATH Injection',
                                'severity': 'High',
                                'code': line.strip(),
                                'description': 'Potential XPATH injection vulnerability detected'
                            })
                            found_vulnerabilities.add(vuln_key)
                            xpath_found = True
                            break
                        
        except Exception as e:
            st.error(f"Error scanning file {file_path}: {str(e)}")
        
        return vulnerabilities

    def scan_folder(self, folder_path: str) -> List[Dict[str, Any]]:
        """Scan all Python files in a folder recursively."""
        all_vulnerabilities = []
        python_files = []
        
        # Find all Python files
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        
        # Scan each file
        progress_bar = st.progress(0)
        for i, file_path in enumerate(python_files):
            vulnerabilities = self.scan_file(file_path)
            all_vulnerabilities.extend(vulnerabilities)
            progress_bar.progress((i + 1) / len(python_files))
        
        return all_vulnerabilities

def main():
    st.set_page_config(
        page_title="Injection Attack Scanner",
        page_icon="🔍",
        layout="wide"
    )
    
    st.title("🔍 Injection Attack Scanner")
    st.markdown("**Scan Python files and folders for injection vulnerabilities**")
    
    # Sidebar for configuration
    st.sidebar.header("Configuration")
    scan_type = st.sidebar.radio(
        "Select scan type:",
        ["Single File", "Folder", "Upload File"]
    )
    
    scanner = InjectionScanner()
    vulnerabilities = []
    
    if scan_type == "Single File":
        file_path = st.text_input("Enter the path to Python file:", placeholder="/path/to/your/file.py")
        
        if st.button("Scan File"):
            if file_path and os.path.isfile(file_path) and file_path.endswith('.py'):
                with st.spinner("Scanning file..."):
                    vulnerabilities = scanner.scan_file(file_path)
            elif file_path:
                st.error("Please provide a valid Python file path.")
    
    elif scan_type == "Folder":
        folder_path = st.text_input("Enter the path to folder:", placeholder="/path/to/your/folder")
        
        if st.button("Scan Folder"):
            if folder_path and os.path.isdir(folder_path):
                with st.spinner("Scanning folder..."):
                    vulnerabilities = scanner.scan_folder(folder_path)
            elif folder_path:
                st.error("Please provide a valid folder path.")
    
    else:  # Upload File
        uploaded_file = st.file_uploader("Upload a Python file", type=['py'])
        
        if uploaded_file is not None:
            # Save uploaded file temporarily
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp_file:
                tmp_file.write(uploaded_file.getvalue().decode('utf-8'))
                tmp_path = tmp_file.name
            
            if st.button("Scan Uploaded File"):
                with st.spinner("Scanning uploaded file..."):
                    vulnerabilities = scanner.scan_file(tmp_path)
                os.unlink(tmp_path)  # Clean up temp file
    
    # Display results
    if vulnerabilities:
        st.header("🚨 Vulnerabilities Found")
        
        # Summary statistics
        col1, col2, col3, col4 = st.columns(4)
        
        total_vulns = len(vulnerabilities)
        critical_vulns = len([v for v in vulnerabilities if v['severity'] == 'Critical'])
        high_vulns = len([v for v in vulnerabilities if v['severity'] == 'High'])
        medium_vulns = len([v for v in vulnerabilities if v['severity'] == 'Medium'])
        
        col1.metric("Total Vulnerabilities", total_vulns)
        col2.metric("Critical", critical_vulns)
        col3.metric("High", high_vulns)
        col4.metric("Medium", medium_vulns)
        
        # Vulnerability breakdown by type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln['type']
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        st.subheader("Vulnerability Types")
        for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            st.write(f"- **{vuln_type}**: {count} instances")
        
        # Detailed results
        st.subheader("Detailed Results")
        
        # Convert to DataFrame for better display
        df = pd.DataFrame(vulnerabilities)
        
        # Add filters
        col1, col2 = st.columns(2)
        with col1:
            severity_filter = st.multiselect(
                "Filter by Severity:",
                options=['Critical', 'High', 'Medium', 'Low'],
                default=['Critical', 'High', 'Medium', 'Low']
            )
        
        with col2:
            type_filter = st.multiselect(
                "Filter by Type:",
                options=list(vuln_types.keys()),
                default=list(vuln_types.keys())
            )
        
        # Apply filters
        filtered_df = df[
            (df['severity'].isin(severity_filter)) & 
            (df['type'].isin(type_filter))
        ]
        
        # Display filtered results
        for _, vuln in filtered_df.iterrows():
            severity_color = {
                'Critical': '🔴',
                'High': '🟠', 
                'Medium': '🟡',
                'Low': '🟢'
            }
            
            with st.expander(f"{severity_color[vuln['severity']]} {vuln['type']} - Line {vuln['line']}"):
                st.write(f"**File:** `{vuln['file']}`")
                st.write(f"**Line:** {vuln['line']}")
                st.write(f"**Severity:** {vuln['severity']}")
                st.write(f"**Description:** {vuln['description']}")
                st.code(vuln['code'], language='python')
        
        # Export results
        if st.button("Export Results as CSV"):
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name="vulnerability_report.csv",
                mime="text/csv"
            )
    
    elif st.session_state.get('scan_clicked', False):
        st.success("✅ No injection vulnerabilities detected!")
    
    # Information section
    with st.expander("ℹ️ About This Scanner"):
        st.markdown("""
        This scanner detects the following types of injection vulnerabilities:
        
        - **SQL Injection**: Unsafe database query construction
        - **XSS (Cross-Site Scripting)**: Unsafe HTML output generation  
        - **Command Injection**: Unsafe system command execution
        - **Path Traversal**: Unsafe file path handling
        - **LDAP Injection**: Unsafe LDAP query construction
        - **Code Injection**: Unsafe dynamic code execution
        - **XPATH Injection**: Unsafe XML query construction
        
        **Note**: This is a static analysis tool and may produce false positives. 
        Manual code review is recommended for confirmation.
        """)

if __name__ == "__main__":
    main()
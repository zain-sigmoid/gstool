import streamlit as st
import os
import re
import ast
from pathlib import Path
from typing import List, Dict, Tuple, Set
import pandas as pd
from dataclasses import dataclass
from enum import Enum

class RiskLevel(Enum):
    HIGH = "🔴 HIGH"
    MEDIUM = "🟡 MEDIUM"
    LOW = "🟢 LOW"

@dataclass
class PIIFinding:
    file_path: str
    line_number: int
    line_content: str
    pii_type: str
    risk_level: RiskLevel
    context: str
    recommendation: str
    matched_text: str = ""  # Add matched text for better deduplication

class PIIPatterns:
    """PII/PHI pattern definitions focused on data privacy"""
    
    # Email patterns - more specific to avoid false positives
    EMAIL = r'\b[A-Za-z0-9]([A-Za-z0-9._%+-]*[A-Za-z0-9])?@[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}\b'
    
    # Phone number patterns - more restrictive to avoid token matches
    PHONE = r'\b(?:\+?1[-.\s]?)?\(?[2-9][0-8][0-9]\)?[-.\s]?[2-9][0-9]{2}[-.\s]?[0-9]{4}\b'
    
    # Social Security Number - strict format
    SSN = r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'
    
    # Credit Card Numbers - more specific patterns
    CREDIT_CARD = r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
    
    # IP Addresses - exclude common non-personal IPs
    IP_ADDRESS = r'\b(?:(?!(?:10|127|169\.254|192\.168|172\.(?:1[6-9]|2[0-9]|3[01]))\.)(?:[0-9]{1,3}\.){3}[0-9]{1,3})\b'
    
    # Medical Record Numbers
    MRN = r'\b(?:MRN|mrn|medical[-_\s]record|patient[-_\s]id)[:\s=]*[A-Z0-9]{5,15}\b'
    
    # Date of Birth patterns
    DOB = r'\b(?:dob|date[-_\s]of[-_\s]birth|birth[-_\s]date)[:\s=]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b'
    
    # Driver's License patterns
    DRIVERS_LICENSE = r'\b(?:DL|dl|license|driver)[:\s=]*[A-Z0-9]{8,15}\b'
    
    # Passport numbers
    PASSPORT = r'\b(?:passport|pass)[:\s=]*[A-Z0-9]{6,9}\b'
    
    # Common PII variable names (excluding security-related ones)
    PII_VARIABLES = [
        'first_name', 'last_name', 'full_name', 'email', 'phone', 'ssn',
        'social_security', 'credit_card', 'patient_id', 'medical_record',
        'diagnosis', 'prescription', 'blood_type', 'insurance_id',
        'drivers_license', 'passport', 'address', 'zipcode', 'birth_date',
        'patient_name', 'user_email', 'phone_number'
    ]
    
    # Token patterns to exclude from phone number detection
    TOKEN_PATTERNS = [
        r'xoxp-\d+-\d+-\d+-[a-f0-9]+',  # Slack tokens
        r'sk-[a-zA-Z0-9]{48}',          # OpenAI API keys
        r'gh[ps]_[a-zA-Z0-9]{36}',      # GitHub tokens
        r'AKIA[0-9A-Z]{16}',            # AWS access keys
    ]

class PIIScanner:
    def __init__(self):
        self.findings: List[PIIFinding] = []
        self.patterns = PIIPatterns()
        
    def scan_file(self, file_path: str) -> List[PIIFinding]:
        """Scan a single Python file for PII/PHI"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()
                
            # Parse AST for deeper analysis
            try:
                tree = ast.parse(''.join(lines))
                ast_findings = self._analyze_ast(tree, file_path, lines)
                findings.extend(ast_findings)
            except SyntaxError:
                st.warning(f"Could not parse AST for {file_path} - syntax errors present")
            
            # Pattern-based scanning
            for line_num, line in enumerate(lines, 1):
                line_findings = self._scan_line(file_path, line_num, line)
                findings.extend(line_findings)
            
            # Remove duplicates and false positives
            findings = self._deduplicate_findings(findings)
            findings = self._filter_false_positives(findings)
                
        except Exception as e:
            st.error(f"Error scanning {file_path}: {str(e)}")
            
        return findings
    
    def _analyze_ast(self, tree: ast.AST, file_path: str, lines: List[str]) -> List[PIIFinding]:
        """Analyze AST for PII patterns"""
        findings = []
        
        for node in ast.walk(tree):
            # Check string literals for PII content
            if isinstance(node, ast.Str) and hasattr(node, 'lineno'):
                string_findings = self._check_string_content(
                    file_path, node.lineno, node.s, "String literal"
                )
                findings.extend(string_findings)
            
            # Check variable assignments for PII variable names
            if isinstance(node, ast.Assign) and hasattr(node, 'lineno'):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(pii_var in var_name for pii_var in self.patterns.PII_VARIABLES):
                            line_content = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "Unknown"
                            findings.append(PIIFinding(
                                file_path=file_path,
                                line_number=node.lineno,
                                line_content=line_content,
                                pii_type="Sensitive Variable Name",
                                risk_level=RiskLevel.MEDIUM,
                                context=f"Variable name '{target.id}' suggests PII/PHI data storage",
                                recommendation="Use generic variable names and implement data encryption",
                                matched_text=target.id
                            ))
            
            # Check function calls that might log PII data
            if isinstance(node, ast.Call) and hasattr(node, 'lineno'):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ['info', 'debug', 'error', 'warning', 'log']:
                        # Check if logging call has arguments that might contain PII
                        for arg in node.args:
                            if isinstance(arg, ast.Name):
                                var_name = arg.id.lower()
                                if any(pii_var in var_name for pii_var in self.patterns.PII_VARIABLES):
                                    line_content = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "Unknown"
                                    findings.append(PIIFinding(
                                        file_path=file_path,
                                        line_number=node.lineno,
                                        line_content=line_content,
                                        pii_type="PII Data Logging",
                                        risk_level=RiskLevel.HIGH,
                                        context=f"Logging statement may expose PII variable '{arg.id}'",
                                        recommendation="Implement data masking before logging sensitive information",
                                        matched_text=arg.id
                                    ))
        
        return findings
    
    def _scan_line(self, file_path: str, line_num: int, line: str) -> List[PIIFinding]:
        """Scan individual line for PII patterns"""
        findings = []
        
        # Skip if line contains tokens that might cause false positives
        if self._is_likely_token(line):
            return findings
        
        patterns_to_check = [
            (self.patterns.EMAIL, "Email Address", RiskLevel.HIGH),
            (self.patterns.PHONE, "Phone Number", RiskLevel.HIGH),
            (self.patterns.SSN, "Social Security Number", RiskLevel.HIGH),
            (self.patterns.CREDIT_CARD, "Credit Card Number", RiskLevel.HIGH),
            (self.patterns.IP_ADDRESS, "IP Address", RiskLevel.MEDIUM),
            (self.patterns.MRN, "Medical Record Number", RiskLevel.HIGH),
            (self.patterns.DOB, "Date of Birth", RiskLevel.HIGH),
            (self.patterns.DRIVERS_LICENSE, "Driver's License", RiskLevel.HIGH),
            (self.patterns.PASSPORT, "Passport Number", RiskLevel.HIGH),
        ]
        
        for pattern, pii_type, risk_level in patterns_to_check:
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                matched_text = match.group()
                
                # Additional validation for specific types
                if self._is_valid_match(pii_type, matched_text, line):
                    findings.append(PIIFinding(
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line.strip(),
                        pii_type=pii_type,
                        risk_level=risk_level,
                        context=f"Found {pii_type.lower()} pattern: {matched_text}",
                        recommendation=self._get_recommendation(pii_type),
                        matched_text=matched_text
                    ))
        
        return findings
    
    def _is_likely_token(self, line: str) -> bool:
        """Check if line contains tokens that might cause false positives"""
        for token_pattern in self.patterns.TOKEN_PATTERNS:
            if re.search(token_pattern, line, re.IGNORECASE):
                return True
        
        # Check for other token indicators
        token_indicators = ['xoxp-', 'sk-', 'ghp_', 'ghs_', 'token', 'api_key', 'bearer']
        line_lower = line.lower()
        return any(indicator in line_lower for indicator in token_indicators)
    
    def _is_valid_match(self, pii_type: str, matched_text: str, line: str) -> bool:
        """Validate if the match is likely a real PII instance"""
        
        # Skip obvious test/example data
        test_indicators = ['example', 'test', 'dummy', 'fake', 'sample', 'placeholder']
        line_lower = line.lower()
        if any(indicator in line_lower for indicator in test_indicators):
            return False
        
        # Additional validation for phone numbers
        if pii_type == "Phone Number":
            # Skip if it's clearly not a phone number format
            if len(matched_text.replace('-', '').replace('(', '').replace(')', '').replace(' ', '')) != 10:
                return False
            # Skip sequences like 1234567890
            if re.match(r'^(\d)\1+$', matched_text.replace('-', '').replace('(', '').replace(')', '').replace(' ', '')):
                return False
        
        # Additional validation for SSN
        if pii_type == "Social Security Number":
            # Skip obvious fake SSNs
            fake_ssns = ['123-45-6789', '000-00-0000', '111-11-1111']
            if matched_text in fake_ssns:
                return False
        
        # Additional validation for emails
        if pii_type == "Email Address":
            # Skip obvious test emails
            test_domains = ['example.com', 'test.com', 'domain.com', 'email.com']
            domain = matched_text.split('@')[-1] if '@' in matched_text else ''
            if domain.lower() in test_domains:
                return False
        
        return True
    
    def _check_string_content(self, file_path: str, line_num: int, content: str, context: str) -> List[PIIFinding]:
        """Check string content for PII patterns"""
        findings = []
        
        # Skip very short strings
        if len(content) < 5:
            return findings
        
        # Check for potential sample/test PII data
        sample_indicators = [
            ('john.doe', 'Sample Email Format'),
            ('jane.smith', 'Sample Name Format'),
            ('patient_name', 'PHI Variable Reference'),
            ('diagnosis:', 'Medical Information'),
            ('patient_id', 'Patient Identifier'),
            ('medical_record', 'Medical Record Reference'),
            ('ssn:', 'SSN Reference'),
            ('phone:', 'Phone Reference')
        ]
        
        content_lower = content.lower()
        for indicator, description in sample_indicators:
            if indicator in content_lower and len(content) > 10:  # Avoid very short matches
                findings.append(PIIFinding(
                    file_path=file_path,
                    line_number=line_num,
                    line_content=content[:100] + "..." if len(content) > 100 else content,
                    pii_type="Sample/Test PII Data",
                    risk_level=RiskLevel.MEDIUM,
                    context=f"String contains potential sample PII: {description}",
                    recommendation="Replace sample data with anonymized placeholders or synthetic data",
                    matched_text=indicator
                ))
        
        # Check for medical/health-related terms (PHI)
        phi_indicators = [
            ('blood pressure', 'Vital Signs'),
            ('heart rate', 'Vital Signs'),
            ('medication', 'Treatment Information'),
            ('prescription', 'Treatment Information'),
            ('diagnosis', 'Medical Diagnosis'),
            ('treatment', 'Medical Treatment'),
            ('allergy', 'Medical Condition'),
            ('diabetes', 'Medical Condition'),
            ('hypertension', 'Medical Condition')
        ]
        
        for phi_term, category in phi_indicators:
            if phi_term in content_lower and len(content) > 15:  # Ensure substantial content
                findings.append(PIIFinding(
                    file_path=file_path,
                    line_number=line_num,
                    line_content=content[:100] + "..." if len(content) > 100 else content,
                    pii_type="Protected Health Information",
                    risk_level=RiskLevel.HIGH,
                    context=f"String contains potential PHI: {category}",
                    recommendation="Ensure HIPAA compliance and implement proper PHI handling",
                    matched_text=phi_term
                ))
        
        return findings
    
    def _deduplicate_findings(self, findings: List[PIIFinding]) -> List[PIIFinding]:
        """Remove duplicate findings based on file, line, type, and matched text"""
        seen = set()
        deduplicated = []
        
        for finding in findings:
            # Create unique key based on file, line, PII type, and matched text
            key = (
                finding.file_path, 
                finding.line_number, 
                finding.pii_type, 
                finding.matched_text
            )
            
            if key not in seen:
                seen.add(key)
                deduplicated.append(finding)
        
        return deduplicated
    
    def _filter_false_positives(self, findings: List[PIIFinding]) -> List[PIIFinding]:
        """Filter out likely false positives"""
        filtered = []
        
        for finding in findings:
            should_include = True
            
            # Skip if it's likely a token/API key being misidentified
            if finding.pii_type == "Phone Number":
                token_indicators = ['xoxp', 'token', 'api_key', 'slack', 'bearer', 'sk-']
                if any(indicator in finding.line_content.lower() for indicator in token_indicators):
                    should_include = False
            
            # Skip comments that are just explaining PII concepts
            if '# ' in finding.line_content or '"""' in finding.line_content:
                explanation_terms = ['example', 'like', 'such as', 'format:', 'e.g.']
                if any(term in finding.line_content.lower() for term in explanation_terms):
                    should_include = False
            
            # Skip import statements and library references
            if any(keyword in finding.line_content.lower() for keyword in ['import ', 'from ', 'lib']):
                should_include = False
            
            if should_include:
                filtered.append(finding)
        
        return filtered
    
    def _get_recommendation(self, pii_type: str) -> str:
        """Get specific recommendations for PII type"""
        recommendations = {
            "Email Address": "Use email hashing or tokenization, avoid logging complete emails",
            "Phone Number": "Implement phone number masking (XXX-XXX-1234)",
            "Social Security Number": "Never store SSN in plain text, use strong encryption",
            "Credit Card Number": "Use PCI-compliant tokenization, never log full numbers",
            "IP Address": "Consider IP anonymization for logging and analytics",
            "Medical Record Number": "Encrypt MRNs, ensure HIPAA compliance",
            "Date of Birth": "Use age ranges instead of exact dates when possible",
            "Driver's License": "Encrypt license numbers, limit access to authorized personnel",
            "Passport Number": "Use secure encryption and access controls",
            "Protected Health Information": "Implement HIPAA-compliant data handling procedures",
            "Sample/Test PII Data": "Replace with synthetic or anonymized data",
            "Sensitive Variable Name": "Use generic names and implement proper data protection",
            "PII Data Logging": "Implement data masking and review logging practices"
        }
        return recommendations.get(pii_type, "Review and secure sensitive data handling")

def scan_directory(directory_path: str) -> List[PIIFinding]:
    """Scan all Python files in directory"""
    scanner = PIIScanner()
    all_findings = []
    
    path = Path(directory_path)
    python_files = list(path.glob('**/*.py'))
    
    if not python_files:
        st.warning("No Python files found in the specified directory.")
        return []
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for i, file_path in enumerate(python_files):
        status_text.text(f'Scanning: {file_path.name} ({i+1}/{len(python_files)})')
        findings = scanner.scan_file(str(file_path))
        all_findings.extend(findings)
        progress_bar.progress((i + 1) / len(python_files))
    
    status_text.text(f'Scan complete! Found {len(all_findings)} potential PII/PHI issues.')
    return all_findings

def main():
    st.set_page_config(
        page_title="PII/PHI Data Privacy Scanner",
        page_icon="🔒",
        layout="wide"
    )
    
    st.title("🔒 PII/PHI Data Privacy Scanner")
    st.markdown("""
    This tool scans Python code specifically for **Personally Identifiable Information (PII)** and 
    **Protected Health Information (PHI)** to help ensure compliance with data protection 
    regulations like **GDPR**, **HIPAA**, and **CCPA**.
    
    **Focus**: Data privacy and personal information protection with **duplicate detection** and **false positive filtering**.
    """)
    
    # Sidebar configuration
    st.sidebar.header("🔧 Scanner Configuration")
    
    scan_type = st.sidebar.radio(
        "Select scan type:",
        ["📁 Directory/Folder", "📄 Single Python File"]
    )
    
    if scan_type == "📁 Directory/Folder":
        path = st.sidebar.text_input(
            "Enter directory path:",
            placeholder="/path/to/your/project",
            help="Scans all .py files recursively in the directory"
        )
    else:
        path = st.sidebar.text_input(
            "Enter Python file path:",
            placeholder="/path/to/file.py",
            help="Scans a single Python file"
        )
    
    # Risk level filter
    risk_filters = st.sidebar.multiselect(
        "Filter by risk level:",
        [RiskLevel.HIGH.value, RiskLevel.MEDIUM.value, RiskLevel.LOW.value],
        default=[RiskLevel.HIGH.value, RiskLevel.MEDIUM.value],
        help="Select which risk levels to display in results"
    )
    
    # Additional options
    st.sidebar.subheader("📋 Additional Options")
    show_line_content = st.sidebar.checkbox("Show full line content", value=True)
    show_recommendations = st.sidebar.checkbox("Show recommendations", value=True)
    
    if st.sidebar.button("🔍 Start PII/PHI Scan", type="primary"):
        if not path:
            st.error("Please provide a valid path!")
            return
        
        if not os.path.exists(path):
            st.error("Path does not exist!")
            return
        
        # Perform scan
        with st.spinner("Scanning for PII/PHI data privacy issues..."):
            if scan_type == "📁 Directory/Folder":
                findings = scan_directory(path)
            else:
                scanner = PIIScanner()
                findings = scanner.scan_file(path)
        
        # Filter findings by risk level
        filtered_findings = [
            f for f in findings 
            if f.risk_level.value in risk_filters
        ]
        
        # Display results
        st.header("📊 PII/PHI Scan Results")
        
        if not filtered_findings:
            st.success("🎉 No PII/PHI data privacy issues found!")
            if findings:  # There were findings but filtered out
                st.info(f"Found {len(findings)} total issues, but none match your selected risk level filters.")
            return
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total PII/PHI Issues", len(filtered_findings))
        
        with col2:
            high_risk = sum(1 for f in filtered_findings if f.risk_level == RiskLevel.HIGH)
            st.metric("High Risk", high_risk, delta_color="inverse")
        
        with col3:
            medium_risk = sum(1 for f in filtered_findings if f.risk_level == RiskLevel.MEDIUM)
            st.metric("Medium Risk", medium_risk, delta_color="inverse")
        
        with col4:
            unique_files = len(set(f.file_path for f in filtered_findings))
            st.metric("Affected Files", unique_files)
        
        # PII Type breakdown
        st.subheader("📈 PII/PHI Types Found")
        pii_types = {}
        for finding in filtered_findings:
            pii_types[finding.pii_type] = pii_types.get(finding.pii_type, 0) + 1
        
        if pii_types:
            df_types = pd.DataFrame(list(pii_types.items()), columns=['PII/PHI Type', 'Count'])
            st.bar_chart(df_types.set_index('PII/PHI Type'))
        
        # Detailed findings
        st.subheader("🔍 Detailed Findings")
        
        # Group findings by file
        files_with_issues = {}
        for finding in filtered_findings:
            if finding.file_path not in files_with_issues:
                files_with_issues[finding.file_path] = []
            files_with_issues[finding.file_path].append(finding)
        
        # Display findings by file
        for file_path, file_findings in files_with_issues.items():
            with st.expander(f"📄 {os.path.basename(file_path)} ({len(file_findings)} issues)", expanded=len(files_with_issues) <= 3):
                
                # Create DataFrame for this file
                df_data = []
                for finding in file_findings:
                    row_data = {
                        "Line": finding.line_number,
                        "Risk": finding.risk_level.value,
                        "PII/PHI Type": finding.pii_type,
                        "Matched Text": finding.matched_text or "N/A",
                        "Context": finding.context
                    }
                    
                    if show_line_content:
                        row_data["Code"] = finding.line_content[:80] + "..." if len(finding.line_content) > 80 else finding.line_content
                    
                    if show_recommendations:
                        row_data["Recommendation"] = finding.recommendation
                    
                    df_data.append(row_data)
                
                df = pd.DataFrame(df_data)
                st.dataframe(df, use_container_width=True)
        
        # Export functionality
        st.subheader("📥 Export Results")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📊 Export to CSV"):
                export_data = []
                for finding in filtered_findings:
                    export_data.append({
                        "File Path": finding.file_path,
                        "Line Number": finding.line_number,
                        "Risk Level": finding.risk_level.value,
                        "PII/PHI Type": finding.pii_type,
                        "Matched Text": finding.matched_text,
                        "Line Content": finding.line_content,
                        "Context": finding.context,
                        "Recommendation": finding.recommendation
                    })
                
                df_export = pd.DataFrame(export_data)
                csv = df_export.to_csv(index=False)
                
                st.download_button(
                    label="📥 Download CSV Report",
                    data=csv,
                    file_name=f"pii_phi_scan_report_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("📋 Generate Summary"):
                st.subheader("📋 Executive Summary")
                
                total_issues = len(filtered_findings)
                high_risk_count = sum(1 for f in filtered_findings if f.risk_level == RiskLevel.HIGH)
                affected_files = len(set(f.file_path for f in filtered_findings))
                
                summary_text = f"""
**PII/PHI Scan Summary Report**

- **Total Issues Found**: {total_issues}
- **High Risk Issues**: {high_risk_count}
- **Files Affected**: {affected_files}
- **Most Common PII Type**: {max(pii_types, key=pii_types.get) if pii_types else 'N/A'}

**Top Recommendations**:
1. Review and remediate all HIGH risk findings immediately
2. Implement data masking for logging and debug output
3. Replace sample/test data with anonymized alternatives
4. Ensure proper encryption for stored PII/PHI data
5. Conduct regular code reviews for data privacy compliance
"""
                st.markdown(summary_text)
    
    # Information panel
    with st.expander("ℹ️ About PII/PHI Detection & Features"):
        st.markdown("""
        ### 🔍 What This Scanner Detects:
        
        **Personal Identifiable Information (PII):**
        - Email addresses and contact information
        - Phone numbers in various formats
        - Social Security Numbers (SSN)
        - Credit card numbers
        - Driver's license numbers
        - Passport numbers
        - IP addresses (considered personal data under GDPR)
        
        **Protected Health Information (PHI):**
        - Medical record numbers
        - Patient identifiers
        - Dates of birth
        - Medical diagnosis information
        - Treatment and prescription data
        - Health condition indicators
        
        ### 🛡️ Advanced Features:
        
        - **Duplicate Detection**: Eliminates redundant findings
        - **False Positive Filtering**: Reduces noise from tokens/API keys
        - **Context-Aware Analysis**: Better understanding of code context
        - **AST Parsing**: Deep code structure analysis
        - **Pattern Validation**: Ensures realistic PII patterns
        
        ### 📊 Data Privacy Focus Areas:
        
        - **Sample/Test Data**: Detection of PII in code examples
        - **Variable Naming**: Identification of variables storing sensitive data
        - **Logging Risks**: Detection of PII being logged or printed
        - **Accidental Exposure**: Finding PII in string literals and comments
        
        ### 📋 Compliance Frameworks:
        - **GDPR**: General Data Protection Regulation (EU)
        - **HIPAA**: Health Insurance Portability and Accountability Act (US Healthcare)
        - **CCPA**: California Consumer Privacy Act (US)
        - **PCI DSS**: Payment Card Industry Data Security Standard
        """)

if __name__ == "__main__":
    main()

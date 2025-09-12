import streamlit as st
import os
import ast
import re
from pathlib import Path
from typing import List, Dict, Tuple
import pandas as pd

class LoggingAnalyzer:
    def __init__(self):
        # Common logging patterns to detect
        self.logging_patterns = [
            r'logger\.\w+\(',
            r'log\.\w+\(',
            r'logging\.\w+\(',
            r'print\(',  # Basic print statements
            r'console\.\w+\(',
            r'_logger\.\w+\(',
            r'self\.logger\.\w+\(',
            r'self\.log\.\w+\(',
        ]
        
        # Logging method names
        self.logging_methods = [
            'debug', 'info', 'warning', 'warn', 'error', 'critical', 'exception',
            'log', 'print'
        ]
    
    def extract_functions_from_file(self, file_path: str) -> List[Dict]:
        """Extract all function definitions from a Python file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            tree = ast.parse(content)
            functions = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Get function source code
                    func_lines = content.split('\n')[node.lineno-1:node.end_lineno]
                    func_code = '\n'.join(func_lines)
                    
                    functions.append({
                        'name': node.name,
                        'lineno': node.lineno,
                        'code': func_code,
                        'file_path': file_path
                    })
            
            return functions
            
        except Exception as e:
            st.error(f"Error parsing {file_path}: {str(e)}")
            return []
    
    def has_logging(self, code: str) -> Tuple[bool, List[str]]:
        """Check if code contains logging statements"""
        found_patterns = []
        
        for pattern in self.logging_patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                found_patterns.extend(matches)
        
        return len(found_patterns) > 0, found_patterns
    
    def analyze_file(self, file_path: str) -> Dict:
        """Analyze a single Python file for logging observability"""
        functions = self.extract_functions_from_file(file_path)
        total_functions = len(functions)
        functions_with_logging = 0
        function_details = []
        
        for func in functions:
            has_log, patterns = self.has_logging(func['code'])
            if has_log:
                functions_with_logging += 1
            
            function_details.append({
                'function_name': func['name'],
                'has_logging': has_log,
                'logging_patterns': patterns,
                'line_number': func['lineno']
            })
        
        score = (functions_with_logging / total_functions * 100) if total_functions > 0 else 0
        
        return {
            'file_path': file_path,
            'total_functions': total_functions,
            'functions_with_logging': functions_with_logging,
            'score': score,
            'function_details': function_details
        }
    
    def analyze_directory(self, directory_path: str) -> List[Dict]:
        """Analyze all Python files in a directory"""
        results = []
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    result = self.analyze_file(file_path)
                    results.append(result)
        
        return results

def main():
    st.set_page_config(
        page_title="Code Logging Observability Analyzer",
        page_icon="🔍",
        layout="wide"
    )
    
    st.title("🔍 Python Code Logging Observability Analyzer")
    st.markdown("Analyze your Python code to check how well it uses logging for observability.")
    
    # Initialize analyzer
    analyzer = LoggingAnalyzer()
    
    # Input section
    st.header("📁 Input Configuration")
    
    input_type = st.radio("Select input type:", ["Single Python File", "Directory/Folder"])
    
    if input_type == "Single Python File":
        file_path = st.text_input("Enter path to Python file:", placeholder="/path/to/your/file.py")
        
        if st.button("Analyze File") and file_path:
            if os.path.exists(file_path) and file_path.endswith('.py'):
                with st.spinner("Analyzing file..."):
                    result = analyzer.analyze_file(file_path)
                    display_single_file_results(result)
            else:
                st.error("Please provide a valid Python file path.")
    
    else:  # Directory
        dir_path = st.text_input("Enter directory path:", placeholder="/path/to/your/project")
        
        if st.button("Analyze Directory") and dir_path:
            if os.path.exists(dir_path) and os.path.isdir(dir_path):
                with st.spinner("Analyzing directory..."):
                    results = analyzer.analyze_directory(dir_path)
                    if results:
                        display_directory_results(results)
                    else:
                        st.warning("No Python files found in the specified directory.")
            else:
                st.error("Please provide a valid directory path.")

def display_single_file_results(result: Dict):
    """Display results for a single file analysis"""
    st.header("📊 Analysis Results")
    
    # Summary metrics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Functions", result['total_functions'])
    
    with col2:
        st.metric("Functions with Logging", result['functions_with_logging'])
    
    with col3:
        st.metric("Observability Score", f"{result['score']:.1f}%")
    
    # Progress bar
    st.progress(result['score'] / 100)
    
    # Detailed function analysis
    st.subheader("🔍 Function Details")
    
    if result['function_details']:
        df_data = []
        for func in result['function_details']:
            df_data.append({
                'Function Name': func['function_name'],
                'Line Number': func['line_number'],
                'Has Logging': '✅' if func['has_logging'] else '❌',
                'Logging Patterns': ', '.join(func['logging_patterns']) if func['logging_patterns'] else 'None'
            })
        
        df = pd.DataFrame(df_data)
        st.dataframe(df, use_container_width=True)
        
        # Show functions without logging
        functions_without_logging = [f for f in result['function_details'] if not f['has_logging']]
        if functions_without_logging:
            st.subheader("⚠️ Functions Missing Logging")
            for func in functions_without_logging:
                st.write(f"• `{func['function_name']}` (Line {func['line_number']})")

def display_directory_results(results: List[Dict]):
    """Display results for directory analysis"""
    st.header("📊 Directory Analysis Results")
    
    # Overall summary
    total_files = len(results)
    total_functions = sum(r['total_functions'] for r in results)
    total_with_logging = sum(r['functions_with_logging'] for r in results)
    overall_score = (total_with_logging / total_functions * 100) if total_functions > 0 else 0
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Python Files", total_files)
    
    with col2:
        st.metric("Total Functions", total_functions)
    
    with col3:
        st.metric("Functions with Logging", total_with_logging)
    
    with col4:
        st.metric("Overall Score", f"{overall_score:.1f}%")
    
    st.progress(overall_score / 100)
    
    # File-by-file breakdown
    st.subheader("📁 File-by-File Analysis")
    
    df_data = []
    for result in results:
        df_data.append({
            'File Path': os.path.basename(result['file_path']),
            'Full Path': result['file_path'],
            'Total Functions': result['total_functions'],
            'Functions with Logging': result['functions_with_logging'],
            'Score (%)': f"{result['score']:.1f}%"
        })
    
    df = pd.DataFrame(df_data)
    st.dataframe(df, use_container_width=True)
    
    # Charts
    # st.subheader("📈 Visualization")
    
    # col1, col2 = st.columns(2)
    
    # with col1:
    #     # Score distribution
    #     scores = [r['score'] for r in results if r['total_functions'] > 0]
    #     if scores:
    #         st.bar_chart(pd.DataFrame({'Files': range(len(scores)), 'Scores': scores}).set_index('Files'))
    #         st.caption("Observability Scores by File")
    
    # with col2:
    #     # Summary pie chart data
    #     chart_data = pd.DataFrame({
    #         'Category': ['With Logging', 'Without Logging'],
    #         'Count': [total_with_logging, total_functions - total_with_logging]
    #     })
    #     st.bar_chart(chart_data.set_index('Category'))
    #     st.caption("Functions Distribution")
    
    # Recommendations
    st.subheader("💡 Recommendations")
    
    if overall_score < 30:
        st.error("🚨 Low observability! Consider adding logging to more functions.")
    elif overall_score < 60:
        st.warning("⚠️ Moderate observability. There's room for improvement.")
    elif overall_score < 80:
        st.info("ℹ️ Good observability! A few more functions could benefit from logging.")
    else:
        st.success("✅ Excellent observability! Your code is well-instrumented.")
    
    # Files needing attention
    low_score_files = [r for r in results if r['score'] < 50 and r['total_functions'] > 0]
    if low_score_files:
        st.subheader("🎯 Files Needing Attention")
        for file_result in low_score_files[:5]:  # Show top 5
            st.write(f"• `{os.path.basename(file_result['file_path'])}` - {file_result['score']:.1f}% ({file_result['functions_with_logging']}/{file_result['total_functions']} functions)")

if __name__ == "__main__":
    main()
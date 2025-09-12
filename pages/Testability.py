import streamlit as st
import os
import ast
import re
from pathlib import Path
from typing import List, Dict, Tuple, Set
import pandas as pd

class CodeTestabilityAnalyzer:
    def __init__(self):
        self.test_patterns = [
            r'test_.*\.py$',
            r'.*_test\.py$',
            r'tests\.py$'
        ]
        self.test_folders = ['test', 'tests', '__tests__']
    
    def is_test_file(self, filename: str) -> bool:
        """Check if a file is a test file based on naming patterns."""
        for pattern in self.test_patterns:
            if re.match(pattern, filename):
                return True
        return False
    
    def extract_functions_from_file(self, file_path: str) -> List[str]:
        """Extract function names from a Python file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            tree = ast.parse(content)
            functions = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Skip private methods and special methods for main code
                    if not file_path.endswith(('test.py', '_test.py')) or 'test' not in os.path.basename(file_path).lower():
                        if not node.name.startswith('_'):
                            functions.append(node.name)
                    else:
                        # For test files, include test functions
                        if node.name.startswith('test_'):
                            functions.append(node.name)
            
            return functions
        except Exception as e:
            st.warning(f"Could not parse {file_path}: {str(e)}")
            return []
    
    def find_python_files(self, path: str) -> Tuple[List[str], List[str]]:
        """Find all Python files and separate them into main code and test files."""
        python_files = []
        test_files = []
        
        if os.path.isfile(path) and path.endswith('.py'):
            if self.is_test_file(os.path.basename(path)):
                test_files.append(path)
            else:
                python_files.append(path)
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith('.py'):
                        file_path = os.path.join(root, file)
                        if self.is_test_file(file):
                            test_files.append(file_path)
                        else:
                            python_files.append(file_path)
        
        return python_files, test_files
    
    def extract_test_function_targets(self, test_functions: List[str]) -> Set[str]:
        """Extract the target function names from test function names."""
        targets = set()
        for test_func in test_functions:
            # Remove 'test_' prefix and extract the target function name
            if test_func.startswith('test_'):
                target = test_func[5:]  # Remove 'test_' prefix
                targets.add(target)
        return targets
    
    def analyze_testability(self, path: str) -> Dict:
        """Analyze the testability of code in the given path."""
        if not os.path.exists(path):
            return {"error": "Path does not exist"}
        
        python_files, test_files = self.find_python_files(path)
        
        # Extract all functions from main code files
        all_functions = {}
        total_functions = 0
        
        for py_file in python_files:
            functions = self.extract_functions_from_file(py_file)
            if functions:
                all_functions[py_file] = functions
                total_functions += len(functions)
        
        # Extract test functions and their targets
        all_test_functions = {}
        tested_functions = set()
        
        for test_file in test_files:
            test_functions = self.extract_functions_from_file(test_file)
            if test_functions:
                all_test_functions[test_file] = test_functions
                targets = self.extract_test_function_targets(test_functions)
                tested_functions.update(targets)
        
        # Calculate coverage
        main_function_names = set()
        for functions in all_functions.values():
            main_function_names.update(functions)
        
        tested_count = len(tested_functions.intersection(main_function_names))
        coverage_percentage = (tested_count / total_functions * 100) if total_functions > 0 else 0
        
        # Check for test folder structure
        has_test_folder = False
        test_folder_paths = []
        
        if os.path.isdir(path):
            for item in os.listdir(path):
                if os.path.isdir(os.path.join(path, item)) and item.lower() in self.test_folders:
                    has_test_folder = True
                    test_folder_paths.append(os.path.join(path, item))
        
        return {
            "total_python_files": len(python_files),
            "total_test_files": len(test_files),
            "total_functions": total_functions,
            "tested_functions": tested_count,
            "untested_functions": total_functions - tested_count,
            "coverage_percentage": coverage_percentage,
            "has_test_folder": has_test_folder,
            "test_folder_paths": test_folder_paths,
            "python_files": python_files,
            "test_files": test_files,
            "all_functions": all_functions,
            "all_test_functions": all_test_functions,
            "tested_function_names": list(tested_functions.intersection(main_function_names)),
            "untested_function_names": list(main_function_names - tested_functions)
        }

def main():
    st.set_page_config(
        page_title="Code Testability Analyzer",
        page_icon="🧪",
        layout="wide"
    )
    
    st.title("🧪 Code Testability Analyzer")
    st.markdown("Analyze your Python code to check testability and unit test coverage!")
    
    # Sidebar for input
    st.sidebar.header("Input Configuration")
    
    # Path input
    path_input = st.sidebar.text_input(
        "Enter path to Python file or folder:",
        placeholder="/path/to/your/code"
    )
    
    # File upload option
    st.sidebar.markdown("### Or upload a Python file:")
    uploaded_file = st.sidebar.file_uploader(
        "Choose a Python file",
        type=['py'],
        help="Upload a single Python file to analyze"
    )
    
    analyzer = CodeTestabilityAnalyzer()
    
    # Determine which input to use
    analysis_path = None
    temp_file_path = None
    
    if uploaded_file is not None:
        # Save uploaded file temporarily
        temp_file_path = f"/tmp/{uploaded_file.name}"
        with open(temp_file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        analysis_path = temp_file_path
        st.sidebar.success(f"File uploaded: {uploaded_file.name}")
    elif path_input:
        analysis_path = path_input
    
    if analysis_path:
        if st.sidebar.button("Analyze Testability", type="primary"):
            with st.spinner("Analyzing code testability..."):
                results = analyzer.analyze_testability(analysis_path)
            
            if "error" in results:
                st.error(f"Error: {results['error']}")
                return
            
            # Display results
            st.header("📊 Analysis Results")
            
            # Key metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric(
                    "Total Functions",
                    results['total_functions']
                )
            
            with col2:
                st.metric(
                    "Tested Functions",
                    results['tested_functions']
                )
            
            with col3:
                st.metric(
                    "Test Coverage",
                    f"{results['coverage_percentage']:.1f}%"
                )
            
            with col4:
                st.metric(
                    "Test Files Found",
                    results['total_test_files']
                )
            
            # Progress bar for coverage
            st.subheader("Test Coverage Progress")
            progress_color = "green" if results['coverage_percentage'] >= 80 else "orange" if results['coverage_percentage'] >= 50 else "red"
            st.progress(results['coverage_percentage'] / 100)
            
            # Test folder structure
            st.subheader("🗂️ Test Structure Analysis")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if results['has_test_folder']:
                    st.success("✅ Test folder structure found!")
                    for folder in results['test_folder_paths']:
                        st.write(f"📁 {folder}")
                else:
                    st.warning("⚠️ No dedicated test folder found")
            
            with col2:
                st.write(f"**Python files:** {results['total_python_files']}")
                st.write(f"**Test files:** {results['total_test_files']}")
            
            # Detailed breakdown
            if results['total_functions'] > 0:
                st.subheader("🔍 Detailed Function Analysis")
                
                # Create tabs for different views
                tab1, tab2, tab3 = st.tabs(["Coverage Overview", "Tested Functions", "Untested Functions"])
                
                with tab1:
                    # Coverage chart
                    coverage_data = {
                        'Status': ['Tested', 'Untested'],
                        'Count': [results['tested_functions'], results['untested_functions']],
                        'Percentage': [
                            results['coverage_percentage'],
                            100 - results['coverage_percentage']
                        ]
                    }
                    
                    df_coverage = pd.DataFrame(coverage_data)
                    st.bar_chart(df_coverage.set_index('Status')['Count'])
                
                with tab2:
                    if results['tested_function_names']:
                        st.success(f"✅ {len(results['tested_function_names'])} functions have tests:")
                        for func in sorted(results['tested_function_names']):
                            st.write(f"• `{func}`")
                    else:
                        st.info("No functions with tests found.")
                
                with tab3:
                    if results['untested_function_names']:
                        st.warning(f"⚠️ {len(results['untested_function_names'])} functions need tests:")
                        for func in sorted(results['untested_function_names']):
                            st.write(f"• `{func}`")
                    else:
                        st.success("All functions have tests! 🎉")
            
            # File breakdown
            with st.expander("📁 File-by-File Breakdown", expanded=False):
                st.subheader("Python Files and Functions")
                for file_path, functions in results['all_functions'].items():
                    st.write(f"**{os.path.basename(file_path)}** ({len(functions)} functions)")
                    for func in functions:
                        test_status = "✅" if func in results['tested_function_names'] else "❌"
                        st.write(f"  {test_status} `{func}`")
                
                if results['all_test_functions']:
                    st.subheader("Test Files and Test Functions")
                    for file_path, test_functions in results['all_test_functions'].items():
                        st.write(f"**{os.path.basename(file_path)}** ({len(test_functions)} test functions)")
                        for func in test_functions:
                            st.write(f"  🧪 `{func}`")
            
            # Recommendations
            st.subheader("💡 Recommendations")
            
            if results['coverage_percentage'] < 50:
                st.error("🚨 Low test coverage! Consider adding more unit tests.")
            elif results['coverage_percentage'] < 80:
                st.warning("⚠️ Moderate test coverage. Aim for 80%+ coverage.")
            else:
                st.success("🎉 Good test coverage! Keep it up!")
            
            if not results['has_test_folder']:
                st.info("💡 Consider creating a dedicated 'tests' or 'test' folder for better organization.")
            
            if results['total_test_files'] == 0:
                st.error("❗ No test files found. Start by creating test files with 'test_' prefix.")
            
            # Clean up temporary file
            if temp_file_path and os.path.exists(temp_file_path):
                os.remove(temp_file_path)
    
    else:
        st.info("👆 Please enter a file/folder path or upload a Python file to analyze.")
        
        # Example usage
        st.subheader("📖 How to use:")
        st.markdown("""
        1. **Enter a path** to your Python file or project folder
        2. **Or upload** a single Python file
        3. **Click 'Analyze Testability'** to get your results
        
        ### What it analyzes:
        - ✅ Presence of test folders (`test`, `tests`, `__tests__`)
        - ✅ Number of test files (files with `test_*.py`, `*_test.py` patterns)
        - ✅ Functions in your code vs functions with unit tests
        - ✅ Test coverage percentage
        - ✅ Detailed breakdown of tested/untested functions
        
        ### Example test file structure:
        ```python
        # main.py
        def calculate_sum(a, b):
            return a + b
        
        def multiply(x, y):
            return x * y
        
        # test_main.py
        def test_calculate_sum():
            assert calculate_sum(2, 3) == 5
        
        # This would show 50% coverage (1 out of 2 functions tested)
        ```
        """)

if __name__ == "__main__":
    main()
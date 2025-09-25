"""
Setup script for Phase 1 implementation.
Initializes the consolidated code review tool and tests basic functionality.
"""
# Flake8: noqa: E501

import os
import sys
import logging
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def check_dependencies():
    """Check if required dependencies are available."""
    required_packages = ["streamlit", "pandas", "asyncio"]

    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
            logger.info(f"✅ {package} is available")
        except ImportError:
            missing_packages.append(package)
            logger.error(f"❌ {package} is missing")

    if missing_packages:
        logger.error(f"Missing packages: {missing_packages}")
        logger.info("Install with: pip install " + " ".join(missing_packages))
        return False

    return True


def check_external_tools():
    """Check if external analysis tools are available."""
    import subprocess

    tools = {
        "gitleaks": "gitleaks version",
        "bandit": "bandit --help",
        "pylint": "pylint --version",
        "mypy": "mypy --version",
    }

    available_tools = []
    missing_tools = []

    for tool, command in tools.items():
        try:
            result = subprocess.run(
                command.split(), capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                available_tools.append(tool)
                logger.info(f"✅ {tool} is available")
            else:
                missing_tools.append(tool)
                logger.warning(f"⚠️ {tool} is not working properly")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            missing_tools.append(tool)
            logger.warning(f"⚠️ {tool} is not installed")

    if missing_tools:
        logger.warning(f"Missing tools: {missing_tools}")
        logger.info("Some analyzers may not work without these tools")

    return available_tools, missing_tools


def test_core_components():
    """Test core components functionality."""
    logger.info("Testing core components...")

    try:
        # Test imports
        from core.models import (
            UnifiedFinding,
            ConsolidatedReport,
            AnalysisConfiguration,
        )
        from core.engine import UnifiedAnalysisEngine
        from core.interfaces import analyzer_registry
        from core.aggregator import ResultAggregator
        from core.transformers import DataTransformer

        logger.info("✅ Core imports successful")

        # Test basic instantiation
        engine = UnifiedAnalysisEngine()
        aggregator = ResultAggregator()
        transformer = DataTransformer()

        logger.info("✅ Core component instantiation successful")

        # Test analyzer registry
        analyzer_count = len(analyzer_registry.list_analyzer_names())
        logger.info(f"✅ Analyzer registry initialized ({analyzer_count} analyzers)")

        return True

    except Exception as e:
        logger.error(f"❌ Core components test failed: {str(e)}")
        return False


def test_analyzers():
    """Test analyzer functionality."""
    logger.info("Testing analyzers...")

    try:
        from core.interfaces import analyzer_registry
        from analyzers.secrets_analyzer import HardcodedSecretsAnalyzer
        from analyzers.robustness_analyzer import RobustnessAnalyzer
        from analyzers.pii_analyzer import PIIAnalyzer
        from analyzers.testability_analyzer import TestabilityAnalyzer
        from analyzers.observability_analyzer import ObservabilityAnalyzer
        from analyzers.readability_analyzer import ReadabilityAnalyzer
        from analyzers.injection_analyzer import InjectionAnalyzer

        # Test analyzer instantiation
        secrets_analyzer = HardcodedSecretsAnalyzer()
        robustness_analyzer = RobustnessAnalyzer()
        pii_analyzer = PIIAnalyzer()
        testability_analyzer = TestabilityAnalyzer()
        observability_analyzer = ObservabilityAnalyzer()
        readability_analyzer = ReadabilityAnalyzer()
        injection_analyzer = InjectionAnalyzer()
        logger.info("✅ Analyzer instantiation successful")

        # Register analyzers
        analyzer_registry.register(secrets_analyzer)
        analyzer_registry.register(robustness_analyzer)
        analyzer_registry.register(pii_analyzer)
        analyzer_registry.register(testability_analyzer)
        analyzer_registry.register(observability_analyzer)
        analyzer_registry.register(readability_analyzer)
        analyzer_registry.register(injection_analyzer)

        # Test analyzer properties
        secrets_name = secrets_analyzer.get_name()
        secrets_version = secrets_analyzer.get_version()
        secrets_file_types = secrets_analyzer.get_supported_file_types()

        robustness_name = robustness_analyzer.get_name()
        robustness_version = robustness_analyzer.get_version()
        robustness_file_types = robustness_analyzer.get_supported_file_types()
        robustness_categories = robustness_analyzer.get_quality_categories()

        pii_name = pii_analyzer.get_name()
        pii_version = pii_analyzer.get_version()
        pii_file_types = pii_analyzer.get_supported_file_types()
        pii_frameworks = pii_analyzer.get_compliance_frameworks()

        testability_name = testability_analyzer.get_name()
        testability_version = testability_analyzer.get_version()
        testability_file_types = testability_analyzer.get_supported_file_types()
        testability_categories = testability_analyzer.get_quality_categories()

        observability_name = observability_analyzer.get_name()
        observability_version = observability_analyzer.get_version()
        observability_file_types = observability_analyzer.get_supported_file_types()
        observability_categories = observability_analyzer.get_quality_categories()

        readability_name = readability_analyzer.get_name()
        readability_version = readability_analyzer.get_version()
        readability_file_types = readability_analyzer.get_supported_file_types()
        readability_categories = readability_analyzer.get_quality_categories()

        injection_name = injection_analyzer.get_name()
        injection_version = injection_analyzer.get_version()
        injection_file_types = injection_analyzer.get_supported_file_types()
        injection_categories = injection_analyzer.get_security_categories()

        logger.info(
            f"✅ Secrets analyzer: {secrets_name} v{secrets_version}, supports: {secrets_file_types}"
        )
        logger.info(
            f"✅ Robustness analyzer: {robustness_name} v{robustness_version}, supports: {robustness_file_types}"
        )
        logger.info(f"✅ Robustness categories: {robustness_categories}")
        logger.info(
            f"✅ PII/PHI analyzer: {pii_name} v{pii_version}, supports: {pii_file_types}"
        )
        logger.info(f"✅ PII/PHI frameworks: {pii_frameworks}")
        logger.info(
            f"✅ Testability analyzer: {testability_name} v{testability_version}, supports: {testability_file_types}"
        )
        logger.info(f"✅ Testability categories: {testability_categories}")
        logger.info(
            f"✅ Observability analyzer: {observability_name} v{observability_version}, supports: {observability_file_types}"
        )
        logger.info(f"✅ Observability categories: {observability_categories}")
        logger.info(
            f"✅ Readability analyzer: {readability_name} v{readability_version}, supports: {readability_file_types}"
        )
        logger.info(f"✅ Readability categories: {readability_categories}")
        logger.info(
            f"✅ Injection analyzer: {injection_name} v{injection_version}, supports: {injection_file_types}"
        )
        logger.info(f"✅ Injection categories: {injection_categories}")

        # Test registry
        registered_analyzers = analyzer_registry.list_analyzer_names()
        logger.info(f"✅ Registered analyzers: {registered_analyzers}")

        return True

    except Exception as e:
        logger.error(f"❌ Analyzer test failed: {str(e)}")
        return False


def create_test_files():
    """Create test files for analysis."""
    test_dir = Path("test_project")
    test_dir.mkdir(exist_ok=True)

    # Create a test Python file with potential issues
    test_file = test_dir / "main_code.py"
    test_content = '''#!/usr/bin/env python3
    """
    Test file for code analysis.
    Contains various issues for testing purposes.
    """

    import os
    import subprocess
    import requests

    # Hardcoded secret (for testing)
    API_KEY = "sk-1234567890abcdef"
    PASSWORD = "admin123"

    class TestClass:
        def __init__(self):
            self.secret = "secret_key_here"

        def process_data(self, data):
            # Dictionary access without .get() - robustness issue
            name = data["name"]
            email = data["email"]
            
            # File operations without try/except - robustness issue
            file_content = open("data.txt").read()
            
            # Network request without timeout - robustness issue (B113)
            response = requests.get("https://api.example.com/data")
            
            return {"name": name, "email": email}
        
        def unsafe_sql(self, user_input):
            # SQL injection vulnerability
            query = f"SELECT * FROM users WHERE name = '{user_input}'"
            return query
        
        def process_patient_data(self, patient_email, phone_number):
            # PII data handling - for testing PII analyzer
            user_ssn = "123-45-6789"  # Test SSN
            patient_diagnosis = "The patient has diabetes"
            return {"email": patient_email, "phone": phone_number}
        
        def calculate_total(self, items):
            # Function without tests - for testability analyzer
            total = 0
            for item in items:
                total += item.get("price", 0)
            return total
        
        def validate_input(self, data):
            # Another function without tests - no logging either
            if not data:
                return False
            return len(data) > 0
        
        def critical_process(self, user_data):
            # Critical function without logging - for observability analyzer
            try:
                result = self.process_data(user_data)
                return result
            except Exception:
                return None  # No logging of errors!
        
        def execute_command(self, command):
            # Command injection vulnerability - for injection analyzer
            import os
            os.system("ls " + command)  # Unsafe concatenation!
            return "executed"
        
        def unsafe_sql(self, user_input):
            # SQL injection vulnerability
            query = f"SELECT * FROM users WHERE name = '{user_input}'"
            return query

    def missing_docstring_function():
        pass

    # Unused import and variable
    import json
    unused_var = "not used"

    if __name__ == "__main__":
        test = TestClass()
        test.process_data("test")
    '''

    # Create a test file with some basic tests
    test_test_file = test_dir / "test_main.py"
    test_content = '''#!/usr/bin/env python3
    """
    Test file for testing testability analyzer.
    """

    def test_unsafe_sql():
        # Test for one function but not others  
        from main_code import TestClass
        tc = TestClass()
        result = tc.unsafe_sql("test")
        assert "test" in result

    # Missing tests for other functions like calculate_total, validate_input, etc.
    '''

    with open(test_file, "w") as f:
        f.write(test_content)
    
    with open(test_test_file, "w") as f:
        f.write(test_content)

    logger.info(f"✅ Created main file: {test_file}")
    logger.info(f"✅ Created test file: {test_test_file}")

    # Create requirements.txt with vulnerable dependencies
    requirements_file = test_dir / "requirements.txt"
    requirements_content = """django==2.0.0
    requests==2.20.0
    flask==0.12.0
    """

    with open(requirements_file, "w") as f:
        f.write(requirements_content)

    logger.info(f"✅ Created requirements file: {requirements_file}")

    return str(test_dir)


def run_sample_analysis():
    """Run a sample analysis to test the system."""
    logger.info("Running sample analysis...")

    try:
        import asyncio
        from core.engine import UnifiedAnalysisEngine
        from core.models import AnalysisConfiguration
        from core.interfaces import analyzer_registry
        from analyzers.secrets_analyzer import HardcodedSecretsAnalyzer

        # Register analyzers
        secrets_analyzer = HardcodedSecretsAnalyzer()
        analyzer_registry.register(secrets_analyzer)
        
        from analyzers.robustness_analyzer import RobustnessAnalyzer
        robustness_analyzer = RobustnessAnalyzer()
        analyzer_registry.register(robustness_analyzer)
        
        from analyzers.pii_analyzer import PIIAnalyzer
        pii_analyzer = PIIAnalyzer()
        analyzer_registry.register(pii_analyzer)
        
        from analyzers.testability_analyzer import TestabilityAnalyzer
        testability_analyzer = TestabilityAnalyzer()
        analyzer_registry.register(testability_analyzer)
        
        from analyzers.observability_analyzer import ObservabilityAnalyzer
        observability_analyzer = ObservabilityAnalyzer()
        analyzer_registry.register(observability_analyzer)
        
        from analyzers.readability_analyzer import ReadabilityAnalyzer
        readability_analyzer = ReadabilityAnalyzer()
        analyzer_registry.register(readability_analyzer)
        
        from analyzers.injection_analyzer import InjectionAnalyzer
        injection_analyzer = InjectionAnalyzer()
        analyzer_registry.register(injection_analyzer)

        # Create test files
        test_dir = create_test_files()

        # Setup analysis configuration
        config = AnalysisConfiguration(
            target_path=test_dir,
            enabled_analyzers={"hardcoded_secrets", "robustness", "pii_phi", "testability", "observability", "readability", "injection"},
            parallel_execution=False,
        )

        # Run analysis
        engine = UnifiedAnalysisEngine()

        # Use asyncio to run the async analysis
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        report = loop.run_until_complete(engine.analyze(config))

        # Display results
        logger.info(f"✅ Analysis completed successfully!")
        logger.info(f"   - Target: {report.target_path}")
        logger.info(f"   - Duration: {report.total_execution_time:.2f}s")
        logger.info(f"   - Findings: {len(report.findings)}")
        logger.info(f"   - Analyzers: {len(report.analysis_metrics)}")

        if report.findings:
            logger.info("   - Sample findings:")
            for finding in report.findings[:3]:
                logger.info(f"     * {finding.severity.value.upper()}: {finding.title}")

        return True

    except Exception as e:
        logger.error(f"❌ Sample analysis failed: {str(e)}")
        return False


def main():
    """Main setup and test function."""
    logger.info("🚀 Setting up Phase 1 Consolidated Code Review Tool")
    logger.info("=" * 60)

    # Check dependencies
    logger.info("1. Checking Python dependencies...")
    if not check_dependencies():
        logger.error("❌ Dependency check failed")
        return False

    # Check external tools
    logger.info("\n2. Checking external tools...")
    available_tools, missing_tools = check_external_tools()

    # Test core components
    logger.info("\n3. Testing core components...")
    if not test_core_components():
        logger.error("❌ Core components test failed")
        return False

    # Test analyzers
    logger.info("\n4. Testing analyzers...")
    if not test_analyzers():
        logger.error("❌ Analyzer test failed")
        return False

    # Run sample analysis
    logger.info("\n5. Running sample analysis...")
    if not run_sample_analysis():
        logger.error("❌ Sample analysis failed")
        return False

    # Success message
    logger.info("\n" + "=" * 60)
    logger.info("🎉 Phase 1 setup completed successfully!")
    logger.info("\nTo run the consolidated application:")
    logger.info("  streamlit run main_consolidated.py")
    logger.info("\nTo run individual legacy modules:")
    logger.info("  streamlit run parts/app_Hardcoded_Secrets.py")
    logger.info("  streamlit run parts/app_Robustness.py")
    logger.info("  ... etc")

    if missing_tools:
        logger.info(f"\n⚠️ Note: Some tools are missing: {missing_tools}")
        logger.info("Install them for full functionality:")
        for tool in missing_tools:
            if tool == "gitleaks":
                logger.info("  - Gitleaks: https://github.com/gitleaks/gitleaks")
            elif tool == "bandit":
                logger.info("  - Bandit: pip install bandit")
            elif tool == "pylint":
                logger.info("  - Pylint: pip install pylint")
            elif tool == "mypy":
                logger.info("  - MyPy: pip install mypy")

    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

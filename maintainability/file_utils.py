"""
File Utilities for Code Analysis Tool
Provides file system operations and Python file discovery.
"""

import os
import fnmatch
from pathlib import Path
from typing import List, Set


def find_python_files(directory: str, max_depth: int = 10) -> List[str]:
    """
    Find all Python files in a directory recursively.

    Args:
        directory (str): Directory to search
        max_depth (int): Maximum recursion depth

    Returns:
        List[str]: List of Python file paths
    """
    python_files = []

    # Ignored directories and patterns
    ignored_dirs = {
        "__pycache__",
        ".git",
        ".svn",
        ".hg",
        "node_modules",
        "venv",
        "env",
        ".env",
        ".venv",
        "virtualenv",
        "build",
        "dist",
        ".tox",
        ".pytest_cache",
        ".mypy_cache",
        ".coverage",
        "htmlcov",
    }

    ignored_patterns = {".*", "_*", "__*", "test_*", "*_test.py", "tests.py"}

    def should_ignore_dir(dir_name: str) -> bool:
        """Check if directory should be ignored."""
        return dir_name in ignored_dirs or dir_name.startswith(".")

    def should_ignore_file(file_name: str) -> bool:
        """Check if file should be ignored based on patterns."""
        for pattern in ignored_patterns:
            if fnmatch.fnmatch(file_name, pattern):
                return False  # Don't ignore test files for analysis
        return False

    def walk_directory(current_dir: str, current_depth: int = 0):
        """Recursively walk directory to find Python files."""
        if current_depth > max_depth:
            return

        try:
            for item in os.listdir(current_dir):
                item_path = os.path.join(current_dir, item)

                if os.path.isfile(item_path):
                    # Check if it's a Python file
                    if item.endswith(".py") and not should_ignore_file(item):
                        # Verify file size (skip very large files)
                        try:
                            if (
                                os.path.getsize(item_path) < 10 * 1024 * 1024
                            ):  # 10MB limit
                                python_files.append(item_path)
                        except OSError:
                            continue

                elif os.path.isdir(item_path):
                    # Recursively search subdirectories
                    if not should_ignore_dir(item):
                        walk_directory(item_path, current_depth + 1)

        except (PermissionError, OSError):
            # Skip directories we can't access
            pass

    walk_directory(directory)
    return sorted(python_files)


def find_requirements_files(directory: str) -> List[str]:
    """
    Find requirements files in a directory.

    Args:
        directory (str): Directory to search

    Returns:
        List[str]: List of requirements file paths
    """
    requirements_files = []
    requirements_patterns = [
        "requirements.txt",
        "requirements-*.txt",
        "dev-requirements.txt",
        "test-requirements.txt",
        "requirements/*.txt",
        "pyproject.toml",
        "Pipfile",
        "poetry.lock",
        "setup.py",
        "setup.cfg",
    ]

    def find_files_with_pattern(pattern: str, base_dir: str):
        """Find files matching a pattern."""
        if "/" in pattern:
            # Handle subdirectory patterns
            subdir, file_pattern = pattern.split("/", 1)
            subdir_path = os.path.join(base_dir, subdir)
            if os.path.isdir(subdir_path):
                for file in os.listdir(subdir_path):
                    if fnmatch.fnmatch(file, file_pattern):
                        requirements_files.append(os.path.join(subdir_path, file))
        else:
            # Handle root directory patterns
            for file in os.listdir(base_dir):
                if fnmatch.fnmatch(file, pattern):
                    file_path = os.path.join(base_dir, file)
                    if os.path.isfile(file_path):
                        requirements_files.append(file_path)

    try:
        for pattern in requirements_patterns:
            find_files_with_pattern(pattern, directory)
    except (PermissionError, OSError):
        pass

    return sorted(list(set(requirements_files)))  # Remove duplicates


def find_config_files(directory: str) -> List[str]:
    """
    Find configuration files that might contain security-sensitive information.

    Args:
        directory (str): Directory to search

    Returns:
        List[str]: List of configuration file paths
    """
    config_files = []
    config_patterns = [
        "*.ini",
        "*.cfg",
        "*.conf",
        "*.config",
        ".env*",
        "*.env",
        "environment*",
        "config.py",
        "settings.py",
        "local_settings.py",
        "*.yaml",
        "*.yml",
        "*.json",
    ]

    def search_directory(current_dir: str, depth: int = 0):
        """Search directory for config files."""
        if depth > 3:  # Limit recursion depth
            return

        try:
            for item in os.listdir(current_dir):
                item_path = os.path.join(current_dir, item)

                if os.path.isfile(item_path):
                    for pattern in config_patterns:
                        if fnmatch.fnmatch(item, pattern):
                            config_files.append(item_path)
                            break

                elif os.path.isdir(item_path) and not item.startswith("."):
                    search_directory(item_path, depth + 1)

        except (PermissionError, OSError):
            pass

    search_directory(directory)
    return sorted(list(set(config_files)))


def get_file_info(file_path: str) -> dict:
    """
    Get information about a file.

    Args:
        file_path (str): Path to the file

    Returns:
        dict: File information including size, lines, etc.
    """
    try:
        stat = os.stat(file_path)

        # Count lines
        lines = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = sum(1 for _ in f)
        except (UnicodeDecodeError, OSError):
            pass

        return {
            "path": file_path,
            "size": stat.st_size,
            "lines": lines,
            "modified": stat.st_mtime,
            "extension": Path(file_path).suffix,
        }
    except OSError:
        return {
            "path": file_path,
            "size": 0,
            "lines": 0,
            "modified": 0,
            "extension": Path(file_path).suffix,
            "error": "Could not access file",
        }


def is_text_file(file_path: str) -> bool:
    """
    Check if a file is a text file.

    Args:
        file_path (str): Path to the file

    Returns:
        bool: True if file appears to be text
    """
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)

        # Check for null bytes (binary indicator)
        if b"\x00" in chunk:
            return False

        # Try to decode as UTF-8
        try:
            chunk.decode("utf-8")
            return True
        except UnicodeDecodeError:
            pass

        # Try other common encodings
        for encoding in ["latin-1", "cp1252"]:
            try:
                chunk.decode(encoding)
                return True
            except UnicodeDecodeError:
                continue

        return False
    except OSError:
        return False


def safe_read_file(file_path: str, max_size: int = 1048576) -> str:
    """
    Safely read a file with size limits and encoding detection.

    Args:
        file_path (str): Path to the file
        max_size (int): Maximum file size to read (default 1MB)

    Returns:
        str: File content or empty string if error
    """
    try:
        # Check file size
        if os.path.getsize(file_path) > max_size:
            return ""

        # Try different encodings
        encodings = ["utf-8", "latin-1", "cp1252", "utf-16"]

        for encoding in encodings:
            try:
                with open(file_path, "r", encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue

        return ""
    except OSError:
        return ""


def create_file_tree(directory: str, max_depth: int = 3) -> dict:
    """
    Create a tree representation of files in a directory.

    Args:
        directory (str): Directory to analyze
        max_depth (int): Maximum depth to traverse

    Returns:
        dict: Tree structure of files and directories
    """

    def build_tree(current_dir: str, current_depth: int = 0):
        """Recursively build directory tree."""
        if current_depth > max_depth:
            return {"type": "directory", "children": {}, "truncated": True}

        tree = {"type": "directory", "children": {}}

        try:
            items = sorted(os.listdir(current_dir))

            for item in items:
                item_path = os.path.join(current_dir, item)

                if os.path.isfile(item_path):
                    file_info = get_file_info(item_path)
                    tree["children"][item] = {
                        "type": "file",
                        "size": file_info["size"],
                        "lines": file_info["lines"],
                        "extension": file_info["extension"],
                    }

                elif os.path.isdir(item_path) and not item.startswith("."):
                    tree["children"][item] = build_tree(item_path, current_depth + 1)

        except (PermissionError, OSError):
            tree["error"] = "Access denied"

        return tree

    return build_tree(directory)


def validate_python_syntax(file_path: str) -> dict:
    """
    Validate Python syntax of a file.

    Args:
        file_path (str): Path to Python file

    Returns:
        dict: Validation result with any syntax errors
    """
    try:
        content = safe_read_file(file_path)
        if not content:
            return {"valid": False, "error": "Could not read file"}

        compile(content, file_path, "exec")
        return {"valid": True}

    except SyntaxError as e:
        return {
            "valid": False,
            "error": "Syntax error",
            "line": e.lineno,
            "column": e.offset,
            "message": str(e),
        }
    except Exception as e:
        return {"valid": False, "error": "Compilation error", "message": str(e)}

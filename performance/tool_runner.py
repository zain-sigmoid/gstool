"""
Tool Runner Utility for Code Analysis Tool
Safely executes external analysis tools with timeout and error handling.
"""

import subprocess
import signal
import os
import shutil
import tempfile
from typing import List, Optional, Dict, Any
from pathlib import Path
from termcolor import colored


class ToolTimeoutError(Exception):
    """Raised when a tool execution times out."""

    pass


class ToolNotFoundError(Exception):
    """Raised when a required tool is not found."""

    pass


class ToolRunner:
    """Utility class for running external analysis tools safely."""

    def __init__(self):
        """Initialize the tool runner."""
        self.tool_cache = {}
        self._check_tool_availability()

    def _check_tool_availability(self):
        """Check which tools are available on the system."""
        tools_to_check = [
            "pylint",
            "semgrep",
            "gitleaks",
            "radon",
            "mypy",
            "pip-audit",
            "pip-licenses",
            "bandit",
            "safety",
        ]

        for tool in tools_to_check:
            self.tool_cache[tool] = shutil.which(tool) is not None

    def is_tool_available(self, tool_name: str) -> bool:
        """
        Check if a tool is available on the system.

        Args:
            tool_name (str): Name of the tool

        Returns:
            bool: True if tool is available
        """
        return self.tool_cache.get(tool_name, False)

    def run_tool(
        self,
        tool_name: str,
        args: List[str],
        timeout: int = 300,
        capture_output: bool = True,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> subprocess.CompletedProcess:
        """
        Run an external tool with proper error handling and timeout.

        Args:
            tool_name (str): Name of the tool to run
            args (List[str]): Arguments to pass to the tool
            timeout (int): Timeout in seconds (default 300)
            capture_output (bool): Whether to capture stdout/stderr
            cwd (Optional[str]): Working directory
            env (Optional[Dict[str, str]]): Environment variables

        Returns:
            subprocess.CompletedProcess: Result of the tool execution

        Raises:
            ToolNotFoundError: If the tool is not available
            ToolTimeoutError: If the tool execution times out
        """
        if not self.is_tool_available(tool_name):
            # Try to install common tools via pip if they're missing
            if tool_name in ["pip-audit", "pip-licenses"]:
                try:
                    self._install_pip_tool(tool_name)
                    self.tool_cache[tool_name] = True
                except Exception:
                    raise ToolNotFoundError(
                        f"Tool '{tool_name}' is not available and could not be installed"
                    )
            else:
                raise ToolNotFoundError(f"Tool '{tool_name}' is not available")

        # Prepare command
        cmd = [tool_name] + args

        # Set up environment
        if env is None:
            env = os.environ.copy()

        # Add common Python paths
        env["PYTHONPATH"] = env.get("PYTHONPATH", "") + ":" + str(Path.cwd())

        try:
            # Run the tool with timeout
            result = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
            )
            return result

        except subprocess.TimeoutExpired:
            raise ToolTimeoutError(
                f"Tool '{tool_name}' timed out after {timeout} seconds"
            )

        except FileNotFoundError:
            raise ToolNotFoundError(f"Tool '{tool_name}' was not found in PATH")

        except Exception as e:
            # Return a failed result instead of raising
            return subprocess.CompletedProcess(
                cmd, returncode=1, stdout="", stderr=str(e)
            )

    def _install_pip_tool(self, tool_name: str):
        """Attempt to install a pip-based tool."""
        install_map = {"pip-audit": "pip-audit", "pip-licenses": "pip-licenses"}

        if tool_name in install_map:
            package_name = install_map[tool_name]
            subprocess.run(
                ["pip", "install", package_name], capture_output=True, timeout=60
            )

    def run_pylint(
        self, path: str, config_file: Optional[str] = None
    ) -> subprocess.CompletedProcess:
        """
        Run pylint analysis.

        Args:
            path (str): Path to analyze
            config_file (Optional[str]): Path to pylint config file

        Returns:
            subprocess.CompletedProcess: Pylint results
        """
        args = [path, "--output-format=json"]

        if config_file and os.path.exists(config_file):
            args.extend(["--rcfile", config_file])

        # Disable some noisy checks by default
        args.extend(
            ["--disable=import-error,no-name-in-module,missing-module-docstring"]
        )

        return self.run_tool("pylint", args, timeout=300)

    def run_semgrep(
        self, path: str, rules: Optional[List[str]] = None
    ) -> subprocess.CompletedProcess:
        """
        Run semgrep security analysis.

        Args:
            path (str): Path to analyze
            rules (Optional[List[str]]): Custom rules to use

        Returns:
            subprocess.CompletedProcess: Semgrep results
        """
        args = ["--json", "--config=auto", path]

        if rules:
            args = ["--json"] + [f"--config={rule}" for rule in rules] + [path]

        return self.run_tool("semgrep", args, timeout=300)

    def run_gitleaks(self, path: str) -> subprocess.CompletedProcess:
        """
        Run gitleaks secret detection.

        Args:
            path (str): Path to analyze

        Returns:
            subprocess.CompletedProcess: Gitleaks results
        """
        # args = [
        #     "detect",
        #     "--source",
        #     path,
        #     "--report-format",
        #     "json",
        #     "--no-git",
        #     "--verbose",
        # ]
        args = [
            "dir",
            path,
            "-c",
            "gitleaks.toml",
            "-f",
            "json",
            "-r",
            "leaks.json",
        ]
        print(
            colored("Running gitleaks for secret detection... tool runner 229", "cyan")
        )
        return self.run_tool("gitleaks", args, timeout=180)

    def run_radon(self, path: str, metric: str = "cc") -> subprocess.CompletedProcess:
        """
        Run radon complexity analysis.

        Args:
            path (str): Path to analyze
            metric (str): Metric to calculate (cc, mi, raw, hal)

        Returns:
            subprocess.CompletedProcess: Radon results
        """
        args = [metric, path, "--json"]

        return self.run_tool("radon", args, timeout=120)

    def run_mypy(
        self, path: str, config_file: Optional[str] = None
    ) -> subprocess.CompletedProcess:
        """
        Run mypy type checking.

        Args:
            path (str): Path to analyze
            config_file (Optional[str]): Path to mypy config file

        Returns:
            subprocess.CompletedProcess: MyPy results
        """
        args = [path, "--show-error-codes", "--no-error-summary"]

        if config_file and os.path.exists(config_file):
            args.extend(["--config-file", config_file])

        return self.run_tool("mypy", args, timeout=300)

    def run_pip_audit(self, path: str) -> subprocess.CompletedProcess:
        """
        Run pip-audit for dependency vulnerability scanning.

        Args:
            path (str): Path to analyze

        Returns:
            subprocess.CompletedProcess: pip-audit results
        """
        # Try to find requirements files
        req_files = []
        for req_file in ["requirements.txt", "requirements-dev.txt", "pyproject.toml"]:
            req_path = os.path.join(path, req_file)
            if os.path.exists(req_path):
                req_files.append(req_path)

        if req_files:
            args = ["--format=json"] + [f"--requirement={f}" for f in req_files]
        else:
            # Fallback to scanning the environment
            args = ["--format=json"]

        return self.run_tool("pip-audit", args, timeout=180)

    def run_pip_licenses(self) -> subprocess.CompletedProcess:
        """
        Run pip-licenses to check package licenses.

        Returns:
            subprocess.CompletedProcess: pip-licenses results
        """
        args = ["--format=json", "--with-urls", "--with-description"]

        return self.run_tool("pip-licenses", args, timeout=60)

    def run_bandit(self, path: str) -> subprocess.CompletedProcess:
        """
        Run bandit security analysis.

        Args:
            path (str): Path to analyze

        Returns:
            subprocess.CompletedProcess: Bandit results
        """
        args = ["-r", path, "-f", "json"]

        return self.run_tool("bandit", args, timeout=300)

    def create_temp_config(self, tool_name: str, config_content: str) -> str:
        """
        Create a temporary configuration file for a tool.

        Args:
            tool_name (str): Name of the tool
            config_content (str): Configuration content

        Returns:
            str: Path to the temporary config file
        """
        suffix_map = {"pylint": ".ini", "mypy": ".ini", "semgrep": ".yml"}

        suffix = suffix_map.get(tool_name, ".conf")

        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as f:
            f.write(config_content)
            return f.name

    def cleanup_temp_files(self, file_paths: List[str]):
        """
        Clean up temporary files.

        Args:
            file_paths (List[str]): List of file paths to delete
        """
        for file_path in file_paths:
            try:
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except OSError:
                pass

    def get_available_tools(self) -> Dict[str, bool]:
        """
        Get a dictionary of available tools.

        Returns:
            Dict[str, bool]: Dictionary mapping tool names to availability
        """
        return self.tool_cache.copy()

    def run_tool_with_retry(
        self, tool_name: str, args: List[str], max_retries: int = 2, **kwargs
    ) -> subprocess.CompletedProcess:
        """
        Run a tool with retry logic.

        Args:
            tool_name (str): Name of the tool
            args (List[str]): Arguments to pass
            max_retries (int): Maximum number of retries
            **kwargs: Additional arguments for run_tool

        Returns:
            subprocess.CompletedProcess: Tool execution result
        """
        last_exception = None

        for attempt in range(max_retries + 1):
            try:
                return self.run_tool(tool_name, args, **kwargs)
            except (ToolTimeoutError, ToolNotFoundError) as e:
                last_exception = e
                if attempt == max_retries:
                    break
                # Wait a bit before retrying
                import time

                time.sleep(1)

        # Return a failed result with the last exception
        return subprocess.CompletedProcess(
            [tool_name] + args, returncode=1, stdout="", stderr=str(last_exception)
        )

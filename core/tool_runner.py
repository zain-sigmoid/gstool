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

"""Safe subprocess execution utilities."""

import subprocess
import shlex
from typing import Sequence, Optional
from pathlib import Path


class SafeSubprocessError(Exception):
    """Exception raised for subprocess-related errors."""
    pass


def run_safe(
    command: Sequence[str],
    cwd: Optional[Path] = None,
    env: Optional[dict] = None,
    capture_output: bool = True,
    text: bool = True,
    check: bool = False,
) -> subprocess.CompletedProcess:
    """Execute a subprocess safely with explicit argument list.
    
    This function NEVER uses shell=True and validates all arguments.
    
    Args:
        command: Command and arguments as a list (no shell interpretation)
        cwd: Working directory for the command
        env: Environment variables
        capture_output: Whether to capture stdout/stderr
        text: Whether to return text instead of bytes
        check: Whether to raise exception on non-zero exit
    
    Returns:
        CompletedProcess instance
    
    Raises:
        SafeSubprocessError: If command execution fails
    """
    # Validate command is a list/tuple (no shell=True)
    if not isinstance(command, (list, tuple)):
        raise SafeSubprocessError(
            f"Command must be a sequence, not a string. Got: {type(command)}"
        )
    
    if len(command) == 0:
        raise SafeSubprocessError("Command cannot be empty")
    
    # Validate each argument
    for i, arg in enumerate(command):
        if not isinstance(arg, str):
            raise SafeSubprocessError(f"Argument {i} must be a string: {arg}")
        if len(arg) == 0:
            raise SafeSubprocessError(f"Argument {i} cannot be empty")
    
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=capture_output,
            text=text,
            check=check,
            shell=False,  # Always False - explicit
        )
        return result
    except subprocess.CalledProcessError as e:
        raise SafeSubprocessError(
            f"Command failed with exit code {e.returncode}: {' '.join(command)}"
        ) from e
    except FileNotFoundError as e:
        raise SafeSubprocessError(
            f"Command not found: {command[0]}"
        ) from e
    except PermissionError as e:
        raise SafeSubprocessError(
            f"Permission denied executing: {command[0]}"
        ) from e
    except Exception as e:
        raise SafeSubprocessError(
            f"Unexpected error running command: {e}"
        ) from e


def run_safe_with_timeout(
    command: Sequence[str],
    timeout: float,
    cwd: Optional[Path] = None,
    env: Optional[dict] = None,
    capture_output: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess:
    """Execute a subprocess with a timeout.
    
    Args:
        command: Command and arguments as a list
        timeout: Maximum execution time in seconds
        cwd: Working directory
        env: Environment variables
        capture_output: Whether to capture stdout/stderr
        text: Whether to return text
    
    Returns:
        CompletedProcess instance
    
    Raises:
        SafeSubprocessError: If command times out or fails
    """
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=capture_output,
            text=text,
            timeout=timeout,
            shell=False,  # Always False
        )
        return result
    except subprocess.TimeoutExpired as e:
        raise SafeSubprocessError(
            f"Command timed out after {timeout}s: {' '.join(command)}"
        ) from e
    except Exception as e:
        raise SafeSubprocessError(
            f"Error running command with timeout: {e}"
        ) from e


def validate_command_args(args: Sequence[str]) -> list[str]:
    """Validate command arguments for dangerous patterns.
    
    Returns a list of warning messages for suspicious patterns.
    """
    warnings = []
    
    dangerous_patterns = [
        (";", "semicolon (command chaining)"),
        ("|", "pipe (command chaining)"),
        ("&", "ampersand (background process)"),
        ("$", "dollar sign (variable expansion)"),
        ("`", "backtick (command substitution)"),
        ("(", "parenthesis (subshell)"),
        (">", "redirection"),
        ("<", "redirection"),
    ]
    
    for arg in args:
        for pattern, description in dangerous_patterns:
            if pattern in arg:
                warnings.append(
                    f"Argument contains {description}: {arg[:50]}"
                )
    
    return warnings


def safe_which(executable: str, path: Optional[str] = None) -> Optional[Path]:
    """Safely locate an executable in PATH.
    
    Args:
        executable: Name of executable to find
        path: Optional PATH string (defaults to system PATH)
    
    Returns:
        Path to executable if found, None otherwise
    """
    try:
        result = subprocess.run(
            ["which", executable],
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,
        )
        if result.returncode == 0:
            exe_path = Path(result.stdout.strip())
            if exe_path.exists() and exe_path.is_file():
                return exe_path
    except Exception:
        pass
    
    # Fallback to manual PATH search
    search_path = path or "/usr/local/bin:/usr/bin:/bin"
    for directory in search_path.split(":"):
        exe_path = Path(directory) / executable
        if exe_path.exists() and exe_path.is_file():
            return exe_path
    
    return None


def safe_popen(
    command: Sequence[str],
    cwd: Optional[Path] = None,
    env: Optional[dict] = None,
    stdout: Optional[int] = None,
    stderr: Optional[int] = None,
) -> subprocess.Popen:
    """Safely start a subprocess for streaming output.
    
    Args:
        command: Command and arguments as a list
        cwd: Working directory
        env: Environment variables
        stdout: Optional stdout handle
        stderr: Optional stderr handle
    
    Returns:
        Popen instance
    """
    if not isinstance(command, (list, tuple)):
        raise SafeSubprocessError("Command must be a sequence")
    
    return subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=stdout,
        stderr=stderr,
        shell=False,  # Always False
    )

"""Timeout management utilities."""

import signal
import functools
from typing import TypeVar, Callable, Any, Optional
from contextlib import contextmanager


T = TypeVar('T')


class TimeoutError(Exception):
    """Exception raised when a timeout occurs."""
    pass


class TimeoutManager:
    """Manages timeouts for various operations."""
    
    def __init__(
        self,
        default_timeout: float = 30.0,
        connection_timeout: float = 5.0,
        read_timeout: float = 10.0,
    ):
        self.default_timeout = default_timeout
        self.connection_timeout = connection_timeout
        self.read_timeout = read_timeout
    
    def get_timeout(self, operation: str) -> float:
        """Get appropriate timeout for an operation type."""
        timeouts = {
            "network": max(self.connection_timeout + self.read_timeout, 15.0),
            "connection": self.connection_timeout,
            "read": self.read_timeout,
            "filesystem": 10.0,
            "command": 60.0,
            "default": self.default_timeout,
        }
        return timeouts.get(operation, self.default_timeout)


# Platform-specific timeout implementation
def _set_alarm_timeout(seconds: float) -> None:
    """Set an alarm signal timeout (Unix only)."""
    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(int(seconds))


def _clear_alarm_timeout() -> None:
    """Clear the alarm signal timeout (Unix only)."""
    signal.alarm(0)


def _timeout_handler(signum: int, frame: Any) -> None:
    """Signal handler for timeout."""
    raise TimeoutError("Operation timed out")


@contextmanager
def timeout_context(seconds: float):
    """Context manager for timeouts.
    
    Usage:
        with timeout_context(5.0):
            # Code that must complete within 5 seconds
            pass
    
    Note: This only works on Unix systems with SIGALRM support.
    On Windows or other platforms, it will run without timeout enforcement.
    """
    try:
        # Try to use signal-based timeout
        _set_alarm_timeout(seconds)
        yield
    except TimeoutError:
        raise
    except Exception:
        raise
    finally:
        try:
            _clear_alarm_timeout()
        except Exception:
            pass


def timeout_decorator(
    seconds: float,
    default_return: Optional[Any] = None,
    raise_on_timeout: bool = True,
) -> Callable[[Callable[..., T]], Callable[..., Optional[T]]]:
    """Decorator to add timeout to a function.
    
    Usage:
        @timeout_decorator(5.0)
        def slow_function():
            # Must complete within 5 seconds
            pass
    
    Note: This only works on Unix systems with SIGALRM support.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., Optional[T]]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Optional[T]:
            def handler(signum: int, frame: Any) -> None:
                raise TimeoutError(f"Function {func.__name__} timed out after {seconds}s")
            
            try:
                # Set up signal handler
                old_handler = signal.signal(signal.SIGALRM, handler)
                signal.alarm(int(seconds))
                
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old_handler)
                    
            except TimeoutError:
                if raise_on_timeout:
                    raise
                return default_return
            except Exception:
                # Clean up signal handler on other exceptions
                try:
                    signal.alarm(0)
                except Exception:
                    pass
                raise
        
        return wrapper
    return decorator


def with_timeout(
    func: Callable[..., T],
    timeout: float,
    *args: Any,
    **kwargs: Any
) -> T:
    """Run a function with a timeout.
    
    Args:
        func: Function to run
        timeout: Maximum execution time in seconds
        *args: Positional arguments for func
        **kwargs: Keyword arguments for func
    
    Returns:
        Result of func(*args, **kwargs)
    
    Raises:
        TimeoutError: If function execution exceeds timeout
    """
    import threading
    import queue
    
    result_queue: queue.Queue = queue.Queue()
    exception_queue: queue.Queue = queue.Queue()
    
    def target() -> None:
        try:
            result = func(*args, **kwargs)
            result_queue.put(result)
        except Exception as e:
            exception_queue.put(e)
    
    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout)
    
    if thread.is_alive():
        raise TimeoutError(f"Function timed out after {timeout}s")
    
    if not exception_queue.empty():
        raise exception_queue.get()
    
    if not result_queue.empty():
        return result_queue.get()
    
    raise TimeoutError(f"Function timed out after {timeout}s")


class RateLimiter:
    """Simple rate limiter for controlling request rates."""
    
    def __init__(self, requests_per_second: float = 10.0):
        self.min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self.last_request_time: Optional[float] = None
    
    def wait(self) -> None:
        """Wait if necessary to maintain rate limit."""
        import time
        
        if self.min_interval <= 0:
            return
        
        current_time = time.time()
        
        if self.last_request_time is not None:
            elapsed = current_time - self.last_request_time
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)
                current_time = time.time()
        
        self.last_request_time = current_time
    
    @contextmanager
    def acquire(self):
        """Context manager to acquire rate limit permission."""
        self.wait()
        try:
            yield
        finally:
            pass  # Update timing on next acquire

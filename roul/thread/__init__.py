import math
import threading
import time
from datetime import datetime
from numbers import Real
from typing import Callable, TypedDict

import roul


class _SchedulerInfo(TypedDict):
    thread: threading.Thread
    event: threading.Event


_active_schedulers: dict[str, _SchedulerInfo] = {}
_lock = threading.Lock()


def _is_valid_interval(interval: object) -> bool:
    """Return whether an interval is safe for threading.Event.wait()."""
    return (
        not isinstance(interval, bool)
        and isinstance(interval, Real)
        and 0 < interval <= threading.TIMEOUT_MAX
        and math.isfinite(float(interval))
    )


def _periodic_worker(task_id: str, interval: float, func: Callable[..., object], stop_event: threading.Event, args: tuple[object, ...], kwargs: dict[str, object]) -> None:
    """Run a function periodically and remove its scheduler on exit."""
    try:
        start_time = time.monotonic()

        while not stop_event.is_set():
            try:
                func(*args, **kwargs)
            except Exception as error:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] An error occurred in the worker: {error}")
                if roul.DEBUG:
                    raise

            if stop_event.is_set():
                break

            elapsed = time.monotonic() - start_time
            wait_time = interval - (elapsed % interval)
            stop_event.wait(wait_time)
    finally:
        current_thread = threading.current_thread()
        with _lock:
            scheduler_info = _active_schedulers.get(task_id)
            if scheduler_info is not None and scheduler_info["thread"] is current_thread:
                del _active_schedulers[task_id]


def start(task_id: str, interval: float, func: Callable[..., object], *args: object, **kwargs: object) -> bool:
    """Start a periodic scheduler task.

    Args:
        task_id: Unique identifier for the task.
        interval: Number of seconds between scheduled runs.
        func: Function to run.
        *args: Positional arguments passed to the function.
        **kwargs: Keyword arguments passed to the function.

    Returns:
        True when the task starts, otherwise False.
    """
    if not isinstance(task_id, str) or not task_id:
        print("Error: task_id must be a non-empty string.")
        return False

    if not _is_valid_interval(interval):
        print("Error: interval must be a positive finite number no greater than threading.TIMEOUT_MAX.")
        return False

    if not callable(func):
        print("Error: func must be callable.")
        return False

    normalized_interval = float(interval)
    with _lock:
        if task_id in _active_schedulers:
            print(f"Error: Task '{task_id}' is already running.")
            return False

        stop_event = threading.Event()
        thread = threading.Thread(
            target=_periodic_worker,
            args=(task_id, normalized_interval, func, stop_event, args, kwargs),
            daemon=True,
        )
        scheduler_info: _SchedulerInfo = {"thread": thread, "event": stop_event}
        _active_schedulers[task_id] = scheduler_info

        try:
            thread.start()
        except Exception:
            if _active_schedulers.get(task_id) is scheduler_info:
                del _active_schedulers[task_id]
            raise

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Task '{task_id}' started (interval: {interval}s)")
    return True


def stop(task_id: str) -> bool:
    """Stop a periodic scheduler task.

    Args:
        task_id: Identifier of the task to stop.

    Returns:
        True when the task exists and receives a stop request, otherwise False.
    """
    with _lock:
        scheduler_info = _active_schedulers.get(task_id)
        if scheduler_info is None:
            print(f"Error: Task '{task_id}' not found.")
            return False

        scheduler_info["event"].set()

    if scheduler_info["thread"] is not threading.current_thread():
        scheduler_info["thread"].join()

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Task '{task_id}' has been stopped.")
    return True


def stop_all() -> None:
    """Stop all periodic scheduler tasks.

    Returns:
        None.
    """
    task_ids = get_running_tasks()
    if not task_ids:
        return

    print(f"Stopping all scheduler tasks: {task_ids}")
    for task_id in task_ids:
        stop(task_id)


def get_running_tasks() -> list[str]:
    """Return the identifiers of registered scheduler tasks.

    Returns:
        Registered task identifiers.
    """
    with _lock:
        return list(_active_schedulers.keys())

import time
import threading
from datetime import datetime
from typing import Callable

_active_schedulers = {}
_lock = threading.Lock()

def _periodic_worker(interval, func, stop_event, args, kwargs):
    start_time = time.time()
    
    while not stop_event.is_set():
        try:
            func(*args, **kwargs)
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] An error occurred in the worker: {e}")

        if stop_event.is_set():
            break

        elapsed = time.time() - start_time
        sleep_time = interval - (elapsed % interval)
        
        stop_event.wait(sleep_time)

def start(task_id: str, interval: float, func: Callable, *args, **kwargs):
    if not isinstance(task_id, str) or not task_id:
        print("Error: task_id must be a non-empty string.")
        return False
        
    with _lock:
        if task_id in _active_schedulers:
            print(f"Error: Task '{task_id}' is already running.")
            return False

        stop_event = threading.Event()
        thread = threading.Thread(
            target=_periodic_worker,
            args=(interval, func, stop_event, args, kwargs),
            daemon=True
        )
        _active_schedulers[task_id] = {'thread': thread, 'event': stop_event}
        thread.start()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Task '{task_id}' started (interval: {interval}s)")
        return True

def stop(task_id: str):
    with _lock:
        if task_id not in _active_schedulers:
            print(f"Error: Task '{task_id}' not found.")
            return False
        
        scheduler_info = _active_schedulers.pop(task_id)

    scheduler_info['event'].set()
    scheduler_info['thread'].join()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Task '{task_id}' has been stopped.")
    return True

def stop_all():
    task_ids = get_running_tasks()
    if not task_ids:
        return
        
    print(f"Stopping all scheduler tasks: {task_ids}")
    for task_id in task_ids:
        stop(task_id)

def get_running_tasks():
    with _lock:
        return list(_active_schedulers.keys())
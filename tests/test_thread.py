import io
import threading
import unittest
from contextlib import redirect_stdout
from unittest import mock

import roul
import roul.thread as scheduler


class _FakeStopEvent:
    def __init__(self) -> None:
        self.stopped = False
        self.wait_timeout: float | None = None

    def is_set(self) -> bool:
        return self.stopped

    def wait(self, timeout: float) -> bool:
        self.wait_timeout = timeout
        self.stopped = True
        return True


class SchedulerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.original_debug = roul.DEBUG

    def tearDown(self) -> None:
        roul.DEBUG = self.original_debug
        with scheduler._lock:
            scheduler_infos = list(scheduler._active_schedulers.values())
            for scheduler_info in scheduler_infos:
                scheduler_info["event"].set()

        for scheduler_info in scheduler_infos:
            thread = scheduler_info["thread"]
            if thread is not threading.current_thread():
                thread.join(timeout=1)

        with scheduler._lock:
            scheduler._active_schedulers.clear()

    def test_start_rejects_invalid_interval_and_callback(self) -> None:
        invalid_intervals = (
            True,
            False,
            0,
            -1,
            float("nan"),
            float("inf"),
            threading.TIMEOUT_MAX + 1,
            10**1000,
            "1",
            None,
        )

        with redirect_stdout(io.StringIO()):
            for interval in invalid_intervals:
                with self.subTest(interval=interval):
                    self.assertFalse(scheduler.start("invalid", interval, lambda: None))

            self.assertFalse(scheduler.start("invalid", 1, None))

        self.assertEqual(scheduler.get_running_tasks(), [])

    def test_worker_uses_monotonic_clock(self) -> None:
        stop_event = _FakeStopEvent()
        calls: list[str] = []

        with mock.patch.object(scheduler.time, "monotonic", side_effect=(10.0, 10.25)):
            with mock.patch.object(scheduler.time, "time", side_effect=AssertionError("wall clock used")):
                scheduler._periodic_worker("clock", 1.0, lambda: calls.append("called"), stop_event, (), {})

        self.assertEqual(calls, ["called"])
        self.assertEqual(stop_event.wait_timeout, 0.75)

    def test_debug_exception_cleans_up_and_allows_restart(self) -> None:
        exception_caught = threading.Event()
        exception_types: list[type[BaseException]] = []

        def capture_exception(args: threading.ExceptHookArgs) -> None:
            exception_types.append(args.exc_type)
            exception_caught.set()

        def fail() -> None:
            raise RuntimeError("worker failed")

        roul.DEBUG = True
        with redirect_stdout(io.StringIO()):
            with mock.patch.object(threading, "excepthook", capture_exception):
                self.assertTrue(scheduler.start("restartable", 60, fail))
                self.assertTrue(exception_caught.wait(timeout=1))

            restarted = threading.Event()
            self.assertTrue(scheduler.start("restartable", 60, restarted.set))
            self.assertTrue(restarted.wait(timeout=1))
            self.assertTrue(scheduler.stop("restartable"))

        self.assertEqual(exception_types, [RuntimeError])
        self.assertNotIn("restartable", scheduler.get_running_tasks())

    def test_self_stop_does_not_join_current_thread(self) -> None:
        stopped_inside_callback = threading.Event()
        release_callback = threading.Event()
        stop_results: list[bool] = []

        def stop_self() -> None:
            stop_results.append(scheduler.stop("self-stop"))
            stopped_inside_callback.set()
            release_callback.wait(timeout=1)

        with redirect_stdout(io.StringIO()):
            self.assertTrue(scheduler.start("self-stop", 60, stop_self))
            self.assertTrue(stopped_inside_callback.wait(timeout=1))
            with scheduler._lock:
                worker = scheduler._active_schedulers["self-stop"]["thread"]
            self.assertFalse(scheduler.start("self-stop", 60, lambda: None))
            release_callback.set()
            worker.join(timeout=1)

        self.assertFalse(worker.is_alive())
        self.assertEqual(stop_results, [True])
        self.assertNotIn("self-stop", scheduler.get_running_tasks())

    def test_stop_keeps_task_registered_until_worker_finishes(self) -> None:
        callback_started = threading.Event()
        release_callback = threading.Event()
        stop_results: list[bool] = []

        def blocking_callback() -> None:
            callback_started.set()
            release_callback.wait(timeout=1)

        with redirect_stdout(io.StringIO()):
            self.assertTrue(scheduler.start("overlap", 60, blocking_callback))
            self.assertTrue(callback_started.wait(timeout=1))
            with scheduler._lock:
                scheduler_info = scheduler._active_schedulers["overlap"]

            stopper = threading.Thread(target=lambda: stop_results.append(scheduler.stop("overlap")))
            stopper.start()
            self.assertTrue(scheduler_info["event"].wait(timeout=1))
            self.assertIn("overlap", scheduler.get_running_tasks())
            self.assertFalse(scheduler.start("overlap", 60, lambda: None))

            release_callback.set()
            stopper.join(timeout=1)

        self.assertFalse(stopper.is_alive())
        self.assertEqual(stop_results, [True])
        self.assertNotIn("overlap", scheduler.get_running_tasks())

    def test_start_failure_removes_registry_entry(self) -> None:
        with redirect_stdout(io.StringIO()):
            with mock.patch.object(threading.Thread, "start", side_effect=RuntimeError("cannot start")):
                with self.assertRaisesRegex(RuntimeError, "cannot start"):
                    scheduler.start("failed-start", 1, lambda: None)

        self.assertNotIn("failed-start", scheduler.get_running_tasks())


if __name__ == "__main__":
    unittest.main()

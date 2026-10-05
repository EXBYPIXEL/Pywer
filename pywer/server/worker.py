"""Background thread pool worker pipeline for offloading CPU-heavy tasks."""

import concurrent.futures
import os
import queue

from ..log import dbg


class WorkerFailure:
    """The result published in place of a value when a submitted task raises.

    A task that raises never produces a value, but consumers routinely register
    state before submitting (a chunk slot, a request id, ...). Dropping the failure
    on the floor leaves that registration claimed forever, so the job's arguments
    travel with the error: they are what the consumer needs to give the claim back.
    Delivered inside the usual ``(task_type, session_id, res)`` envelope, because a
    consumer's result loop must not have to know which shape it is holding.
    """

    __slots__ = ("args", "error")

    def __init__(self, args, error):
        self.args = tuple(args)
        self.error = error

    def __repr__(self):
        return "WorkerFailure(%r, %r)" % (self.args, self.error)


class WorkerPool:
    def __init__(self, max_workers=None):
        workers = max_workers or min(4, max(2, os.cpu_count() or 2))
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="pywer-worker",
        )
        self.results = queue.Queue()
        self.running = True

    def submit(self, task_type, session_id, func, *args):
        """Submit a background job. Upon completion, post result to the thread-safe queue.

        A task that raises posts a WorkerFailure instead of a result, so no job
        disappears without a consumer being able to see it.
        """
        if not self.running:
            return

        def _runner():
            try:
                res = func(*args)
            except Exception as e:
                dbg(
                    "Worker",
                    "error executing task %s for session %s: %r"
                    % (task_type, session_id, e),
                )
                if self.running:
                    self.results.put((task_type, session_id, WorkerFailure(args, e)))
                return
            if self.running:
                self.results.put((task_type, session_id, res))

        self.executor.submit(_runner)

    def drain_results(self):
        """Non-blocking drain of all completed results from the worker queue."""
        items = []
        while True:
            try:
                items.append(self.results.get_nowait())
            except queue.Empty:
                break
        return items

    def shutdown(self):
        """Shut down the executor cleanly."""
        self.running = False
        self.executor.shutdown(wait=False, cancel_futures=True)

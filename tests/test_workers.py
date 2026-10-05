"""Unit tests for the background worker pool and how its results are dispatched.

A submitted job registers state before it runs (the caller claims a chunk slot,
for instance), so the two halves of the contract are tested together: a task that
raises must still produce something, and the dispatcher must give the registration
back instead of stranding it or taking the tick loop down with it.
"""

import contextlib
import io
import time
import unittest
from types import SimpleNamespace

from pywer.player.session import Session
from pywer.server.server import Server
from pywer.server.worker import WorkerFailure, WorkerPool


def sample_task(x, y):
    return x + y


def exploding_task(cx, cz):
    raise RuntimeError("terrain exploded")


class FakeChunkCache:
    def __init__(self):
        self.stored = {}

    def put(self, cx, cz, payload):
        self.stored[(cx, cz)] = payload

    def get(self, cx, cz):
        return self.stored.get((cx, cz))


class ExplodingChunkCache:
    def put(self, cx, cz, payload):
        raise RuntimeError("disk full")


class FakeSession:
    def __init__(self, rid):
        self.rid = rid
        self.ready = []
        self.failed = []

    def on_chunk_ready(self, cx, cz, payload):
        self.ready.append((cx, cz, payload))

    def on_chunk_failed(self, cx, cz, error):
        self.failed.append((cx, cz, error))


class FakePool:
    def __init__(self, results):
        self.results = list(results)

    def drain_results(self):
        drained, self.results = self.results, []
        return drained


def bare_dispatch_server(cache=None):
    """A Server carrying only what drain_workers() reaches for."""
    srv = Server.__new__(Server)
    srv.sessions = {}
    srv.chunk_cache = FakeChunkCache() if cache is None else cache
    srv.worker_pool = None
    return srv


def failed_coords(session):
    """The (cx, cz) pairs a session was told it lost, without the error objects."""
    return [(cx, cz) for cx, cz, _error in session.failed]


class RecordingPool:
    """A worker pool that records submissions instead of running them."""

    def __init__(self):
        self.submitted = []

    def submit(self, task_type, session_id, job, *args):
        self.submitted.append((task_type, session_id, args))


def bare_session(pool=None):
    """A Session carrying only its chunk-tracking state, built without a server."""
    session = Session.__new__(Session)
    session.rid = 7
    session.center = (0, 0)
    session.radius = 2
    session.sent_chunks = set()
    session.chunks_in_flight = set()
    session.chunk_attempts = {}
    session.chunk_retries = []
    session.chunk_queue = []
    session.chunk_send_queue = []
    session.srv = SimpleNamespace(chunk_cache=FakeChunkCache(), worker_pool=pool)
    return session


def submitted_coords(pool):
    """The coords in a RecordingPool's submissions, in submission order."""
    return [(args[0], args[1]) for _task_type, _sid, args in pool.submitted]


class TestWorkerPool(unittest.TestCase):
    def _await_drain(self, pool, limit=60):
        for _ in range(limit):
            time.sleep(0.02)
            results = pool.drain_results()
            if results:
                return results
        self.fail("no worker result was published")

    def test_submit_and_drain_results(self):
        pool = WorkerPool(max_workers=2)
        try:
            pool.submit("ADD", 101, sample_task, 15, 25)
            # Wait up to 1 second for background execution
            results = []
            for _ in range(20):
                time.sleep(0.05)
                results = pool.drain_results()
                if results:
                    break
            self.assertEqual(len(results), 1)
            task_type, session_id, res = results[0]
            self.assertEqual(task_type, "ADD")
            self.assertEqual(session_id, 101)
            self.assertEqual(res, 40)
        finally:
            pool.shutdown()

    def test_a_raising_task_publishes_its_arguments_and_its_error(self):
        # Without this record the job simply vanishes and the state its caller
        # claimed before submitting is never given back.
        pool = WorkerPool(max_workers=2)
        try:
            pool.submit("CHUNK", 7, exploding_task, 3, 4)
            task_type, session_id, res = self._await_drain(pool)[0]
            self.assertEqual((task_type, session_id), ("CHUNK", 7))
            self.assertIsInstance(res, WorkerFailure)
            self.assertEqual(res.args, (3, 4))
            self.assertIsInstance(res.error, RuntimeError)
        finally:
            pool.shutdown()


class TestWorkerDispatch(unittest.TestCase):
    def test_chunk_result_is_cached_and_dispatched_to_its_session(self):
        srv = bare_dispatch_server()
        session = FakeSession(7)
        srv.sessions = {"a": session}
        srv.worker_pool = FakePool([("CHUNK", 7, (1, 2, b"payload"))])

        srv.drain_workers()

        self.assertEqual(srv.chunk_cache.stored[(1, 2)], b"payload")
        self.assertEqual(session.ready, [(1, 2, b"payload")])

    def test_failed_chunk_hands_its_slot_back_to_the_session(self):
        srv = bare_dispatch_server()
        session = FakeSession(7)
        srv.sessions = {"a": session}
        srv.worker_pool = FakePool(
            [("CHUNK", 7, WorkerFailure((3, 4), RuntimeError("boom")))]
        )

        srv.drain_workers()

        self.assertEqual(failed_coords(session), [(3, 4)])
        self.assertEqual(session.ready, [])

    def test_failure_for_a_session_that_has_gone_away_is_logged_not_raised(self):
        # drain_workers() runs on every tick with no guard around it, so raising
        # here would stop the server. The absence of an exception is the assertion.
        srv = bare_dispatch_server()
        srv.sessions = {}
        srv.worker_pool = FakePool(
            [("CHUNK", 7, WorkerFailure((3, 4), RuntimeError("boom")))]
        )

        srv.drain_workers()

    def test_one_malformed_result_does_not_drop_the_rest_of_the_batch(self):
        # drain_results() has already emptied the queue into this loop, so an
        # uncaught error on one entry would silently strand every entry behind it.
        srv = bare_dispatch_server()
        session = FakeSession(7)
        srv.sessions = {"a": session}
        srv.worker_pool = FakePool(
            [
                ("CHUNK", 7, "not-a-payload-tuple"),
                ("CHUNK", 7, (1, 2, b"still delivered")),
            ]
        )

        srv.drain_workers()

        self.assertEqual(session.ready, [(1, 2, b"still delivered")])

    def test_a_failing_cache_does_not_cost_the_session_its_chunk(self):
        srv = bare_dispatch_server(cache=ExplodingChunkCache())
        session = FakeSession(7)
        srv.sessions = {"a": session}
        srv.worker_pool = FakePool([("CHUNK", 7, (1, 2, b"payload"))])

        srv.drain_workers()

        self.assertEqual(session.ready, [(1, 2, b"payload")])

    def test_a_raising_chunk_job_releases_the_slot_end_to_end(self):
        # The whole wedge in one pass: the job raises in the worker thread, and the
        # session still ends up with the slot it claimed before submitting it.
        srv = bare_dispatch_server()
        session = FakeSession(7)
        srv.sessions = {"a": session}
        pool = WorkerPool(max_workers=2)
        srv.worker_pool = pool
        try:
            pool.submit("CHUNK", 7, exploding_task, 3, 4)
            for _ in range(60):
                time.sleep(0.02)
                srv.drain_workers()
                if session.failed:
                    break
            self.assertEqual(failed_coords(session), [(3, 4)])
        finally:
            pool.shutdown()


class TestChunkSlotRelease(unittest.TestCase):
    def test_on_chunk_failed_releases_only_the_slot_it_names(self):
        session = bare_session()
        session.chunks_in_flight = {(3, 4), (5, 6)}

        session.on_chunk_failed(3, 4, RuntimeError("boom"))

        self.assertEqual(session.chunks_in_flight, {(5, 6)})

    def test_a_failed_chunk_is_neither_sent_nor_claimed(self):
        # queue_chunks() only re-queues a coord that is in neither set, so both
        # have to be clear for the chunk to ever be requested again.
        session = bare_session()
        session.chunks_in_flight = {(3, 4)}

        session.on_chunk_failed(3, 4, RuntimeError("boom"))

        self.assertNotIn((3, 4), session.chunks_in_flight)
        self.assertNotIn((3, 4), session.sent_chunks)


class TestChunkRetry(unittest.TestCase):
    """A failure has to recover on its own, and has to stop trying when it cannot.

    queue_chunks() only runs on a spawn or a chunk-boundary crossing, so leaving
    the coord alone means a hole under a player who never takes a step - while
    re-queueing it outright means resubmitting a job that is failing for a reason
    every time they do cross one.
    """

    def _fail(self, session, coord=(1, 1), error=RuntimeError("boom")):
        session.chunks_in_flight.add(coord)
        session.on_chunk_failed(coord[0], coord[1], error)

    def test_a_failed_chunk_is_retried_without_the_player_moving(self):
        pool = RecordingPool()
        session = bare_session(pool)

        self._fail(session, error=RuntimeError("sqlite locked"))

        self.assertNotIn((1, 1), session.chunks_in_flight)
        self.assertEqual(len(session.chunk_retries), 1)
        ready_at, cx, cz = session.chunk_retries[0]
        self.assertEqual((cx, cz), (1, 1))
        self.assertGreater(ready_at, time.time(), "the retry must be scheduled, not immediate")

        session._flush_chunk_retries()  # still inside the backoff window
        self.assertEqual(pool.submitted, [])

        session.chunk_retries[0] = (time.time() - 0.01, cx, cz)
        session._flush_chunk_retries()

        self.assertEqual(submitted_coords(pool), [(1, 1)])
        self.assertIn((1, 1), session.chunks_in_flight)
        self.assertEqual(session.chunk_retries, [])

    def test_a_chunk_that_keeps_failing_is_given_up_on(self):
        pool = RecordingPool()
        session = bare_session(pool)
        for _ in range(Session.CHUNK_MAX_ATTEMPTS + 5):
            self._fail(session)
            # Each retry gets its chance to run and fail again before the next
            # one arrives, which is how this happens against a real worker.
            while session.chunk_retries:
                session.chunk_retries[0] = (time.time() - 1, 1, 1)
                session._flush_chunk_retries()

        self.assertEqual(len(pool.submitted), Session.CHUNK_MAX_ATTEMPTS - 1)
        self.assertEqual(session.chunk_attempts[(1, 1)], Session.CHUNK_MAX_ATTEMPTS + 5)
        self.assertEqual(session.chunk_retries, [])

    def test_queue_chunks_never_asks_again_for_a_coord_that_gave_up(self):
        pool = RecordingPool()
        session = bare_session(pool)
        for _ in range(Session.CHUNK_MAX_ATTEMPTS):
            self._fail(session)
        session.chunk_retries = []  # this is about queue_chunks, not the timer

        session.queue_chunks()

        coords = submitted_coords(pool)
        self.assertNotIn((1, 1), coords)
        self.assertEqual(len(coords), 24, "the rest of the 5x5 window is still asked for")

    def test_attempt_counts_are_forgotten_once_the_coord_leaves_the_window(self):
        # The table is bounded by where the player is, not by everywhere they have
        # ever been - and coming back later re-tries a coord whose fault has had
        # time to clear instead of staying poisoned forever.
        pool = RecordingPool()
        session = bare_session(pool)
        for _ in range(Session.CHUNK_MAX_ATTEMPTS):
            self._fail(session)
        session.chunk_retries = []  # this is about queue_chunks, not the timer
        session.center = (50, 50)

        session.queue_chunks()

        self.assertNotIn((1, 1), session.chunk_attempts)


class TestUnclaimedWorkerResults(unittest.TestCase):
    def test_a_success_nothing_consumes_is_reported(self):
        # Failures are reported for every task type; a success that is silently
        # dropped is the same blind spot from the other side.
        srv = bare_dispatch_server()
        srv.worker_pool = FakePool([("PING", 7, b"pong")])

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            srv.drain_workers()

        self.assertIn("no handler for successful task PING", out.getvalue())


if __name__ == "__main__":
    unittest.main()

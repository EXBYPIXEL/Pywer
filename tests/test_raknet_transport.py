"""Regression tests for the RakNet reliability layer.

These cover the transport invariants the rest of the server depends on: the ACK/NACK
direction on both the receive and transmit side, retransmission reusing its original
sequence number, 24-bit counter wrap, and the resource ceilings that keep a single
peer from growing server state without bound.

ACK and NACK are named here rather than written as hex literals because both sides of
the transport have to agree with every other RakNet implementation, not just with each
other: a suite where Pywer sends and reads the same swapped bytes passes while every
spec peer is interpreted backwards.
"""

import struct
import time
import unittest

from pywer.player.session import Session

# RakNet ORs the datagram bit (0x80) into both control packets and tells them apart
# with two extra flags (see go-raknet packet.go: bitFlagACK 0x40, bitFlagNACK 0x20).
ACK = 0xC0
NACK = 0xA0


class FakeServer:
    next_rid = 1

    def __init__(self):
        self.sent = []

    def send(self, data, addr):
        self.sent.append(data)
        return True


def make_session():
    srv = FakeServer()
    s = Session(srv, ("127.0.0.1", 19132), 1492, 42)
    return s, srv


def data_datagram(seq, frames):
    return b"\x84" + (seq & 0xFFFFFF).to_bytes(3, "little") + b"".join(frames)


def reliable_frame(payload, ridx):
    """RELIAble (unsequenced) frame: flags, length in bits, reliable index."""
    return (
        bytes([2 << 5])
        + struct.pack(">H", len(payload) * 8)
        + (ridx & 0xFFFFFF).to_bytes(3, "little")
        + payload
    )


def ordered_frame(payload, ridx, oidx, ch=0):
    """RELIABLE_ORDERED frame: flags, length, reliable index, order index, channel."""
    return (
        bytes([3 << 5])
        + struct.pack(">H", len(payload) * 8)
        + (ridx & 0xFFFFFF).to_bytes(3, "little")
        + (oidx & 0xFFFFFF).to_bytes(3, "little")
        + bytes([ch])
        + payload
    )


def split_frame(payload, ridx, oidx, cnt, sid, idx, ch=0):
    return (
        bytes([(3 << 5) | 0x10])
        + struct.pack(">H", len(payload) * 8)
        + (ridx & 0xFFFFFF).to_bytes(3, "little")
        + (oidx & 0xFFFFFF).to_bytes(3, "little")
        + bytes([ch])
        + struct.pack(">IHI", cnt, sid, idx)
        + payload
    )


def record_packet(pid, seqs):
    """ACK/NACK packet built independently of the code under test."""
    recs = b"".join(
        b"\x01" + (s & 0xFFFFFF).to_bytes(3, "little") for s in seqs
    )
    return bytes([pid]) + struct.pack(">H", len(seqs)) + recs


def wire_seq(datagram):
    return int.from_bytes(datagram[1:4], "little")


class TestAckNackDirection(unittest.TestCase):
    def test_ack_does_not_retransmit(self):
        s, srv = make_session()
        s._send_datagram([b"frame"])
        s.on_datagram(record_packet(ACK, [0]))
        self.assertEqual(s.pending, {})
        s.tick(time.time())
        self.assertEqual(srv.sent, [data_datagram(0, [b"frame"])])

    def test_nack_retransmits_original_sequence(self):
        s, srv = make_session()
        s._send_datagram([b"first"])
        s._send_datagram([b"second"])
        s.on_datagram(record_packet(NACK, [0]))
        self.assertIn(0, s.pending)
        self.assertIn(1, s.pending)
        self.assertEqual(srv.sent[-1], data_datagram(0, [b"first"]))

    def test_tick_reports_received_as_ack_and_gaps_as_nack(self):
        s, srv = make_session()
        s.on_datagram(data_datagram(0, [reliable_frame(b"a", 0)]))
        s.on_datagram(data_datagram(3, [reliable_frame(b"b", 1)]))
        s.tick(time.time())
        acks = [d for d in srv.sent if d[0] == ACK]
        nacks = [d for d in srv.sent if d[0] == NACK]
        self.assertEqual(len(acks), 1)
        self.assertEqual(len(nacks), 1)
        self.assertEqual(sorted(Session._records(None, acks[0])), [0, 3])
        self.assertEqual(Session._records(None, nacks[0]), [1, 2])

    def test_duplicate_datagram_is_acknowledged_but_processed_once(self):
        s, srv = make_session()
        seen = []
        s.on_rak_payload = seen.append
        pkt = data_datagram(0, [reliable_frame(b"a", 0)])
        s.on_datagram(pkt)
        s.on_datagram(pkt)
        self.assertEqual(seen, [b"a"])
        self.assertIn(0, s.ack_q)

    def test_timer_resend_keeps_pending_entry(self):
        s, srv = make_session()
        s._send_datagram([b"frame"])
        first = time.time() + s.RESEND_AFTER + 0.5
        s.tick(first)
        self.assertIn(0, s.pending)
        self.assertEqual(srv.sent[-1], data_datagram(0, [b"frame"]))
        before = len(srv.sent)
        # The second attempt is backed off by RESEND_BACKOFF, so it waits longer than
        # the first one did instead of going out on the original fixed timer.
        s.tick(first + 0.5)
        self.assertEqual(len(srv.sent), before)
        s.tick(first + s.RESEND_AFTER * s.RESEND_BACKOFF + 0.1)
        self.assertGreater(len(srv.sent), before)

    def test_retransmissions_are_capped_per_tick(self):
        s, srv = make_session()
        stale = time.time() - 100.0
        for i in range(s.RESENDS_PER_TICK * 3):
            s._send_datagram([b"x"])
            s.pending[i] = (stale, [b"x"], 0)
        before = len(srv.sent)
        s.tick(time.time())
        self.assertEqual(len(srv.sent) - before, s.RESENDS_PER_TICK)
        self.assertEqual(len(s.pending), s.RESENDS_PER_TICK * 3)

    def test_retransmission_gives_up_after_max_retries(self):
        s, _ = make_session()
        s._send_datagram([b"x"])
        s.pending[0] = (time.time() - 100.0, [b"x"], s.MAX_RETRIES)
        s.tick(time.time())
        self.assertEqual(s.state, "CLOSED")

    def test_wire_flag_bytes_are_the_raknet_spec_ones(self):
        # go-raknet packet.go sets bitFlagACK = 0b01000000 and bitFlagNACK = 0b00100000
        # and ORs the datagram bit into both, then conn.go switches on those two bits.
        # Pywer reads and writes both, so a swap round-trips perfectly between two Pywer
        # ends and only misbehaves against every other RakNet implementation: a spec
        # ACK would be read as a NACK (retransmit forever, pending never retires) and a
        # spec NACK as an ACK (the lost datagram is never sent again).
        s, srv = make_session()
        s.on_datagram(data_datagram(0, [reliable_frame(b"a", 0)]))
        s.on_datagram(data_datagram(5, [reliable_frame(b"b", 1)]))
        s.tick(time.time())
        flags = [d[0] for d in srv.sent]
        self.assertEqual(flags.count(ACK), 1, "received sequences must be ACKed with 0xC0")
        self.assertEqual(flags.count(NACK), 1, "the 1..4 gap must be NACKed with 0xA0")

        s.pending[0] = (time.time() - 100.0, [b"x"], 0)
        s.on_datagram(record_packet(ACK, [0]))
        self.assertEqual(s.pending, {})
        before = len(srv.sent)
        s.tick(time.time())
        self.assertEqual(len(srv.sent), before, "an ACKed datagram must not be retransmitted")

        s.pending[1] = (time.time() - 100.0, [b"x"], 0)
        before = len(srv.sent)
        s.on_datagram(record_packet(NACK, [1]))
        self.assertEqual(len(srv.sent), before + 1, "a NACK must retransmit immediately")
        self.assertEqual(srv.sent[-1], data_datagram(1, [b"x"]))
        self.assertIn(1, s.pending)


class TestAckPacketEncoding(unittest.TestCase):
    def test_ack_datagrams_stay_within_the_mtu(self):
        # A lossy burst encodes to thousands of bytes; in one datagram it would be
        # dropped by the path MTU and cost the peer every retransmission it saves.
        s, _ = make_session()
        seqs = list(range(0, 2000, 2))
        pks = s._ackpkts(ACK, seqs)
        self.assertGreater(len(pks), 1)
        for pk in pks:
            self.assertLessEqual(len(pk), s.mtu - 28)
        decoded = sorted({v for pk in pks for v in Session._records(None, pk)})
        self.assertEqual(decoded, seqs)

    def test_ack_keeps_contiguous_sequences_in_one_datagram(self):
        s, _ = make_session()
        pks = s._ackpkts(ACK, list(range(500)))
        self.assertEqual(len(pks), 1)
        self.assertEqual(Session._records(None, pks[0]), list(range(500)))

    def test_nack_is_split_too(self):
        s, _ = make_session()
        pks = s._ackpkts(NACK, list(range(0, 4000, 2)))
        for pk in pks:
            self.assertEqual(pk[0], NACK)
            self.assertLessEqual(len(pk), s.mtu - 28)


class TestSequenceWrap(unittest.TestCase):
    def test_incoming_wrap_extends_monotonically(self):
        s, _ = make_session()
        s.max_seq = 0xFFFFFF
        s.on_datagram(data_datagram(0, [reliable_frame(b"a", 0)]))
        self.assertEqual(s.max_seq, 0x1000000)

    def test_outgoing_counters_wrap_without_error(self):
        s, srv = make_session()
        s.send_seq = 0xFFFFFF
        s.rel_idx = 0xFFFFFF
        s.ord_idx = 0xFFFFFF
        s.send_rak(b"\xfe\x00")
        self.assertEqual(wire_seq(srv.sent[-1]), 0xFFFFFF)
        self.assertIn(0xFFFFFF, s.pending)
        s.send_rak(b"\xfe\x00")
        self.assertEqual(wire_seq(srv.sent[-1]), 0)
        self.assertIn(0x1000000, s.pending)

    def test_ack_across_wrap_clears_original_pending(self):
        s, srv = make_session()
        s.send_seq = 0x1000001
        s.pending[0xFFFFFF] = (time.time(), [b"frame"], 0)
        s.on_datagram(record_packet(ACK, [0xFFFFFF]))
        self.assertNotIn(0xFFFFFF, s.pending)

    def test_ackpkt_never_straddles_the_wrap(self):
        s, _ = make_session()
        pks = s._ackpkts(ACK, [0xFFFFFF, 0x1000000, 0x1000001])
        decoded = sorted({v for pk in pks for v in Session._records(None, pk)})
        self.assertEqual(decoded, [0, 1, 0xFFFFFF])

    def test_incoming_range_across_the_wrap_is_not_discarded(self):
        # range(0xFFFFFE, 2) is empty, so a wrapped range used to drop every ack in it
        # and the peer retransmitted the whole window for nothing.
        rec = b"\x00" + (0xFFFFFE).to_bytes(3, "little") + (0x000001).to_bytes(3, "little")
        pkt = bytes([ACK]) + struct.pack(">H", 1) + rec
        self.assertEqual(Session._records(None, pkt), [0xFFFFFE, 0xFFFFFF, 0, 1])

    def test_oversized_range_is_capped(self):
        rec = b"\x00" + (0).to_bytes(3, "little") + (0xFFFFFF).to_bytes(3, "little")
        pkt = bytes([ACK]) + struct.pack(">H", 1) + rec
        self.assertEqual(len(Session._records(None, pkt)), Session.MAX_ACK_RANGE)

    def test_oversized_wrapped_range_is_capped(self):
        rec = b"\x00" + (0xFFFFFF).to_bytes(3, "little") + (0x00FFFE).to_bytes(3, "little")
        pkt = bytes([ACK]) + struct.pack(">H", 1) + rec
        self.assertLessEqual(len(Session._records(None, pkt)), Session.MAX_ACK_RANGE)

    def test_ordering_delivers_across_wrap(self):
        s, _ = make_session()
        seen = []
        s.on_rak_payload = seen.append
        s.order_next[0] = 0xFFFFFF
        s.on_datagram(data_datagram(0, [ordered_frame(b"a", 0, 0xFFFFFF)]))
        s.on_datagram(data_datagram(1, [ordered_frame(b"b", 1, 0x000000)]))
        self.assertEqual(seen, [b"a", b"b"])
        self.assertEqual(s.order_next[0], 0x1000001)

    def test_reliable_index_dedup_wraps(self):
        s, _ = make_session()
        seen = []
        s.on_rak_payload = seen.append
        s.max_rel = 0xFFFFFF
        s.on_datagram(data_datagram(0, [reliable_frame(b"a", 0xFFFFFF)]))
        s.on_datagram(data_datagram(1, [reliable_frame(b"b", 0x000000)]))
        self.assertEqual(seen, [b"a", b"b"])


class TestResourceCeilings(unittest.TestCase):
    def test_unacknowledged_peer_is_dropped(self):
        s, _ = make_session()
        s.pending = {i: (time.time(), [b"x"], 0) for i in range(s.MAX_PENDING)}
        s.last_ack_at = time.time() - (s.ACK_STALL_TIMEOUT + 1)
        s.send_rak(b"\xfe\x00")
        self.assertEqual(s.state, "CLOSED")
        self.assertEqual(s.pending[s.MAX_PENDING - 1][1], [b"x"])

    def test_full_window_while_acks_are_still_arriving_is_not_dropped(self):
        # A spawn burst legitimately fills the window before the first ACK round-trips;
        # kicking here would disconnect perfectly healthy high-latency players.
        s, srv = make_session()
        now = time.time()
        s.pending = {i: (now, [b"x"], 0) for i in range(s.MAX_PENDING)}
        s.send_seq = s.MAX_PENDING
        s.last_ack_at = now
        s.send_rak(b"\xfe\x00")
        self.assertNotEqual(s.state, "CLOSED")
        self.assertEqual(len(s.pending), s.MAX_PENDING + 1)

    def test_ack_arrival_resets_the_stall_clock(self):
        s, _ = make_session()
        s.last_ack_at = time.time() - (s.ACK_STALL_TIMEOUT + 1)
        s.on_datagram(record_packet(ACK, [0xFFFFFF]))
        self.assertLess(time.time() - s.last_ack_at, s.ACK_STALL_TIMEOUT)

    def test_closed_session_stops_sending(self):
        s, srv = make_session()
        s.state = "CLOSED"
        s.send_rak(b"\xfe\x00")
        self.assertEqual(srv.sent, [])
        s.on_datagram(data_datagram(0, [reliable_frame(b"a", 0)]))
        self.assertEqual(srv.sent, [])

    def test_ack_and_nack_queues_are_bounded(self):
        s, _ = make_session()
        s.on_rak_payload = lambda p: None
        for seq in range(s.MAX_QUEUE + 16):
            s.on_datagram(data_datagram(seq, [reliable_frame(b"p", seq)]))
        self.assertLessEqual(len(s.ack_q), s.MAX_QUEUE)
        self.assertLessEqual(len(s.nack_q), s.MAX_QUEUE)

    def test_gap_window_is_bounded(self):
        s, _ = make_session()
        s.on_rak_payload = lambda p: None
        s.on_datagram(data_datagram(s.MAX_GAP * 4, [reliable_frame(b"a", 0)]))
        self.assertLessEqual(len(s.nack_q), s.MAX_QUEUE)

    def test_split_part_count_is_validated(self):
        s, _ = make_session()
        s.on_datagram(
            data_datagram(0, [split_frame(b"p", 0, 0, 0, 1, 0)])
        )
        self.assertEqual(s.state, "CLOSED")

    def test_concurrent_splits_are_bounded(self):
        s, _ = make_session()
        for sid in range(s.MAX_SPLITS):
            s.on_datagram(
                data_datagram(sid, [split_frame(b"p", sid, 0, 2, sid, 0)])
            )
        self.assertNotEqual(s.state, "CLOSED")
        s.on_datagram(
            data_datagram(
                s.MAX_SPLITS, [split_frame(b"p", 4096, 0, 2, 999, 0)]
            )
        )
        self.assertEqual(s.state, "CLOSED")

    def test_stale_splits_are_discarded(self):
        s, _ = make_session()
        s.on_datagram(data_datagram(0, [split_frame(b"p", 0, 0, 2, 7, 0)]))
        self.assertIn(7, s.splits)
        s.tick(time.time() + s.SPLIT_TTL + 1)
        self.assertNotIn(7, s.splits)

    def test_ordering_window_overflow_closes_session(self):
        s, _ = make_session()
        s.on_datagram(
            data_datagram(0, [ordered_frame(b"a", 0, s.MAX_ORDER_WINDOW + 1)])
        )
        self.assertEqual(s.state, "CLOSED")


if __name__ == "__main__":
    unittest.main()

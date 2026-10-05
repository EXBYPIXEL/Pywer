# ---------------------------------------------------------------- server
"""Main Bedrock UDP server, session manager, world event loop, and player dispatch."""

from pathlib import Path
import random
import select
import socket
import struct
import time

from .. import config, __version__
from ..storage import WorldStorage, PlayerStorage, SAVE_INTERVAL
from ..log import log, dbg
from ..util.serializer import ByteReader, ByteWriter
from ..crypto.ec import ec_keygen
from ..net.raknet import RAKNET_MAGIC, enc_addr
from ..protocol.inventory import CONTAINER_ID_FIRST, CONTAINER_ID_LAST
from ..protocol.packet_ids import (
    PID_ADD_ITEM_ACTOR,
    PID_ADD_PLAYER,
    PID_MOVE_ACTOR_ABSOLUTE,
    PID_PLAYER_LIST,
    PID_REMOVE_ACTOR,
    PID_TEXT,
    PID_UPDATE_BLOCK,
)
from ..world.chunk import build_update_block
from ..world.blocks import BLOCK_KEYS, BLOCK_RUNTIME, ITEM_RUNTIME, drops_for, item_key_for_id
from ..data.item_table import ITEM_NAME
from ..world.query import get_block, is_solid
from ..world.state import CHUNK_CACHE, EDITS, mark_dirty, load_edits
from ..world import item_entity as ie
from ..player.inventory import add_item, item_tuple, first_empty_slot
from ..packets.item_actor import build_add_item_actor
from ..packets.entity import build_move_entity
from ..packets.player_list import build_player_list_add, build_player_list_remove
from ..packets.spawn import build_add_player
from ..packets.text import build_text
from ..player.movement import NETWORK_EYE_OFFSET
from ..player.session import Session
from ..event import manager as events, PlayerJoinEvent, PlayerQuitEvent, ServerLoadEvent, ServerStopEvent
from .worker import WorkerFailure, WorkerPool
from ..entity.manager import EntityManager, resolve_actor
from ..world.cache import ChunkCache
from ..scheduler import ServerScheduler
from ..command import CommandManager, CommandSender, PlayerCommandSender, ConsoleCommandSender
from ..plugin import PluginManager

TICK_INTERVAL = 0.05
MAX_CATCHUP_TICKS = 5

# Server-list game mode label. Kept in sync with config.GAMEMODE so the ping response
# and the advertised game mode cannot drift apart.
GAMEMODE_NAMES = {
    0: "Survival",
    1: "Creative",
    2: "Adventure",
    3: "Spectator",
    5: "Survival",
    6: "Creative",
}


def build_motd(guid, port, online=0):
    """Unconnected ping response.

    Every advertised value comes from its own source of truth instead of a literal:
    the game mode from config.GAMEMODE, the player limit from config.MAX_PLAYERS, the
    version from pywer.__version__, and the online count from the caller so the server
    list can never disagree with what the server is actually running or hosting.
    """
    mode = config.GAMEMODE & 0x7
    return "MCPE;pywer-v%s;%d;%s;%d;%d;%d;Minimal;%s;%d;%d;%d;" % (
        __version__,
        config.PROTOCOL,
        config.GAME_VERSION,
        max(0, int(online)),
        max(0, int(config.MAX_PLAYERS)),
        guid,
        GAMEMODE_NAMES.get(mode, "Survival"),
        mode,
        port,
        port + 1,
    )


class Server:
    SEND_TIMEOUT = 2.0

    def __init__(self, port=config.PORT, bind=config.BIND):
        self.guid = random.getrandbits(63)
        self.port = port
        self.bind = bind
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        self.sock.bind((bind, port))
        self.sock.setblocking(False)
        self.sessions = {}
        self.key = ec_keygen()
        self.next_rid = 1
        self.entity_mgr = EntityManager(self)
        self.item_entities = self.entity_mgr.entities
        self._last_tick = 0.0
        self.world_storage = WorldStorage()
        self.player_storage = PlayerStorage()
        self._last_save = time.time()
        self._window_id = CONTAINER_ID_FIRST
        self.chests = {}
        self.worker_pool = WorkerPool()
        self.chunk_cache = ChunkCache()
        self.scheduler = ServerScheduler(self)
        self.event_mgr = events
        self.event_manager = self.event_mgr
        self.command_mgr = CommandManager(self)
        self.command_manager = self.command_mgr
        self.plugins_dir = Path("plugins")
        self.plugin_data_dir = self.plugins_dir / "data"
        self.plugin_mgr = PluginManager(self, self.plugins_dir, self.plugin_data_dir)
        self.plugin_manager = self.plugin_mgr
        self._stopped = False
        self._next_tick = time.perf_counter() + TICK_INTERVAL
        # The world must exist before plugins are enabled: an on_enable implementation is
        # allowed to read the level, and ServerLoadEvent is only meaningful once the level
        # has been loaded.
        self.plugin_mgr.load_all_plugins()
        self.load_world()
        self.plugin_mgr.enable_all()
        self.event_mgr.call(ServerLoadEvent(self))

    def send(self, data, addr):
        """UDP send that survives a full kernel send buffer."""
        deadline = time.time() + self.SEND_TIMEOUT
        while True:
            try:
                self.sock.sendto(data, addr)
                return True
            except (BlockingIOError, InterruptedError):
                if time.time() >= deadline:
                    log("RakNet", "send buffer still full, dropped %d bytes to %s" % (len(data), addr))
                    return False
                select.select([], [self.sock], [], 0.02)
            except OSError as e:
                log("RakNet", "send error to %s: %r" % (addr, e))
                return False

    def next_window_id(self):
        """PocketMine InventoryManager::getNewWindowId - cycles inside ContainerIds::FIRST..LAST."""
        self._window_id = max(CONTAINER_ID_FIRST, (self._window_id + 1) % CONTAINER_ID_LAST)
        return self._window_id

    def container_id(self):
        """The FullContainerName id for inventory contents."""
        return self._window_id

    def load_world(self):
        """Restore the saved level, or start a fresh generated one."""
        had_file = self.world_storage.load()
        self.player_storage.load()
        saved = self.world_storage.loaded_edits()
        if had_file:
            load_edits(saved)
            meta = self.world_storage.meta
            if isinstance(meta.get("seed"), int):
                config.SEED = meta["seed"]
            self.world_note = (
                ("seed %d, %d changed chunk(s) restored from %s" % (config.SEED, len(saved), self.world_storage.path))
                if saved
                else ("loaded %s (seed %d), no blocks changed yet" % (self.world_storage.path, config.SEED))
            )
        else:
            self.world_note = "no saved world at %s, generating terrain with seed %d" % (
                self.world_storage.path,
                config.SEED,
            )
        if config.TERRAIN:
            from ..world.terrain import find_spawn
            from ..world import terrain as _terrain

            _terrain.SPAWN = find_spawn()

    def save_all(self, force=False):
        """Persist the world and every online player."""
        self.world_storage.save(
            meta={"seed": config.SEED, "version": config.GAME_VERSION},
            edits=EDITS if EDITS else None,
        )
        for p in self.playing():
            self.player_storage.put(p.uuid, p.to_dict())
        self.player_storage.save(force=force)
        self._last_save = time.time()
        # Note: the window-id counter is deliberately not reset here. Autosave runs while
        # containers may still be open, and rewinding the counter would let the next
        # container reuse a window id that is already in flight.

    def save_player(self, p):
        self.player_storage.put(p.uuid, p.to_dict())
        self.player_storage.save()

    def banner(self):
        print(
            "Minecraft Bedrock %s pywer-v0.9.1dev Server\nProtocol: %d\nRakNet UDP: %d\nOffline mode: ON\n"
            "World: generated terrain (seed %d)\nMovement: ENABLED (PocketMine-derived) | Mining: PocketMine-style block actions/drops"
            % (config.GAME_VERSION, config.PROTOCOL, self.port, config.SEED),
            flush=True,
        )
        log("Server", "Listening on %s:%d" % (self.bind, self.port))
        log("World", self.world_note)

    def unconnected(self, data, addr):
        pid = data[0]
        if pid in (0x01, 0x02):
            t = data[1:9]
            # Built per ping: the online count has to track the live session table, and
            # a string frozen in __init__ advertised "0 players" for the rest of the run.
            ms = build_motd(self.guid, self.port, len(self.sessions)).encode()
            self.send(
                b"\x1c" + t + struct.pack(">Q", self.guid) + RAKNET_MAGIC + struct.pack(">H", len(ms)) + ms,
                addr,
            )
        elif pid == 0x05:
            if data[1:17] != RAKNET_MAGIC:
                return
            mtu = max(576, min(len(data) + 28, 1492))
            self.send(b"\x06" + RAKNET_MAGIC + struct.pack(">QBH", self.guid, 0, mtu), addr)
        elif pid == 0x07:
            r = ByteReader(data, 17)
            if r.read_u8() == 4:
                r.read_bytes(6)
            else:
                r.read_bytes(28)
            mtu = r.read_u16_be()
            cguid = r.read_u64_be()
            mtu = max(576, min(mtu, 1492))
            if addr not in self.sessions and len(self.sessions) >= config.MAX_PLAYERS:
                log("RakNet", "server full, ignoring %s:%d" % addr)
                return
            old = self.sessions.pop(addr, None)
            if old:
                self.on_leave(old)
            self.sessions[addr] = Session(self, addr, mtu, cguid)
            log("RakNet", "RakNet connection from %s (MTU %d)" % (addr[0], mtu))
            self.send(
                b"\x08" + RAKNET_MAGIC + struct.pack(">Q", self.guid) + enc_addr(*addr) + struct.pack(">HB", mtu, 0),
                addr,
            )

    def playing(self, exclude=None):
        return [s for s in self.sessions.values() if s.spawned and s is not exclude]

    def broadcast(self, pkts, exclude=None):
        for s in self.playing(exclude):
            try:
                s.send_packets(pkts)
            except Exception as e:
                log("Player", "send error: %r" % e)

    def handle_entity_attack(self, attacker, target_rid, player_pos, click_pos):
        """PocketMine Player::attackEntity-style validation for melee hits.

        The target may be another player or any world entity - `playing()` only holds
        sessions, so a punch at a zombie used to resolve to nothing and the whole attack
        (swing, damage, hurt animation) was dropped before anything happened.
        """
        target = resolve_actor(self, target_rid)
        if target is None or target is attacker or getattr(target, "dead", False):
            return False
        if attacker.attack_time > 0:
            return False
        dx = target.feet()[0] - attacker.feet()[0]
        dy = (target.feet()[1] + 0.9) - (attacker.feet()[1] + 1.62)
        dz = target.feet()[2] - attacker.feet()[2]
        dist2 = dx * dx + dy * dy + dz * dz
        if dist2 > 64.0:
            return False
        af = attacker.feet()
        if sum((player_pos[i] - (af[i] + (0.0 if i != 1 else NETWORK_EYE_OFFSET))) ** 2 for i in range(3)) > 4.0:
            return False
        attacker.attack_time = 10
        # Inbound AnimatePacket is not relayed, so without this other players never saw
        # the swing of a hit - only the miss path (F_MISSED_SWING) animated anything.
        attacker.broadcast_arm_swing()
        target.damage(1.0, attacker)
        return True

    def break_block(self, p, x, y, z, old_key=None):
        """PocketMine World::useBreakOn subset for pywer's implemented blocks."""
        key = old_key or get_block(x, y, z)
        if key in ("air", "water", "bedrock") or get_block(x, y, z) != key:
            return False
        if not self.set_block(x, y, z, "air"):
            return False
        held = p.held_item_id() if p is not None else 0
        drops = drops_for(key, held)
        if p is not None and not p.gamemode_is_creative():
            for item_key, count in drops:
                self.drop_item((x + 0.5, y + 1.0, z + 0.5), item_key, count)
        elif p is None:
            for item_key, count in drops:
                self.drop_item((x + 0.5, y + 1.0, z + 0.5), item_key, count)
        if key == "chest" and (x, y, z) in self.chests:
            chest_items = self.chests.pop((x, y, z))
            for item in chest_items:
                if item[0] != 0 and item[1] > 0:
                    ikey = item_key_for_id(item[0])
                    if ikey:
                        self.drop_item((x + 0.5, y + 1.0, z + 0.5), ikey, item[1])
        if not drops:
            dbg("World", "no drops for %s at %d,%d,%d (tool %s)" % (key, x, y, z, held))
        return True

    def drop_item(self, pos, item_key, count=1, motion=None, now=None):
        return self.entity_mgr.drop_item(pos, item_key, count=count, motion=motion, now=now)

    def remove_item_entity(self, eid):
        """Despawn an item entity and tell every client to drop it."""
        return self.entity_mgr.remove(eid) is not None

    def tick_item_entities(self, now, dt):
        """Tick all entities through EntityManager."""
        self.entity_mgr.tick(now, dt, is_solid)

    def set_block(self, x, y, z, key):
        """Change one block for everybody (also stored, so later chunk loads see it)."""
        if key not in BLOCK_RUNTIME:
            raise KeyError(key)
        if not (config.MIN_Y <= y <= config.MAX_Y):
            return False
        cx, cz = x >> 4, z >> 4
        EDITS.setdefault((cx, cz), {})[(x & 15, y, z & 15)] = key
        CHUNK_CACHE.pop((cx, cz), None)
        self.chunk_cache.invalidate(cx, cz)
        mark_dirty(cx, cz)
        self.broadcast([Session._pk(PID_UPDATE_BLOCK, build_update_block(x, y, z, key))])
        return True

    def give(self, p, key, count=1, slot=None):
        """Put `count` of a block/item into the player's inventory."""
        item_id = ITEM_RUNTIME.get(key)
        if item_id is None or key in ("air", "water", "bedrock"):
            p.chat_to("unknown item: %s (see !items)" % key)
            return False
        target = slot if slot is not None else self._first_free_slot(p)
        if target is None:
            p.chat_to("inventory is full")
            return False
        held = p.inventory[target]
        if held[1] and held[0] == item_id:
            p.inventory[target] = item_tuple(item_id, held[1] + count, 0)
        else:
            p.inventory[target] = item_tuple(item_id, count, 0)
        p.sync_inventory_slots([target])
        p.chat_to("gave %d %s (slot %d)" % (count, key, target))
        return True

    def give_tools(self, p):
        """Hand out a full tool set so tool-dependent drops can be tested."""
        from ..world.blocks import TOOLS

        given = 0
        for slot, name in enumerate(
            (
                "wooden_pickaxe",
                "stone_pickaxe",
                "iron_pickaxe",
                "diamond_pickaxe",
                "wooden_axe",
                "iron_axe",
                "wooden_shovel",
                "iron_shovel",
                "shears",
            )
        ):
            if slot >= 36:
                break
            if name not in TOOLS:
                continue
            item_id = ITEM_RUNTIME.get(name)
            if item_id is None:
                continue
            p.inventory[slot] = item_tuple(item_id, 1, 0)
            given += 1
        if given:
            p.sync_inventory_slots(range(min(given, 36)))
        p.chat_to("gave %d tools" % given)

    def _first_free_slot(self, p):
        """First empty slot, hotbar first so new items are reachable without switching."""
        for i in range(len(p.inventory)):
            if p.inventory[i][1] <= 0:
                return i
        return None

    def command(self, p, line):
        sender = PlayerCommandSender(p) if not isinstance(p, CommandSender) else p
        return self.command_mgr.dispatch(sender, line)

    def on_join(self, p):
        others = self.playing(exclude=p)
        p.send_packets(
            [Session._pk(PID_PLAYER_LIST, build_player_list_add(others + [p]))]
            + [Session._pk(PID_ADD_PLAYER, build_add_player(o)) for o in others]
        )
        for o in others:
            o.send_packets(
                [
                    Session._pk(PID_PLAYER_LIST, build_player_list_add([p])),
                    Session._pk(PID_ADD_PLAYER, build_add_player(p)),
                ]
            )
        msg = "§e%s joined the game" % p.name
        ev = events.call(PlayerJoinEvent(p, msg))
        if ev.message:
            self.broadcast([Session._pk(PID_TEXT, build_text(0, "", ev.message))])
        log("Player", "%s joined (%d online)" % (p.name, len(others) + 1))

    def on_leave(self, p):
        if not p.spawned:
            return
        p.spawned = False
        try:
            p.close_main_inventory()
        except Exception:
            pass
        ev = events.call(PlayerQuitEvent(p, "§e%s left the game" % p.name))
        pkts = [
            Session._pk(PID_PLAYER_LIST, build_player_list_remove([p])),
            Session._pk(PID_REMOVE_ACTOR, ByteWriter().write_varint64(p.rid).get()),
        ]
        if ev.message:
            pkts.append(Session._pk(PID_TEXT, build_text(0, "", ev.message)))
        self.broadcast(pkts)
        try:
            self.save_player(p)
        except Exception as e:
            log("Storage", "could not save %s: %r" % (p.name, e))
        log("Player", "%s left" % p.name)

    def drain_workers(self):
        """Drain completed worker results and dispatch to active sessions.

        Each result is handled in isolation. A failed or malformed job must not
        drop the rest of the drained batch, and it must never escape into tick(),
        where an unhandled exception would take the whole server down.
        """
        for item in self.worker_pool.drain_results():
            try:
                self._dispatch_worker(item)
            except Exception as e:
                log("Worker", "error dispatching %r: %r" % (item, e))

    def _dispatch_worker(self, item):
        task_type, session_id, res = item

        if isinstance(res, WorkerFailure):
            # A failure for a type this server does not consume is still reported
            # here. A chunk failure is reported by the session that owns the slot,
            # so that it is not logged twice or dropped when the player is gone.
            session = self._session_by_id(session_id) if task_type == "CHUNK" else None
            if session is not None and len(res.args) == 2:
                if hasattr(session, "on_chunk_failed"):
                    session.on_chunk_failed(res.args[0], res.args[1], res.error)
                    return
            log("Worker", "task %s for session %s failed: %r" % (task_type, session_id, res.error))
            return

        if task_type != "CHUNK":
            # Failures are reported above for every task type; a success that
            # nothing consumes is the same blind spot from the other side. Chunk
            # jobs are the only ones submitted today, so this should never fire -
            # which is exactly why it must not be silent when it does.
            log(
                "Worker",
                "no handler for successful task %s (session %s)" % (task_type, session_id),
            )
            return
        cx, cz, payload = res
        try:
            self.chunk_cache.put(cx, cz, payload)
        except Exception as e:
            # The cache is an optimisation; losing one entry must not cost the
            # session its chunk, which is still delivered below.
            log("Worker", "could not cache chunk (%s, %s): %r" % (cx, cz, e))
        session = self._session_by_id(session_id)
        if session is not None and hasattr(session, "on_chunk_ready"):
            session.on_chunk_ready(cx, cz, payload)

    def _session_by_id(self, session_id):
        """The connected session with this session id, or None if it has gone away."""
        for s in self.sessions.values():
            if s.rid == session_id:
                return s
        return None

    def drain_socket(self):
        """Drain all pending UDP datagrams in non-blocking mode."""
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break
            if not data:
                continue
            try:
                if data[0] & 0x80:
                    s = self.sessions.get(addr)
                    if s:
                        s.on_datagram(data)
                else:
                    self.unconnected(data, addr)
            except Exception as e:
                log("RakNet", "error handling packet from %s: %r" % (addr, e))

    def tick(self, now=None):
        """Single tick iteration (20.0 TPS)."""
        now = time.time() if now is None else now
        self.scheduler.tick()
        self.drain_workers()
        if now - self._last_save >= SAVE_INTERVAL:
            self.save_all()
        dt = min(0.1, max(0.0, now - self._last_tick)) if self._last_tick else 0.0
        self._last_tick = now
        self.tick_item_entities(now, dt)
        for a, s in list(self.sessions.items()):
            try:
                s.tick(now)
            except Exception as e:
                log("RakNet", "tick error: %r" % e)
            if s.state == "CLOSED" or now - s.last_rx > 30:
                del self.sessions[a]
                self.on_leave(s)

    def step(self, timeout=None):
        """Single loop step with socket draining and monotonic tick pacing."""
        now_perf = time.perf_counter()
        if timeout is None:
            timeout = max(0.0, min(TICK_INTERVAL, self._next_tick - now_perf))
        rl, _, _ = select.select([self.sock], [], [], timeout)
        if rl:
            self.drain_socket()
        now_perf = time.perf_counter()
        if now_perf >= self._next_tick:
            self.tick()
            self._next_tick += TICK_INTERVAL
            if now_perf - self._next_tick > MAX_CATCHUP_TICKS * TICK_INTERVAL:
                self._next_tick = now_perf + TICK_INTERVAL

    def run(self, stop=None):
        while not (stop and stop.is_set()):
            self.step()

    def stop(self):
        """Shut down plugins, scheduler, workers, persist the world and close the socket.

        Idempotent and failure-isolated: every step is guarded so that one subsystem
        failing to shut down still releases the others, and a second call is a no-op.
        Tolerates a partially constructed server so a failure during __init__ can still
        release what was already acquired.
        """
        if getattr(self, "_stopped", False):
            return
        self._stopped = True

        def _persist():
            self.save_all(force=True)
            log("Storage", "saved world and player data")

        steps = (
            ("ServerStopEvent", lambda: self.event_mgr.call(ServerStopEvent(self))),
            ("plugins", lambda: self.plugin_mgr.disable_all()),
            ("scheduler", self.scheduler.shutdown),
            ("storage", _persist),
            ("workers", self.worker_pool.shutdown),
        )
        for name, step in steps:
            try:
                step()
            except Exception as e:
                log("Server", "%s shutdown failed: %r" % (name, e))
        sock = getattr(self, "sock", None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

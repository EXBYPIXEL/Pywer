"""RakNet session + Bedrock game session."""

import base64
import math
import secrets
import struct
import time
import uuid
import zlib

from .. import config
from ..crypto.bedrock import BedrockCipher
from ..crypto.ec import ecdh, pub_to_spki, spki_to_pub
from ..crypto.jwt import jwt_make_es384
from ..entity.manager import resolve_actor
from ..event import (
    BlockBreakEvent,
    BlockInteractEvent,
    BlockPlaceEvent,
    EntityDamageByEntityEvent,
    EntityDamageEvent,
    PlayerChatEvent,
    PlayerCommandPreprocessEvent,
    PlayerDeathEvent,
    PlayerInteractEvent,
    PlayerRespawnEvent,
)
from ..event import manager as events
from ..log import dbg, log
from ..net.raknet import enc_addr
from ..packets.abilities import (
    build_player_hotbar,
    build_update_abilities,
    build_update_adventure_settings,
)
from ..packets.entity import (
    build_actor_event,
    build_animate,
    build_level_event,
    build_mob_equipment,
    build_move_actor_absolute,
    build_move_player,
    build_set_actor_motion,
    build_update_attributes,
)
from ..packets.metadata import build_set_actor_data, entity_flags
from ..packets.skin import build_skin
from ..packets.sound import build_level_sound_event, build_play_sound
from ..packets.start_game import build_start_game
from ..packets.text import build_text, sanitize_chat
from ..protocol.auth_input import flag_set, parse_auth_input, resolve_on_off
from ..protocol.flags import (
    BA_ABORT_BREAK,
    BA_CONTINUE_DESTROY_BLOCK,
    BA_CRACK_BREAK,
    BA_PREDICT_DESTROY_BLOCK,
    BA_START_BREAK,
    BA_STOP_BREAK,
    F_HANDLED_TELEPORT,
    F_MISSED_SWING,
    F_SNEAKING,
    F_START_CRAWLING,
    F_START_FLYING,
    F_START_GLIDING,
    F_START_JUMPING,
    F_START_SNEAKING,
    F_START_SPRINTING,
    F_START_SWIMMING,
    F_STOP_CRAWLING,
    F_STOP_FLYING,
    F_STOP_GLIDING,
    F_STOP_SNEAKING,
    F_STOP_SPRINTING,
    F_STOP_SWIMMING,
    decode_input_flags,
)
from ..protocol.inventory import (
    CONTAINER_ID_FIRST,
    CONTAINER_ID_INVENTORY,
    CONTAINER_ID_NONE,
    CONTAINER_ID_UI,
    UI_ARMOR,
    UI_COMBINED,
    UI_CRAFTING_INPUT,
    UI_CREATED_OUTPUT,
    UI_CURSOR,
    UI_HOTBAR,
    UI_INVENTORY,
    UI_OFFHAND,
    UI_SPACE_IDS,
    WINDOW_CONTAINER,
    WINDOW_INVENTORY,
    WINDOW_WORKBENCH,
    build_container_close,
    build_container_open,
    build_inventory_content,
    build_inventory_slot,
    build_stack_response_error,
    build_stack_response_ok,
    parse_item_stack_request,
)
from ..protocol.item_stack import read_item_stack_wrapper
from ..protocol.login import parse_login
from ..protocol.names import packet_name
from ..protocol.packet_ids import (
    INTERACT_LEAVE_VEHICLE,
    INTERACT_MOUSEOVER,
    INTERACT_OPEN_INVENTORY,
    LEVEL_EVENT_BLOCK_BREAK_SPEED,
    LEVEL_EVENT_BLOCK_START_BREAK,
    LEVEL_EVENT_BLOCK_STOP_BREAK,
    PID_ACTOR_EVENT,
    PID_ACTOR_IDS,
    PID_ANIMATE,
    PID_AUTH_INPUT,
    PID_BIOME_DEFS,
    PID_C2S_HANDSHAKE,
    PID_CACHE_STATUS,
    PID_CHUNK,
    PID_CONTAINER_CLOSE,
    PID_CONTAINER_OPEN,
    PID_CRAFTING_DATA,
    PID_CREATIVE,
    PID_INITIALIZED,
    PID_INTERACT,
    PID_INVENTORY_CONTENT,
    PID_INVENTORY_SLOT,
    PID_INVENTORY_TRANSACTION,
    PID_ITEM_STACK_REQUEST,
    PID_ITEM_STACK_RESPONSE,
    PID_LEVEL_EVENT,
    PID_LEVEL_SOUND_EVENT,
    PID_LOGIN,
    PID_MOB_EQUIPMENT,
    PID_MOVE_ACTOR_ABSOLUTE,
    PID_MOVE_PLAYER,
    PID_NETWORK_SETTINGS,
    PID_PACK_RESPONSE,
    PID_PACK_STACK,
    PID_PACKS_INFO,
    PID_PLAY_SOUND,
    PID_PLAY_STATUS,
    PID_PLAYER_ACTION,
    PID_PLAYER_HOTBAR,
    PID_PUBLISHER,
    PID_RADIUS_UPDATED,
    PID_REQ_RADIUS,
    PID_REQUEST_NETWORK_SETTINGS,
    PID_S2C_HANDSHAKE,
    PID_SET_ACTOR_DATA,
    PID_SET_ACTOR_MOTION,
    PID_SET_TIME,
    PID_START_GAME,
    PID_TEXT,
    PID_UPDATE_ABILITIES,
    PID_UPDATE_ADVENTURE_SETTINGS,
    PID_UPDATE_ATTRIBUTES,
    PLAY_FAILED_CLIENT,
    PLAY_FAILED_SERVER,
    PLAY_LOGIN_SUCCESS,
    SOUND_HIT,
)
from ..protocol.transaction import (
    ACTION_ATTACK,
    ACTION_CLICK_BLOCK,
    ACTION_CLICK_AIR,
    TX_USE_ITEM,
    TX_USE_ITEM_ON_ENTITY,
    TX_RELEASE_ITEM,
    parse_inventory_transaction,
    read_block_pos,
)
from ..util.nbt import EMPTY_NBT
from ..util.serializer import ByteReader, ByteWriter
from ..world.blocks import (
    BLOCK_HARDNESS,
    BLOCK_RUNTIME,
    ITEM_RUNTIME,
    SOUND_BREAK,
    SOUND_PLACE,
    block_key_from_runtime,
    block_sound,
    break_seconds,
    item_key_for_id,
    item_key_from_id,
)
from ..world.chunk import build_chunk
from ..world.query import get_block, is_solid
from ..world.terrain import SPAWN

BOW_IDS = {261, 324, ITEM_RUNTIME.get("bow", 324)}
ARROW_IDS = {262, 325, ITEM_RUNTIME.get("arrow", 325)}
SNOWBALL_IDS = {332, 399, ITEM_RUNTIME.get("snowball", 399)}
from .containers import (
    CONTAINER_ARMOR,
    CONTAINER_INVENTORY,
    CONTAINER_OFFHAND,
    CONTAINER_UI,
    ContainerRegistry,
    UI_CREATED_OUTPUT_SLOT,
)
from .inventory import ITEM_AIR, add_item, item_tuple
from .inventory_manager import ACTION_MINE_BLOCK, InventoryError, InventoryManager
from .movement import (
    ALLOW_FLIGHT,
    EYE_HEIGHT,
    MAX_MOVE_DISTANCE_SQ,
    MODE_RESET,
    MODE_TELEPORT,
    MOVE_BACKLOG_SIZE,
    MOVES_PER_TICK,
    _finite,
    _move_with_collision,
    player_size,
)
from .prediction import PredictionTracker

ANIMATE_ACTION_HURT = 2  # ActorEvent::HURT_ANIMATION / AnimatePacket::ACTION_HURT
ANIMATE_ACTION_SWING = 1  # AnimatePacket::ACTION_SWING_ARM

BLOCK_ACTION_NAMES = {
    BA_START_BREAK: "START_BREAK",
    BA_ABORT_BREAK: "ABORT_BREAK",
    BA_STOP_BREAK: "STOP_BREAK",
    BA_CRACK_BREAK: "CRACK_BREAK",
    BA_PREDICT_DESTROY_BLOCK: "PREDICT_DESTROY_BLOCK",
    BA_CONTINUE_DESTROY_BLOCK: "CONTINUE_DESTROY_BLOCK",
}

BREAK_INPUT_TIMEOUT = config.BREAK_INPUT_TIMEOUT


def _build_chunk_job(cx, cz):
    return (cx, cz, build_chunk(cx, cz))


class Session:
    RESEND_AFTER = 1.0
    RESEND_BACKOFF = 1.5  # per-retry multiplier
    RESEND_BACKOFF_MAX = 4.0  # ceiling for that delay
    MAX_RETRIES = 10  # a datagram this old means the reliable channel is unusable
    RESENDS_PER_TICK = 32  # spread an expired window instead of re-blasting it at once
    # Transport resource ceilings. RakNet sequences are 24-bit and the counters are
    # extended monotonically in memory, so these only bound how much state a single
    # peer is allowed to make us hold before we treat it as dead.
    # MAX_PENDING is deliberately generous: a spawn burst of chunk packets legitimately
    # puts hundreds of datagrams in flight before the first ACK can round-trip, so the
    # backlog alone never proves anything. It is only the threshold at which we start
    # looking for ACK silence (ACK_STALL_TIMEOUT) before declaring the peer dead.
    MAX_PENDING = 4096
    ACK_STALL_TIMEOUT = 10.0
    MAX_QUEUE = 1024
    MAX_GAP = 1024
    MAX_ORDER_WINDOW = 4096
    MAX_SPLITS = 64
    MAX_SPLIT_PARTS = 8192
    SPLIT_TTL = 10.0
    MAX_ACK_RANGE = 4096  # sequences one range record may expand to
    # A chunk build that fails may be transient (a lock, a memory spike) or
    # permanent (nothing can produce that coord at all). A few delayed retries
    # recover the first kind without making the player walk across a chunk
    # boundary to force queue_chunks(), and a hard stop on the attempt count
    # keeps the second kind from being resubmitted on every such crossing.
    CHUNK_MAX_ATTEMPTS = 3  # one first try plus two retries
    CHUNK_RETRY_DELAY = 1.0  # seconds before the first retry
    CHUNK_RETRY_BACKOFF = 2.0  # multiplier applied to the delay after that
    MAX_CHUNK_RETRIES = 256  # retries one session may hold pending at once

    @staticmethod
    def _extend_seq(wire, ref):
        """Map a 24-bit wire sequence onto the monotonic sequence of *ref*.

        Both directions use 24-bit counters on the wire. Keeping a monotonic
        counter in memory and re-deriving the window here is what keeps duplicate
        detection, gap detection and retransmission correct across the wrap.
        """
        if ref is None or ref < 0:
            return wire
        cand = (ref & ~0xFFFFFF) | wire
        if cand > ref + 0x800000:
            cand -= 0x1000000
        elif cand + 0x800000 < ref:
            cand += 0x1000000
        return cand

    # A client reports one click twice - once in PlayerAuthInput's embedded
    # ItemInteractionData and once as a standalone InventoryTransaction - and which of the
    # two (or whether both) actually arrives differs per client. Two reports of the same
    # click are identified by source + click identity inside this window.
    ITEM_USE_DEDUP_WINDOW = 0.25

    def __init__(self, srv, addr, mtu, guid):
        self.srv = srv
        self.addr = addr
        self.mtu = mtu
        self.guid = guid
        self.state = "RAKNET_CONNECTING"
        self.seen_seq = set()
        self.ack_q = []
        self.nack_q = []
        self.max_seq = -1
        self.seen_rel = set()
        self.max_rel = -1
        self.order_next = {}
        self.order_buf = {}
        self.splits = {}
        self.send_seq = 0
        self.rel_idx = 0
        self.ord_idx = 0
        self.split_id = 0
        self.pending = {}
        self.last_rx = time.time()
        self.last_ack_at = time.time()
        self.compress = False
        self.cipher = None
        self.player = None
        self.pending_cipher = None
        self.rid = srv.next_rid
        srv.next_rid += 1
        self.pos = (SPAWN[0] + 0.5, SPAWN[1] + 1.62, SPAWN[2] + 0.5)
        self.yaw = 0.0
        self.pitch = 0.0
        self.head_yaw = 0.0
        self.sent_chunks = set()
        self.chunk_queue = []
        self.chunk_send_queue = []
        self.chunks_in_flight = set()
        self.chunk_attempts = {}
        self.chunk_retries = []
        self.center = None
        self.radius = 0
        self.sneaking = False
        self.sprinting = False
        self.swimming = False
        self.gliding = False
        self.crawling = False
        self.flying = False
        self.on_ground = False
        self.fall_distance = 0.0
        self.last_fall = 0.0
        self.jumps = 0
        self.allow_flight = ALLOW_FLIGHT
        self.force_move_sync = False
        self.last_input_pos = None
        self.last_input_rot = (None, None)
        self.meta_dirty = False
        self.move_tokens = 10.0 * MOVES_PER_TICK
        self.last_move_proc = None
        self.last_loc = self.loc()
        self.mtick = 0
        self.spawned = False
        self.name = "Player"
        self.uuid = uuid.uuid4()
        self.xuid = ""
        self.real_ip = None
        self.client_data = {}
        self.skin_bytes = b""
        self.seen_unknown = set()
        self.break_target = None
        self.break_started = 0.0
        self.break_last = 0.0
        self.break_face = 0
        self.break_progress = 0.0
        self.break_input = 0.0
        self.break_speed = 0.0
        self._break_fx = 0
        self.last_input_flags = None
        self.last_input_at = 0.0
        self.seen_block_actions = False
        self.seen_bad_input = False
        self.seen_first_input = False
        self.seen_break_rejects = set()
        self._pending_changed_slots = set()
        self.open_window = False
        self.open_window_pos = None
        self.open_window_type = None
        self.seen_item_use = set()
        self.last_item_use_key = None
        self.last_item_use_at = 0.0
        self.last_item_use_cancelled = False
        self.last_item_use_reports = {}
        self.seen_place_rejects = set()
        self.seen_slot_mappings = set()
        self._pending_slots = set()
        self.current_request_id = None
        self.client_selected_slot = -1
        # opened window id -> container id (PocketMine associates the new window with the
        # player inventory when it opens the player's inventory screen)
        self.window_to_container = {CONTAINER_INVENTORY: CONTAINER_INVENTORY}
        # PocketMine's window handshake: a server-initiated close needs a client ack, and no
        # new window may be opened until it arrives, or the client mis-behaves.
        self.pending_close_window_id = None
        self.pending_open = None
        # Entity/Living state used by the server-side simulation.
        self.motion = (0.0, 0.0, 0.0)
        self.health = 20.0
        self.max_health = 20.0
        self.attack_time = 0
        self.hurt_time = 0
        self.dead = False
        self.inventory = [ITEM_AIR for _ in range(36)]  # 0..8 hotbar, 9..35 main inventory
        self.cursor = ITEM_AIR
        self.selected_slot = 0
        # PocketMine keeps the player inventory registered under ContainerIds::INVENTORY (0) and
        # uses a separate dynamic id for the ContainerOpenPacket + FullContainerName.
        self.inventory_window_id = CONTAINER_ID_INVENTORY
        self.open_window_id = 0
        self.container_id = CONTAINER_ID_FIRST
        self.inventory_revision = 1
        self.gamemode = config.GAMEMODE if config.GAMEMODE in config.VALID_GAMEMODES else 0
        self.experience = 0
        self.experience_level = 0
        self.inv_manager = InventoryManager(self)
        self.containers = ContainerRegistry(self)
        self.predictions = PredictionTracker(self)
        # Server-assigned item stack ids: the new inventory system needs them to reconcile the
        # client's predictions (PocketMine tracks these with a monotonic counter too).
        self.next_stack_id = 1

    def stack_id_for(self, container_id, slot):
        info = self.predictions.info(container_id, slot)
        return info.stack_id if info else 0

    # ---- persistence
    def restore_gamemode(self, saved):
        """Restore gamemode and allow_flight from a player save.

        Deliberately applied twice during a login: StartGamePacket has to announce the
        gamemode during resource-pack negotiation, which is long before the rest of the
        save is applied at SetLocalPlayerAsInitialized. Announcing the server default
        there and correcting it afterwards would leave the client showing one gamemode
        while the server plays another. allow_flight rides along because it is what turns
        a restored creative player into one that can actually fly.
        """
        if not isinstance(saved, dict):
            return
        if "gamemode" in saved:
            try:
                self.gamemode = int(saved["gamemode"])
            except (TypeError, ValueError):
                pass
        # A save file is not a protocol document: gamemode is broadcast to every other
        # player (AddPlayerPacket, the ability bitmask) and written into StartGame.
        if self.gamemode not in config.VALID_GAMEMODES:
            self.gamemode = (
                config.GAMEMODE if config.GAMEMODE in config.VALID_GAMEMODES else 0
            )
        if "allow_flight" in saved:
            self.allow_flight = bool(saved["allow_flight"])
        elif "gamemode" in saved:
            # A world written before allow_flight existed: derive it rather than leave a
            # restored creative player grounded.
            self.allow_flight = self.gamemode in (1, 6)

    def to_dict(self):
        """Serialisable player state (UUID is the key the server stores it under)."""
        return {
            "uuid": str(self.uuid),
            "name": self.name,
            "pos": [round(v, 4) for v in self.feet()],
            "yaw": round(self.yaw, 2),
            "pitch": round(self.pitch, 2),
            "head_yaw": round(self.head_yaw, 2),
            "gamemode": self.gamemode,
            "health": self.health,
            "max_health": self.max_health,
            "experience": self.experience,
            "experience_level": self.experience_level,
            "selected_slot": self.selected_slot,
            "inventory": [list(i) for i in self.inventory],
            "allow_flight": bool(self.allow_flight),
            "saved_at": int(time.time()),
        }

    def apply_dict(self, data):
        """Restore a previously saved player. Missing fields keep their defaults."""
        if not isinstance(data, dict):
            return False
        pos = data.get("pos")
        if isinstance(pos, (list, tuple)) and len(pos) == 3:
            self._set_feet(tuple(float(v) for v in pos))
        for attr in ("yaw", "pitch", "head_yaw"):
            if isinstance(data.get(attr), (int, float)):
                setattr(self, attr, float(data[attr]))
        for attr in (
            "experience",
            "experience_level",
            "selected_slot",
            "max_health",
        ):
            if attr in data:
                try:
                    setattr(self, attr, int(data[attr]))
                except (TypeError, ValueError):
                    pass
        self.restore_gamemode(data)
        if isinstance(data.get("health"), (int, float)):
            self.health = max(0.0, min(self.max_health, float(data["health"])))
        inv = data.get("inventory")
        if isinstance(inv, list) and inv:
            for i, item in enumerate(inv[: len(self.inventory)]):
                try:
                    item_id, count, meta = (list(item) + [0, 0])[:3]
                    self.inventory[i] = item_tuple(int(item_id), int(count), int(meta))
                except (TypeError, ValueError):
                    pass
        return True

    def sync_inventory(self):
        """Full sync of every registered player container.

        PocketMine deliberately sends each container twice - once with every slot cleared,
        then with the real contents. Since 1.20.12 the client ignores a stack-id change when
        the old and new item are equal, so without the clearing pass stale stacks are left on
        screen. All three player containers are synced: the inventory screen binds to the
        offhand and armor containers as well as the main one.
        """
        self.sync_container(CONTAINER_INVENTORY)
        self.sync_container(CONTAINER_OFFHAND)
        self.sync_container(CONTAINER_ARMOR)
        self.sync_complex_containers()

    def sync_complex_containers(self):
        """PocketMine syncs complex inventories as per-slot InventorySlotPackets under
        ContainerIds::UI, with the core slot translated to its UIInventorySlotOffset.
        """
        for _name, entry, core in self.containers.complex_entries():
            net = entry.map_core_to_net(core)
            if net is None:
                continue
            item = entry.items[core]
            info = self.predictions.track_item_stack("ui:%d" % net, core, item, None)
            self.send_packet(
                PID_INVENTORY_SLOT,
                build_inventory_slot(
                    CONTAINER_UI, net, item, self._container_name(), info.stack_id
                ),
            )

    def sync_container(self, container_id, window=None):
        items = self.containers.get(container_id)
        if items is None:
            return
        window = container_id if window is None else window
        ids = {}
        for slot in range(len(items)):
            info = self.predictions.track_item_stack(container_id, slot, items[slot], None)
            ids[slot] = info.stack_id
        self.predictions.predictions.clear()
        self.predictions.pending_syncs.clear()
        cleared = [ITEM_AIR] * len(items)
        self.send_packet(
            PID_INVENTORY_CONTENT,
            build_inventory_content(window, cleared, self._container_name(), {}),
        )
        self.send_packet(
            PID_INVENTORY_CONTENT,
            build_inventory_content(window, items, self._container_name(), ids),
        )

    def sync_slot(self, container_id, slot):
        """PocketMine syncSlot: reuses the slot's existing stack id, never mints a new one."""
        items = self.containers.get(container_id)
        if items is None or not 0 <= slot < len(items):
            return
        sid = self.stack_id_for(container_id, slot)
        window = container_id
        if container_id == CONTAINER_OFFHAND:
            # The client sometimes ignores InventorySlotPacket for the offhand; BDS sends
            # InventoryContentPacket instead, and so does PocketMine.
            self.send_packet(
                PID_INVENTORY_CONTENT,
                build_inventory_content(window, [ITEM_AIR], self._container_name(), {}),
            )
            self.send_packet(
                PID_INVENTORY_CONTENT,
                build_inventory_content(
                    window, [items[slot]], self._container_name(), {0: sid}
                ),
            )
            return
        self.send_packet(
            PID_INVENTORY_SLOT,
            build_inventory_slot(
                window, slot, items[slot], self._container_name(), sid
            ),
        )

    def _container_name(self):
        """FullContainerName id: the server's current inventory container id (PocketMine uses
        lastInventoryNetworkId, a plain 1..100 inventory id - never a ContainerUIIds value).
        """
        return self.container_id

    def sync_inventory_slots(self, slots):
        for slot in sorted(set(slots)):
            if 0 <= slot < len(self.inventory):
                self.sync_slot(CONTAINER_INVENTORY, slot)

    def canonical_container(self, cid):
        """Map any network container id onto the container that actually owns the slots.

        PocketMine keys predictions and stack ids by *Inventory*, so every alias of the main
        inventory (the UI container ids and any window opened for it) must resolve to the
        same one - otherwise the server loses track of its own stack ids.
        """
        if self.containers.get(cid) is not None:
            return cid
        mapped = self.window_to_container.get(cid)
        if mapped is not None:
            return mapped
        # ItemStackContainerIdTranslator::translate - UI container ids map onto the inventory
        # that owns the slots, or onto the shared ContainerIds::UI slot space.
        if cid == UI_ARMOR:
            return CONTAINER_ARMOR
        if cid == UI_OFFHAND:
            return CONTAINER_OFFHAND
        if cid in (UI_HOTBAR, UI_INVENTORY, UI_COMBINED):
            return CONTAINER_INVENTORY
        if cid in UI_SPACE_IDS:
            return CONTAINER_UI
        return cid

    def resolve_slot(self, cid, slot):
        """(network container, slot) -> (canonical container id, backing list, core slot).

        Handles plain containers, the UI container ids that mirror the main inventory, and the
        shared UI slot space (ContainerIds::UI) used by the cursor and the crafting grid.
        """
        orig_cid = cid
        cid = self.canonical_container(cid)
        if orig_cid == UI_CREATED_OUTPUT and slot == 0:
            slot = UI_CREATED_OUTPUT_SLOT
        if cid == CONTAINER_UI:
            hit = self.containers.complex_for_slot(slot)
            if hit is None:
                return None
            entry, core = hit
            return ("ui:%d" % slot, entry.items, core)
        if self.open_window and self.open_window_type == WINDOW_CONTAINER and cid == self.open_window_id:
            chest_items = self.srv.chests.get(self.open_window_pos)
            if chest_items is not None and 0 <= slot < len(chest_items):
                return (cid, chest_items, slot)
        cont = self.containers.get(cid)
        if cont is not None:
            if cid == CONTAINER_OFFHAND:
                return (cid, cont, 0)  # client sends an arbitrary offhand slot id
            if 0 <= slot < len(cont):
                return (cid, cont, slot)
            if 0 <= slot - 1 < len(cont):
                return (cid, cont, slot - 1)  # UI ids are 1-based
        if cid in (UI_HOTBAR, UI_INVENTORY, UI_COMBINED) and 0 <= slot < len(self.inventory):
            return (CONTAINER_INVENTORY, self.inventory, slot)
        note = "container=%d slot=%d" % (cid, slot)
        if note not in self.seen_slot_mappings:
            self.seen_slot_mappings.add(note)
            log("Inventory", "unmapped stack-request %s (UI slot numbering not yet known)" % note)
        return None

    def _touched_refs(self, touched):
        """[(canonical container id, core slot, backing list, UI interface id, net slot)].

        Translates the (id(list), index) pairs returned by InventoryManager into the
        information the prediction tracker and the response builder need.
        """
        for lst_id, idx in sorted(touched):
            if lst_id == id(self.inventory):
                yield CONTAINER_INVENTORY, idx, self.inventory, UI_COMBINED, idx
            elif lst_id == id(self.containers.offhand):
                yield CONTAINER_OFFHAND, 0, self.containers.offhand, UI_OFFHAND, 0
            elif lst_id == id(self.containers.armor):
                yield CONTAINER_ARMOR, idx, self.containers.armor, UI_ARMOR, idx
            else:
                hit = self.containers.complex_for_backing(lst_id)
                if hit is None:
                    continue
                name, entry = hit
                net = entry.map_core_to_net(idx)
                if net is None:
                    continue
                ui = UI_CURSOR if name == "cursor" else UI_CRAFTING_INPUT
                yield ("ui:%d" % net), idx, entry.items, ui, net

    def _track_touched(self, touched, request_id):
        """Register every slot a request changed, attributed to that request.

        PocketMine's InventoryManager::onSlotChange does this when the transaction's slot
        writer fires; pywer mutates the lists directly, so it is done explicitly here.
        """
        for cid, idx, lst, _ui, _net in self._touched_refs(touched):
            self.predictions.track_item_stack(cid, idx, lst[idx], request_id)

    def _changed_response(self, touched):
        """Build the ItemStackResponse changed map keyed by ContainerUIIds.

        PocketMine's ItemStackResponseBuilder reports each touched slot under the *container
        interface id* the client used and with the server stack id of that slot.
        """
        changed = {}
        for cid, idx, lst, ui, net in self._touched_refs(touched):
            sid = self.stack_id_for(cid, idx)
            changed.setdefault(ui, []).append((net, lst[idx], sid))
        return changed

    def _handle_stack_requests(self, requests):
        """Apply parsed ItemStackRequests and answer each one with the slots that changed.

        Rejected requests get RESULT_ERROR plus a full resync, which is how the client is told
        to drop its prediction - that is what makes moves, splits and swaps stick.
        """
        for request_id, actions in requests:
            self.current_request_id = request_id
            try:
                touched = self.inv_manager.apply_request(request_id, actions)
            except InventoryError as e:
                dbg("Inventory", "stack request %d rejected: %s" % (request_id, e.reason))
                self.send_packet(
                    PID_ITEM_STACK_RESPONSE, build_stack_response_error(request_id)
                )
                self.sync_inventory()
                self.current_request_id = None
                continue
            self._track_touched(touched, request_id)
            changed = self._changed_response(touched) if touched else {}
            self.send_packet(
                PID_ITEM_STACK_RESPONSE, build_stack_response_ok(request_id, changed)
            )
            self.current_request_id = None

    def _apply_stack_requests(self, body):
        """Dedicated ItemStackRequestPacket path."""
        try:
            self._handle_stack_requests(parse_item_stack_request(body))
        except Exception as e:
            dbg("Inventory", "bad ItemStackRequest: %r" % e)

    # ---- raw send
    def _udp(self, data):
        return self.srv.send(data, self.addr)

    def _datagram_bytes(self, seq, frames):
        return b"\x84" + (seq & 0xFFFFFF).to_bytes(3, "little") + b"".join(frames)

    def _send_datagram(self, frames):
        seq = self.send_seq
        self.send_seq += 1
        # Keep the datagram in pending even when the send fails: tick() resends it.
        if not self._udp(self._datagram_bytes(seq, frames)):
            dbg("RakNet", "datagram %d not sent, will retry" % seq)
        self.pending[seq] = (time.time(), frames, 0)

    def _resend_datagram(self, seq, ent, now=None):
        """Retransmit *seq* under its original sequence number.

        Reusing the wire sequence is what lets the receiver fill the exact gap it
        reported; minting a new one leaves the original gap permanently open.

        `ent` is the pending entry, so the retry counter survives across retransmits and
        `tick()` can back the next attempt off instead of re-blasting on a fixed timer.
        """
        frames = ent[1]
        retries = (ent[2] if len(ent) > 2 else 0) + 1
        if not self._udp(self._datagram_bytes(seq, frames)):
            dbg("RakNet", "retransmit %d not sent, will retry" % seq)
        self.pending[seq] = (now if now is not None else time.time(), frames, retries)

    def _close_for(self, reason):
        dbg("RakNet", "closing %s: %s" % (self.addr, reason))
        self.state = "CLOSED"

    def send_rak(self, payload):
        """Reliable-ordered, channel 0, with splitting."""
        if self.state == "CLOSED":
            return
        # A spawn burst of chunk packets legitimately fills the window before the first
        # ACK can round-trip (a few dozen chunks is hundreds of datagrams, and on a
        # 150-250ms link the ACKs are still in flight for several ticks), so the backlog
        # on its own is not evidence of anything. Only a peer that keeps talking while
        # never acknowledging again is broken or hostile, and that is what the
        # ACK-silence check is here to detect.
        if (
            len(self.pending) >= self.MAX_PENDING
            and time.time() - self.last_ack_at > self.ACK_STALL_TIMEOUT
        ):
            self._close_for(
                "peer stopped acknowledging (%d unsilenced datagrams)"
                % len(self.pending)
            )
            return
        maxp = self.mtu - 28 - 4 - 24
        chunks = [payload[i : i + maxp] for i in range(0, len(payload), maxp)] or [b""]
        oi = self.ord_idx
        self.ord_idx += 1
        sid = self.split_id
        self.split_id = (self.split_id + 1) & 0xFFFF
        frames = []
        for i, c in enumerate(chunks):
            sp = len(chunks) > 1
            f = bytes([(3 << 5) | (0x10 if sp else 0)]) + struct.pack(">H", len(c) * 8)
            f += (self.rel_idx & 0xFFFFFF).to_bytes(3, "little")
            self.rel_idx += 1
            f += (oi & 0xFFFFFF).to_bytes(3, "little") + b"\x00"
            if sp:
                f += struct.pack(">IHI", len(chunks), sid, i)
            frames.append(f + c)
        cur = []
        size = 0
        limit = self.mtu - 28 - 4
        for f in frames:
            if cur and size + len(f) > limit:
                self._send_datagram(cur)
                cur = []
                size = 0
            cur.append(f)
            size += len(f)
        if cur:
            self._send_datagram(cur)

    # ---- bedrock send
    def send_packets(self, pkts):
        w = ByteWriter()
        for p in pkts:
            w.write_varuint32(len(p))
            w.write_bytes(p)
        batch = w.get()
        if self.compress:
            if len(batch) >= config.COMPRESSION_THRESHOLD:
                co = zlib.compressobj(6, zlib.DEFLATED, -15)
                batch = b"\x00" + co.compress(batch) + co.flush()
            else:
                batch = b"\xff" + batch
        if self.cipher:
            batch = self.cipher.encrypt(batch)
        self.send_rak(b"\xfe" + batch)

    def send_packet(self, pid, body=b""):
        w = ByteWriter()
        w.write_varuint32(pid)
        w.write_bytes(body)
        self.send_packets([w.get()])

    def play_status(self, status):
        self.send_packet(PID_PLAY_STATUS, struct.pack(">i", status))

    # ---- receive
    def on_datagram(self, data):
        self.last_rx = time.time()
        if self.state == "CLOSED":
            return
        kind = data[0] & 0xE0
        if kind == 0xA0:  # RakNet ID_ACK
            return self._on_ack(data)
        if kind == 0xC0:  # RakNet ID_NACK
            return self._on_nack(data)
        r = ByteReader(data, 1)
        seq = self._extend_seq(r.read_u24_le(), self.max_seq)
        if len(self.ack_q) < self.MAX_QUEUE:
            self.ack_q.append(seq)
        if seq in self.seen_seq:
            return
        self.seen_seq.add(seq)
        if seq > self.max_seq + 1:
            start = max(self.max_seq + 1, seq - self.MAX_GAP)
            for s in range(start, seq):
                if s not in self.seen_seq and len(self.nack_q) < self.MAX_QUEUE:
                    self.nack_q.append(s)
        self.max_seq = max(self.max_seq, seq)
        if len(self.seen_seq) > 8192:
            self.seen_seq = set(
                s for s in self.seen_seq if s > self.max_seq - 4096
            )
        while r.left() > 0:
            fl = r.read_u8()
            rel = fl >> 5
            split = bool(fl & 0x10)
            ln = (r.read_u16_be() + 7) // 8
            ridx = r.read_u24_le() if rel in (2, 3, 4, 6, 7) else None
            if rel in (1, 4):
                r.read_u24_le()
            oidx = None
            ch = None
            if rel in (1, 3, 4, 7):
                oidx = r.read_u24_le()
                ch = r.read_u8()
            sp = None
            if split:
                sp = (r.read_u32_be(), r.read_u16_be(), r.read_u32_be())
            payload = r.read_bytes(ln)
            if ridx is not None:
                ridx = self._extend_seq(ridx, self.max_rel)
                if ridx in self.seen_rel:
                    continue
                self.seen_rel.add(ridx)
                if ridx > self.max_rel:
                    self.max_rel = ridx
                if len(self.seen_rel) > 8192:
                    self.seen_rel = set(
                        x for x in self.seen_rel if x > self.max_rel - 4096
                    )
            if sp:
                cnt, sid, idx = sp
                if cnt == 0 or cnt > self.MAX_SPLIT_PARTS or idx >= cnt:
                    self._close_for("invalid split frame (cnt=%d idx=%d)" % (cnt, idx))
                    return
                if sid not in self.splits and len(self.splits) >= self.MAX_SPLITS:
                    self._close_for("too many concurrent splits (%d)" % len(self.splits))
                    return
                ent = self.splits.setdefault(
                    sid, {"cnt": cnt, "parts": {}, "t": time.time()}
                )
                if ent["cnt"] != cnt:
                    self._close_for("split %d changed part count" % sid)
                    return
                ent["parts"][idx] = payload
                if len(ent["parts"]) < ent["cnt"]:
                    continue
                payload = b"".join(
                    ent["parts"][i] for i in range(ent["cnt"])
                )
                del self.splits[sid]
            if oidx is not None and rel in (3, 7):
                oidx = self._extend_seq(oidx, self.order_next.get(ch, -1))
                nxt = self.order_next.get(ch, 0)
                buf = self.order_buf.setdefault(ch, {})
                if oidx < nxt:
                    continue
                if oidx - nxt > self.MAX_ORDER_WINDOW:
                    self._close_for("ordering window overflow on channel %d" % ch)
                    return
                buf[oidx] = payload
                while nxt in buf:
                    self.on_rak_payload(buf.pop(nxt))
                    nxt += 1
                self.order_next[ch] = nxt
            else:
                self.on_rak_payload(payload)

    def _records(self, data):
        r = ByteReader(data, 1)
        n = r.read_u16_be()
        out = []
        cap = Session.MAX_ACK_RANGE
        for _ in range(n):
            if r.read_u8():
                out.append(r.read_u24_le())
            else:
                a = r.read_u24_le()
                b = r.read_u24_le()
                if b < a:
                    # The range straddles the 24-bit wrap: the sender counted past
                    # 0xFFFFFF and back to 0. range(a, b + 1) is empty there, so every
                    # ack in it was silently discarded and the peer retransmitted the
                    # whole window for nothing. Emit both halves, capped so a hostile
                    # range cannot materialise 16M entries.
                    head = min(0x1000000 - a, cap)
                    out.extend(range(a, a + head))
                    out.extend(range(0, min(b + 1, cap - head)))
                else:
                    out.extend(range(a, min(b, a + cap - 1) + 1))
        return out

    def _on_ack(self, data):
        # Any ACK at all proves the peer is still acknowledging, which is what the
        # stalled-window check in send_rak keys off.
        self.last_ack_at = time.time()
        for wire in self._records(data):
            self.pending.pop(self._extend_seq(wire, self.send_seq), None)

    def _on_nack(self, data):
        for wire in self._records(data):
            seq = self._extend_seq(wire, self.send_seq)
            ent = self.pending.get(seq)
            if ent:
                self._resend_datagram(seq, ent)

    def tick(self, now):
        if self.spawned:
            self.process_movement(now)
            self.tick_break(now)
            self.stream_chunks()
            # InventoryManager::flushPendingUpdates - the corrections collected while handling
            # requests/transactions are only actually sent once per tick.
            self.predictions.flush()
            if self.attack_time > 0:
                self.attack_time -= 1
            if self.hurt_time > 0:
                self.hurt_time -= 1
        # RakNet: 0xA0 acknowledges, 0xC0 reports a gap the sender must fill.
        if self.ack_q:
            for pk in self._ackpkts(0xA0, self.ack_q):
                self._udp(pk)
            self.ack_q = []
        if self.nack_q:
            for pk in self._ackpkts(0xC0, self.nack_q):
                self._udp(pk)
            self.nack_q = []
        # Expiring entries are retried on a per-packet backoff and capped per tick: a
        # burst that all went out at the same instant would otherwise all come due at
        # the same instant too, and re-transmit as one storm straight into a link that
        # is already struggling.
        resends = 0
        for s, ent in list(self.pending.items()):
            t, retries = ent[0], ent[2]
            delay = min(
                self.RESEND_AFTER * (self.RESEND_BACKOFF ** retries),
                self.RESEND_BACKOFF_MAX,
            )
            if now - t <= delay:
                continue
            if retries >= self.MAX_RETRIES:
                self._close_for(
                    "datagram %d still unacknowledged after %d retries" % (s, retries)
                )
                return
            if resends >= self.RESENDS_PER_TICK:
                break
            resends += 1
            dbg("RakNet", "resend seq %d (attempt %d)" % (s, retries + 1))
            self._resend_datagram(s, ent, now)
        if self.splits:
            for sid in [
                sid for sid, e in self.splits.items() if now - e["t"] > self.SPLIT_TTL
            ]:
                del self.splits[sid]

    def _ackpkts(self, pid, seqs):
        """Encode an ACK/NACK, splitting it across datagrams when it would exceed the MTU.

        A lossy burst encodes to several KB of records. Crammed into one UDP datagram
        that exceeds the path MTU it is dropped (or IP-fragmented and then dropped on
        most paths), so the peer never learns what arrived and retransmits the entire
        window anyway - the exact traffic the ACK was meant to prevent.
        """
        # Truncate before sorting: a range must never straddle the 24-bit wrap or the
        # receiver would decode an inverted (empty) range and silently drop the acks.
        seqs = sorted(set(s & 0xFFFFFF for s in seqs))
        recs = []
        i = 0
        while i < len(seqs):
            j = i
            while j + 1 < len(seqs) and seqs[j + 1] == seqs[j] + 1:
                j += 1
            if i == j:
                recs.append(b"\x01" + seqs[i].to_bytes(3, "little"))
            else:
                recs.append(
                    b"\x00"
                    + seqs[i].to_bytes(3, "little")
                    + seqs[j].to_bytes(3, "little")
                )
            i = j + 1

        limit = max(64, self.mtu - 28)
        header = 1 + 2  # packet id + record count
        out = []
        cur = []
        used = header
        for rec in recs:
            if cur and used + len(rec) > limit:
                out.append(bytes([pid]) + struct.pack(">H", len(cur)) + b"".join(cur))
                cur = []
                used = header
            cur.append(rec)
            used += len(rec)
        if cur:
            out.append(bytes([pid]) + struct.pack(">H", len(cur)) + b"".join(cur))
        return out

    def on_rak_payload(self, p):
        if not p:
            return
        pid = p[0]
        if pid == 0x09:
            r = ByteReader(p, 1)
            _guid = r.read_u64_be()
            t = r.read_u64_be()
            w = ByteWriter()
            w.write_u8(0x10).write_bytes(enc_addr(*self.addr)).write_u16_be(0)
            for _ in range(10):
                w.write_bytes(enc_addr("255.255.255.255", 19132))
            w.write_u64_be(t).write_u64_be(
                int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF
            )
            self.send_rak(w.get())
            log("RakNet", "Connection request accepted for %s:%d" % self.addr)
        elif pid == 0x13:
            self.state = "WAIT_NETWORK_SETTINGS"
            log("RakNet", "RakNet connected")
        elif pid == 0x00:
            t = ByteReader(p, 1).read_u64_be()
            self.send_rak(
                b"\x03"
                + struct.pack(">Q", t)
                + struct.pack(">Q", int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF)
            )
        elif pid == 0x15:
            log("RakNet", "Client disconnected")
            self.state = "CLOSED"
        elif pid == 0xFE:
            self.on_game(p[1:])
        else:
            dbg("RakNet", "unhandled connected id 0x%02x" % pid, p)

    def on_game(self, data):
        try:
            if self.cipher:
                data = self.cipher.decrypt(data)
            if self.compress:
                h = data[0]
                if h == 0:
                    data = zlib.decompress(data[1:], -15)
                elif h == 0xFF:
                    data = data[1:]
                else:
                    raise ValueError("unsupported compression header %d" % h)
            r = ByteReader(data)
            pkts = []
            while r.left() > 0:
                pkts.append(r.read_bytes(r.read_varuint32()))
        except Exception as e:
            log("Bedrock", "bad batch (%r) - ignored" % e)
            return
        for pk in pkts:
            try:
                rr = ByteReader(pk)
                pid = rr.read_varuint32() & 0x3FF
                self.on_packet(pid, rr.rest())
            except Exception as e:
                log("Bedrock", "packet handler error: %r" % e)

    def on_packet(self, pid, body):
        if config.DEBUG_PACKETS and pid != PID_AUTH_INPUT:
            dbg("Bedrock", "packet id=%d" % pid, body)
        if pid == PID_REQUEST_NETWORK_SETTINGS:
            proto = struct.unpack(">i", body[:4])[0]
            log("Bedrock", "NetworkSettings requested (client protocol %d)" % proto)
            if proto != config.PROTOCOL:
                self.play_status(
                    PLAY_FAILED_CLIENT if proto < config.PROTOCOL else PLAY_FAILED_SERVER
                )
                log("Bedrock", "protocol mismatch, rejected")
                return
            w = ByteWriter()
            w.write_u16_le(config.COMPRESSION_THRESHOLD).write_u16_le(0)  # 0 = zlib
            w.write_bool(False).write_u8(0).write_float(0.0)
            self.send_packet(PID_NETWORK_SETTINGS, w.get())
            self.compress = True
            self.state = "WAIT_LOGIN"
        elif pid == PID_LOGIN:
            info = parse_login(body)
            self.player = info
            log(
                "Login",
                "Login received: name=%s protocol=%s"
                % (info["name"], info["protocol"]),
            )
            if info["protocol"] != config.PROTOCOL:
                self.play_status(
                    PLAY_FAILED_CLIENT
                    if info["protocol"] < config.PROTOCOL
                    else PLAY_FAILED_SERVER
                )
                return
            info["uuid"] = uuid.uuid5(uuid.NAMESPACE_DNS, "offline:" + info["name"])
            self.xuid = info.get("proxy_xuid") or info.get("xuid") or ""
            self.real_ip = info.get("proxy_ip") if config.PROXY_MODE else None
            if config.PROXY_MODE:
                log(
                    "Login",
                    "via proxy: real ip=%s xuid=%s" % (self.real_ip or "?", self.xuid or "?"),
                )
            self.name = info["name"]
            self.uuid = info["uuid"]
            self.client_data = info["client_data"] or {}
            self.skin_bytes = build_skin(self.client_data)
            log(
                "Login",
                "Offline login accepted: %s (uuid %s)"
                % (info["name"], info["uuid"]),
            )
            use_enc = config.ENCRYPTION
            if config.PROXY_MODE and config.PROXY_ENCRYPTION is not None:
                use_enc = config.PROXY_ENCRYPTION
            if use_enc:
                self.state = "ENCRYPTION_HANDSHAKE"
                client_pub = spki_to_pub(
                    base64.b64decode(info["client_key"] or info["identity_key"])
                )
                d, pub = self.srv.key
                salt = secrets.token_bytes(16)
                spki = base64.b64encode(pub_to_spki(pub)).decode()
                jwt = jwt_make_es384(
                    d,
                    {"alg": "ES384", "x5u": spki},
                    {"salt": base64.b64encode(salt).decode()},
                )
                self.send_packet(
                    PID_S2C_HANDSHAKE, ByteWriter().write_string(jwt).get()
                )
                self.cipher = BedrockCipher(
                    salt, ecdh(d, client_pub)
                )  # applies from the next outgoing packet
            else:
                self.play_status(PLAY_LOGIN_SUCCESS)
                self.stage1_done()
        elif pid == PID_C2S_HANDSHAKE:
            log("Handshake", "Encryption handshake complete")
            self.play_status(PLAY_LOGIN_SUCCESS)
            self.stage1_done()
        elif pid == PID_CACHE_STATUS:
            log("Bedrock", "ClientCacheStatus: enabled=%s" % bool(body[:1] and body[0]))
        elif pid == PID_PACK_RESPONSE:
            r = ByteReader(body)
            status = r.read_u8()
            n = r.read_u16_le()
            log("Bedrock", "ResourcePackClientResponse status=%d (%d packs)" % (status, n))
            if status == 3:  # HAVE_ALL_PACKS -> send stack
                w = ByteWriter()
                w.write_bool(False)  # mustAccept
                w.write_varuint32(0).write_varuint32(0)  # behavior packs, resource packs
                w.write_string(config.GAME_VERSION)  # base game version
                w.write_u32_le(0)  # experiments
                w.write_bool(False).write_bool(False)  # previouslyToggled, hasEditorPacks
                self.send_packet(PID_PACK_STACK, w.get())
                log("Bedrock", "ResourcePackStack sent (no packs)")
            elif status == 4:  # COMPLETED
                self.state = "START_GAME"
                log("Bedrock", "Resource pack negotiation COMPLETE")
                # StartGame announces the gamemode now, but the save is only applied at
                # SetLocalPlayerAsInitialized. Restoring these two fields first keeps
                # StartGame, UpdateAbilities and AddPlayer in agreement from the first
                # packet instead of contradicting each other mid-login.
                self.restore_gamemode(
                    self.srv.player_storage.get(self.uuid)
                    if self.srv.player_storage
                    else None
                )
                sg = build_start_game(self.rid, self.gamemode)
                dbg("World", "StartGame payload", sg)
                self.send_packet(PID_START_GAME, sg)
                log("World", "StartGame sent (%d bytes)" % len(sg))
                if config.SEND_ACTOR_IDS:
                    self.send_packet(PID_ACTOR_IDS, EMPTY_NBT)
                if config.SEND_BIOME_DEFS:
                    self.send_packet(PID_BIOME_DEFS, EMPTY_NBT)
                if config.SEND_CREATIVE:
                    self.send_packet(PID_CREATIVE, b"\x00")
                self.send_packet(PID_CRAFTING_DATA, b"\x00\x00\x00\x00\x01")  # empty CraftingData
                self.send_packet(PID_SET_TIME, ByteWriter().write_varint32(6000).get())
                self.state = "WORLD_LOADING"
                log("World", "Waiting for RequestChunkRadius")
            elif status == 1:
                log("Bedrock", "client REFUSED resource packs")
        elif pid == PID_MOB_EQUIPMENT:
            if self.spawned:
                try:
                    r = ByteReader(body)
                    actor = r.read_varuint64()
                    item = read_item_stack_wrapper(r)
                    inv_slot = r.read_u8()
                    hotbar = r.read_u8()
                    window = r.read_u8()
                    if window == 0 and 0 <= hotbar < 9:
                        if actor == self.rid:
                            self.client_selected_slot = hotbar  # record first, so the echo is not suppressed
                            if hotbar != self.selected_slot:
                                self.selected_slot = hotbar
                                self.sync_selected_hotbar()
                except Exception as e:
                    dbg("Inventory", "bad MobEquipment: %r" % e)
        elif pid == PID_ITEM_STACK_REQUEST:
            if self.spawned:
                try:
                    self._apply_stack_requests(body)
                except Exception as e:
                    dbg("Inventory", "invalid ItemStackRequest: %r" % e)
        elif pid == PID_INVENTORY_TRANSACTION:
            if self.spawned:
                try:
                    for tx_type, tx in parse_inventory_transaction(body):
                        if tx is None:
                            continue
                        if tx_type == TX_USE_ITEM:
                            self.handle_item_use(tx, "transaction")
                        elif tx_type == TX_USE_ITEM_ON_ENTITY and tx["action"] == ACTION_ATTACK:
                            self.srv.handle_entity_attack(
                                self,
                                tx["target_rid"],
                                tx["player_pos"],
                                tx["click_pos"],
                            )
                        elif tx_type == TX_RELEASE_ITEM:
                            self.handle_release_item(tx)
                except Exception as e:
                    dbg("Inventory", "bad InventoryTransaction: %r" % e)
        elif pid == PID_REQ_RADIUS:
            r = ByteReader(body)
            want = r.read_varint32()
            rad = max(1, min(want, config.MAX_RADIUS))
            log("World", "RequestChunkRadius %d -> using %d" % (want, rad))
            self.send_packet(PID_RADIUS_UPDATED, ByteWriter().write_varint32(rad).get())
            self.radius = rad
            self.center = (SPAWN[0] >> 4, SPAWN[2] >> 4)
            self.send_publisher(SPAWN)
            self.queue_chunks()
            self.stream_chunks()
            self.play_status(3)
            log("Player", "PlayStatus(PLAYER_SPAWN) sent, waiting for SetLocalPlayerAsInitialized")
        elif pid == PID_INITIALIZED:
            self.state = "SPAWNED"
            log("Player", "Client entered world (SetLocalPlayerAsInitialized)")
            self.spawned = True
            self.force_move_sync = False
            self.last_input_pos = None
            saved = self.srv.player_storage.get(self.uuid) if self.srv.player_storage else None
            if saved and self.apply_dict(saved):
                log(
                    "Player",
                    "%s restored from save (pos %s, %d items)"
                    % (
                        self.name,
                        tuple(round(v, 1) for v in self.feet()),
                        sum(1 for i in self.inventory if i[1] > 0),
                    ),
                )
            self.on_ground = is_solid(
                math.floor(self.pos[0]),
                math.floor(self.pos[1] - EYE_HEIGHT) - 1,
                math.floor(self.pos[2]),
            )
            self.srv.on_join(self)
            self.sync_inventory()
            self.send_packet(PID_UPDATE_ATTRIBUTES, build_update_attributes(self))
            # AddPlayer carries abilities too, but it only goes to *other* players, so the
            # joining player needs these explicitly - same as PocketMine's syncAbilities().
            self.sync_abilities()
            self.send_packet(PID_UPDATE_ADVENTURE_SETTINGS, build_update_adventure_settings())
            self.send_packet(PID_PLAYER_HOTBAR, build_player_hotbar(self.selected_slot))
            self.send_data()
            log(
                "World",
                "%s spawn pose: flags=%s bbox=%.2fx%.2f on_ground=%s feet=%s"
                % (
                    self.name,
                    entity_flags(self),
                    player_size(self)[0],
                    player_size(self)[1],
                    self.on_ground,
                    tuple(round(v, 2) for v in self.feet()),
                ),
            )
        elif pid == PID_CONTAINER_CLOSE:
            if self.spawned:
                self.on_client_close_window(body[0] if body else 0)
        elif pid == PID_INTERACT:
            if self.spawned:
                self.handle_interact(body)
        elif pid == PID_PLAYER_ACTION:
            if self.spawned:
                self.handle_player_action(body)
        elif pid == PID_AUTH_INPUT:
            # Receiving the packet at all proves the client is alive, even if the body is
            # malformed: the break watchdog uses this and must not fire on a parse error.
            self.last_input_at = time.time()
            if self.spawned:
                self.handle_auth_input(body)
        elif pid == PID_TEXT:
            r = ByteReader(body)
            ttype = r.read_u8()
            r.read_bool()
            if ttype == 1:
                r.read_string()
                msg = sanitize_chat(r.read_string())
                if (msg.startswith("!") or msg.startswith("/")) and self.spawned:
                    ev_cmd = events.call(PlayerCommandPreprocessEvent(self, msg))
                    if ev_cmd.is_cancelled:
                        return
                    self.srv.command(self, ev_cmd.command)
                    return
                if msg and self.spawned:
                    ev = events.call(PlayerChatEvent(self, msg))
                    if ev.is_cancelled or not ev.message:
                        return
                    log("Chat", "<%s> %s" % (self.name, ev.message))
                    self.srv.broadcast(
                        [self._pk(PID_TEXT, build_text(1, self.name, ev.format % (self.name, ev.message)))]
                    )
        else:
            if pid not in self.seen_unknown:
                self.seen_unknown.add(pid)
                log("Bedrock", "ignored %s (id %d)" % (packet_name(pid), pid))

    # ---- movement (see player/movement.py for the PocketMine sources this is ported from)
    def feet(self):
        return (self.pos[0], self.pos[1] - EYE_HEIGHT, self.pos[2])

    def _set_feet(self, f):
        self.pos = (f[0], f[1] + EYE_HEIGHT, f[2])

    def loc(self):
        f = self.feet()
        return (f[0], f[1], f[2], self.yaw, self.pitch)

    def _toggle(self, attr, value, allowed=True):
        """Player::toggleSprint/Sneak/Swim/Glide/Flight. Returns False when the change is refused."""
        if value == getattr(self, attr):
            return True
        if not allowed:
            return False
        setattr(self, attr, value)
        self.meta_dirty = True
        return True

    def _tick_entity_motion(self):
        """PocketMine Entity::onUpdate/tryChangeMovement equivalent for server-applied motion.
        Client-authoritative position packets are still validated by handle_movement; this path is for
        knockback and other server-side impulses, so it never blindly trusts a client coordinate.
        """
        mx, my, mz = self.motion
        if abs(mx) < 1e-5 and abs(my) < 1e-5 and abs(mz) < 1e-5:
            return
        if not self.flying and not self.gliding:
            my -= 0.08
        friction = 0.91 if not self.on_ground else 0.60
        mx *= friction
        mz *= friction
        resolved, actual = _move_with_collision(self, mx, my, mz)
        self._set_feet(resolved)
        self.update_fall_state(actual[1], self.on_ground)
        self.motion = (
            0.0 if abs(actual[0]) < 1e-4 else mx,
            0.0 if self.on_ground or abs(actual[1]) < 1e-4 else my,
            0.0 if abs(actual[2]) < 1e-4 else mz,
        )
        if any(abs(v) > 1e-4 for v in actual):
            self.srv.broadcast(
                [self._pk(PID_MOVE_ACTOR_ABSOLUTE, build_move_actor_absolute(self))],
                exclude=self,
            )

    def apply_knockback(self, x, z, force=0.4, vertical=0.4):
        f = math.sqrt(x * x + z * z)
        if f <= 1e-9:
            return
        mx, my, mz = self.motion
        self.motion = (
            mx * 0.5 + x / f * force,
            min(vertical, my * 0.5 + vertical),
            mz * 0.5 + z / f * force,
        )
        self.send_packets(
            [self._pk(PID_SET_ACTOR_MOTION, build_set_actor_motion(self.rid, self.motion))]
        )

    def sync_attributes(self):
        """Send UpdateAttributes so the client's health bar tracks the server's value.

        PocketMine rebroadcasts attributes on every health change; pywer only ever sent
        them once at spawn, so the bar stayed at 20/20 no matter how much damage landed.
        """
        self.send_packet(PID_UPDATE_ATTRIBUTES, build_update_attributes(self))

    def damage(self, amount, attacker=None, source_rid=None, cause=None):
        """Entity::attack / EntityDamageEvent pipeline for players.

        `source_rid` is the keyword Projectiles use; it resolves back to the shooting
        actor - player *or* mob - so a skeleton's arrow carries the same damager,
        knockback and death message as a melee hit. Without it a projectile landing on
        a player raised TypeError straight out of EntityManager.tick and took the whole
        tick loop with it.

        `cause` defaults from what actually hit us rather than always claiming
        "entity_attack": a void or environmental hit that passes through here would
        otherwise tell plugins it was a mob.
        """
        if self.dead or self.hurt_time > 0:
            return False
        amount = float(amount)
        # Zero is a real impact - a snowball or an egg does no damage but must still
        # fire the event, play the hurt animation and knock the target back. Only a
        # negative amount is meaningless.
        if amount < 0.0:
            return False
        if attacker is None and source_rid is not None:
            attacker = resolve_actor(self.srv, source_rid)
        if cause is None:
            cause = (
                "entity_attack"
                if (attacker is not None or source_rid is not None)
                else "generic"
            )
        if attacker is not None:
            ev = EntityDamageByEntityEvent(self, attacker, amount, cause)
        else:
            ev = EntityDamageEvent(self, amount, cause)
        events.call(ev)
        if ev.is_cancelled:
            return False
        amount = float(ev.amount)
        if amount < 0.0:
            return False
        self.health = max(0.0, self.health - amount)
        self.hurt_time = 10
        if attacker is not None:
            dx = self.feet()[0] - attacker.feet()[0]
            dz = self.feet()[2] - attacker.feet()[2]
            self.apply_knockback(dx, dz)
        # Entity hurt animation (generic, no weapon/item simulation). PocketMine broadcasts
        # ActorEventPacket::HURT_ANIMATION, not AnimatePacket.
        self.srv.broadcast(
            [self._pk(PID_ACTOR_EVENT, build_actor_event(self.rid, ANIMATE_ACTION_HURT))]
        )
        self.sync_attributes()
        if self.health <= 0:
            self._on_death(attacker)
        return True

    def _on_death(self, killer=None):
        """Player::onDeath + immediate respawn: event, announcement, then heal and move."""
        self.dead = True
        self.health = 0.0
        if killer is not None:
            killer_name = getattr(killer, "name", None)
            if not killer_name:
                ident = getattr(killer, "identifier", "") or ""
                killer_name = ident.rsplit(":", 1)[-1] or "something"
            message = "§e%s was slain by %s" % (self.name, killer_name)
        else:
            killer_name = "nothing"
            message = "§e%s died" % self.name
        ev = events.call(PlayerDeathEvent(self, death_message=message))
        if ev.death_message:
            self.srv.broadcast([self._pk(PID_TEXT, build_text(0, "", ev.death_message))])
        respawn_pos = (SPAWN[0] + 0.5, SPAWN[1] + 1.0, SPAWN[2] + 0.5)
        # Dispatched before the teleport, not after it: the whole point of this event is
        # to let a plugin redirect the respawn (bed, lobby, arena), and firing it once
        # the player was already moved - with the return value thrown away - meant the
        # only spawn-point hook could never choose anything. A malformed rewrite falls
        # back to the world spawn instead of teleporting the player into garbage.
        ev = events.call(PlayerRespawnEvent(self, respawn_pos))
        pos = getattr(ev, "respawn_pos", None)
        if not (
            isinstance(pos, (list, tuple))
            and len(pos) == 3
            and all(isinstance(v, (int, float)) for v in pos)
        ):
            pos = respawn_pos
        else:
            pos = (float(pos[0]), float(pos[1]), float(pos[2]))
        self.teleport(*pos)
        self.health = self.max_health
        self.hurt_time = 0
        self.fall_distance = 0.0
        self.last_fall = 0.0
        self.dead = False
        self.sync_attributes()
        self.send_data()
        log(
            "Player",
            "%s died (killed by %s), respawned at %s" % (self.name, killer_name, pos),
        )

    def send_data(self, to_all=False):
        """Entity::sendData: SetActorData with flags + bounding box (to everybody, or only to this player)."""
        pk = self._pk(PID_SET_ACTOR_DATA, build_set_actor_data(self))
        if to_all:
            self.srv.broadcast([pk])
        else:
            self.send_packets([pk])

    def sync_movement(self, pos_eye, mode):
        """NetworkSession::syncMovement: MovePlayer to the owner and lock input until it acknowledges (forceMoveSync)."""
        self.send_packets(
            [self._pk(PID_MOVE_PLAYER, build_move_player(self, pos_eye, mode))]
        )
        self.force_move_sync = True

    def revert_movement(self, old_feet):
        self._set_feet(old_feet)
        self.sync_movement(self.feet(), MODE_RESET)

    def update_fall_state(self, dy, on_ground):
        """Entity::updateFallState (+ Player: flying never accumulates fall distance)."""
        if self.flying:
            self.fall_distance = 0.0
            return
        if dy < self.fall_distance:
            self.fall_distance -= dy
        else:
            self.fall_distance = 0.0
        if on_ground and self.fall_distance > 0:
            if self.fall_distance >= 3:
                dbg(
                    "Move",
                    "%s landed after falling %.1f blocks"
                    % (self.name, self.fall_distance),
                )
            self.last_fall = self.fall_distance
            self.fall_distance = 0.0

    def handle_movement(self, new_feet):
        """Player::handleMovement / actuallyHandleMovement."""
        self.move_tokens -= 1
        if self.move_tokens < 0:
            return  # rate limit exceeded: drop it
        old = self.feet()
        dsq = sum((new_feet[i] - old[i]) ** 2 for i in range(3))
        revert = False
        if dsq > MAX_MOVE_DISTANCE_SQ:  # safety check, not anti-cheat (see Player.php)
            dbg(
                "Move",
                "%s moved too fast (%.1f blocks), reverting"
                % (self.name, math.sqrt(dsq)),
            )
            revert = True
        elif (
            math.floor(new_feet[0]) >> 4,
            math.floor(new_feet[2]) >> 4,
        ) not in self.sent_chunks:
            revert = True
            self.center = None  # not in loaded terrain -> re-run chunk order
        if not revert and dsq != 0:
            wanted = (
                new_feet[0] - old[0],
                new_feet[1] - old[1],
                new_feet[2] - old[2],
            )
            resolved, actual = _move_with_collision(self, *wanted)
            self._set_feet(resolved)
            self.update_fall_state(actual[1], self.on_ground)
        if revert:
            self.revert_movement(old)

    def process_movement(self, now):
        """Player::processMostRecentMovements - once per 50 ms: refill the rate limit, broadcast the newest position."""
        if self.last_move_proc is not None and now - self.last_move_proc < 0.05:
            return
        mult = (now - self.last_move_proc) * 20 if self.last_move_proc is not None else 1
        exceeded = self.move_tokens < 0
        self.move_tokens = min(
            MOVE_BACKLOG_SIZE, max(0, self.move_tokens) + MOVES_PER_TICK * mult
        )
        self.last_move_proc = now
        cur = self.loc()
        last = self.last_loc
        d = sum((cur[i] - last[i]) ** 2 for i in range(3))
        ang = abs(last[3] - cur[3]) + abs(last[4] - cur[4])
        if d > 0.0001 or ang > 1.0:
            self.last_loc = cur
            self.srv.broadcast(
                [self._pk(PID_MOVE_ACTOR_ABSOLUTE, build_move_actor_absolute(self))],
                exclude=self,
            )
        if exceeded:
            dbg(
                "Move",
                "%s exceeded the movement rate limit, resetting" % self.name,
            )
            self.sync_movement(self.feet(), MODE_RESET)

    def handle_auth_input(self, body):
        """InGamePacketHandler::handlePlayerAuthInput."""
        try:
            d = parse_auth_input(body)
        except Exception as e:
            if not self.seen_bad_input:
                self.seen_bad_input = True
                log("Bedrock", "bad PlayerAuthInput (logged once): %r" % (e,))
            return
        self.last_input_at = time.time()
        if not self.seen_first_input:
            self.seen_first_input = True
            log(
                "Move",
                "%s first input: flags=%s inputMode=%d playMode=%d interactionMode=%d "
                "pos=%s rot=(%.1f,%.1f)"
                % (
                    self.name,
                    "|".join(decode_input_flags(d["flags"])) or "none",
                    d["input_mode"],
                    d["play_mode"],
                    d["interaction_mode"],
                    tuple(round(v, 2) for v in d["pos"]),
                    d["yaw"],
                    d["pitch"],
                ),
            )
        raw = d["pos"]
        if not _finite(*raw, d["yaw"], d["head_yaw"], d["pitch"]) or any(
            abs(v) > 1e7 for v in raw
        ):
            dbg("Move", "invalid movement received (NaN/INF/huge)")
            return
        if (d["yaw"], d["pitch"]) != self.last_input_rot:  # rotation: fmod 360, yaw made positive
            self.last_input_rot = (d["yaw"], d["pitch"])
            yaw = math.fmod(d["yaw"], 360)
            self.pitch = math.fmod(d["pitch"], 360)
            self.yaw = yaw + 360 if yaw < 0 else yaw
        hy = math.fmod(d["head_yaw"], 360)
        self.head_yaw = hy + 360 if hy < 0 else hy
        has_moved = self.last_input_pos is None or self.last_input_pos != raw
        new_feet = (
            round(raw[0], 4),
            round(raw[1] - EYE_HEIGHT, 4),
            round(raw[2], 4),
        )
        if self.force_move_sync and has_moved:
            cur = self.feet()
            if sum((new_feet[i] - cur[i]) ** 2 for i in range(3)) > 1:
                return  # outdated pre-teleport input
            self.force_move_sync = False  # close enough = teleport acknowledged
        flags = d["flags"]
        # InGamePacketHandler only evaluates the start/stop flag pairs when the whole
        # BitSet actually changed. Without this guard a client that keeps START_SWIMMING
        # asserted while it believes it is swimming re-asserts it every tick, so the
        # server can never observe STOP_SWIMMING and the pose latches on forever.
        if self.last_input_flags != flags:
            # Pose flags are logged on change only: rare enough to be cheap, and the only
            # reliable way to see what the client actually asks for.
            pose_bits = (
                F_SNEAKING
                | F_START_SPRINTING
                | F_STOP_SPRINTING
                | F_START_SNEAKING
                | F_STOP_SNEAKING
                | F_START_SWIMMING
                | F_STOP_SWIMMING
                | F_START_GLIDING
                | F_STOP_GLIDING
                | F_START_CRAWLING
                | F_STOP_CRAWLING
                | F_START_FLYING
                | F_STOP_FLYING
            )
            if (flags ^ (self.last_input_flags or 0)) & pose_bits:
                log(
                    "Move",
                    "%s flags: %s"
                    % (self.name, "|".join(decode_input_flags(flags)) or "none"),
                )
            self.last_input_flags = flags
            sneaking = flag_set(flags, F_SNEAKING)
            if self.sneaking == sneaking:
                sneaking = None
            sprinting = resolve_on_off(flags, F_START_SPRINTING, F_STOP_SPRINTING)
            swimming = resolve_on_off(flags, F_START_SWIMMING, F_STOP_SWIMMING)
            gliding = resolve_on_off(flags, F_START_GLIDING, F_STOP_GLIDING)
            flying = resolve_on_off(flags, F_START_FLYING, F_STOP_FLYING)
            crawling = resolve_on_off(
                flags, F_START_CRAWLING, F_STOP_CRAWLING
            )  # not in PM 5.22, flags exist in the protocol
            mismatch = False
            if sneaking is not None:
                mismatch |= not self._toggle("sneaking", sneaking)
            if sprinting is not None:
                mismatch |= not self._toggle("sprinting", sprinting)
            if swimming is not None:
                mismatch |= not self._toggle("swimming", swimming)
            if gliding is not None:
                mismatch |= not self._toggle("gliding", gliding)
            if flying is not None:
                was_flying = self.flying
                mismatch |= not self._toggle("flying", flying, self.allow_flight)
                if self.flying != was_flying:
                    # UpdateAbilities is the only packet that carries the FLYING bit, so
                    # without this the client keeps whatever was true when we spawned it.
                    self.sync_abilities()
            if crawling is not None:
                mismatch |= not self._toggle("crawling", crawling)
            if self.meta_dirty:
                self.meta_dirty = False
                self.send_data(to_all=True)
            if mismatch:
                self.send_data()  # refused: tell the client the real state
            # InGamePacketHandler only fires jump/missSwing when the flag set changes.
            if flag_set(flags, F_START_JUMPING):
                self.jumps += 1
                dbg("Move", "%s jumped" % self.name)
            if flag_set(flags, F_MISSED_SWING):
                self.broadcast_arm_swing()
        if not self.force_move_sync and has_moved:
            self.last_input_pos = raw
            self.handle_movement(new_feet)

        # PocketMine processes PlayerBlockActions first, then the item-interaction
        # transaction, preserving the wire order in PlayerAuthInput::decodePayload.
        actions = d.get("block_actions", [])
        if actions and not self.seen_block_actions:
            self.seen_block_actions = True
            log(
                "World",
                "client sends server-authoritative block actions (%s)"
                % ", ".join(
                    BLOCK_ACTION_NAMES.get(a, str(a)) for a, _, _ in actions
                ),
            )
        for action, bpos, face in actions:
            if action == BA_START_BREAK:
                if bpos is not None:
                    self.start_break(bpos, face)
            elif action in (BA_CONTINUE_DESTROY_BLOCK, BA_CRACK_BREAK):
                if bpos is not None:
                    self.continue_break(bpos, face)
            elif action == BA_PREDICT_DESTROY_BLOCK:
                # This is only the *client's* guess that the block is gone. With
                # serverAuthoritativeBlockBreaking the server owns the timing, so acting on
                # it here would destroy the block long before hardness*5 elapsed (the client
                # predicts early), which also killed the crack animation.
                if bpos is not None and self.break_target == tuple(bpos):
                    dbg(
                        "World",
                        "client predicted destroy at %.0f%%, waiting for the server timer"
                        % (self.break_progress * 100),
                    )
            elif action in (BA_ABORT_BREAK, BA_STOP_BREAK):
                self.stop_break(bpos)
        item_use = d.get("item_use")
        if item_use is not None:
            self.handle_item_use(item_use, "auth_input")
        stack_request = d.get("stack_request")
        if stack_request is not None:
            # A MINE_BLOCK request accompanies breaking. The drop is spawned as an item
            # entity, so the inventory itself does not change - but the request must still be
            # answered or the client times out and drops itself.
            self._pending_changed_slots.clear()
            self._handle_stack_requests(
                [(stack_request[0], [(ACTION_MINE_BLOCK,) + stack_request[1][0][1:]])]
            )
        self.mtick += 1
        self.stream_chunks()

    # ---- block placement (Human::interactBlock -> Item::place)
    FACE_NORMALS = (
        (0, -1, 0),
        (0, 1, 0),
        (0, 0, -1),
        (0, 0, 1),
        (-1, 0, 0),
        (1, 0, 0),
    )

    def _held_block_key(self, tx):
        """Work out which block is being placed.

        The client's own `blockRuntimeId` wins when it resolves, because that is the id the
        client actually rendered - PocketMine uses the held item, but pywer hardcodes block
        state names (pillar_axis, infiniburn_bit, ...) and any wrong guess there makes our
        hash differ from the client's, which would silently break placement for that block
        only. The held item is the fallback, and a disagreement between the two is logged.
        """
        declared = (
            tx.get("block_runtime_id")
            or (tx.get("item") or {}).get("block_runtime")
            or 0
        )
        from_runtime = block_key_from_runtime(declared)
        held = self._held_slot_item()
        from_hand = (
            item_key_from_id(held[0])
            if held is not None and held[1] > 0
            else None
        )
        if from_runtime and from_hand and from_runtime != from_hand:
            log(
                "World",
                "%s: client runtime id %d is %s but the hand holds %s; trusting the client"
                % (self.name, declared & 0xFFFFFFFF, from_runtime, from_hand),
            )
        if from_runtime:
            return from_runtime, "client"
        if (
            from_hand
            and from_hand in BLOCK_RUNTIME
            and from_hand not in ("air", "water", "bedrock")
        ):
            return from_hand, "hand"
        item_id = (tx.get("item") or {}).get("id") or 0
        key = item_key_from_id(item_id)
        return (key, "item-id") if key and key in BLOCK_RUNTIME else (None, None)

    def try_place_block(self, tx):
        face = tx.get("face", -1)
        if not 0 <= face < len(self.FACE_NORMALS):
            return self._reject_place(tx.get("pos"), "invalid face %r" % (face,))
        pos = tuple(tx["pos"])
        # World::useItemOn refuses to interact with air, so there is nothing to place against.
        clicked = get_block(*pos)
        if clicked == "air":
            return self._reject_place(
                pos,
                "the block you clicked is air on the server (client and server disagree on this position)",
            )
        # Placement goes on the clicked face: the new block sits at clicked block + face normal.
        nx, ny, nz = (
            pos[0] + self.FACE_NORMALS[face][0],
            pos[1] + self.FACE_NORMALS[face][1],
            pos[2] + self.FACE_NORMALS[face][2],
        )
        if not (config.MIN_Y <= ny <= config.MAX_Y):
            return self._reject_place(pos, "target y %d out of world height" % ny)
        if not self._block_reach_ok(pos):
            return self._reject_place(pos, "clicked block out of reach")
        if not self.sneaking:
            if clicked == "crafting_table":
                self.open_crafting_table(pos)
                return True
            if clicked == "chest":
                self.open_chest(pos)
                return True
        key, source = self._held_block_key(tx)
        if key is None:
            return self._reject_place(
                pos,
                "no placeable block resolved (held=%s runtimeId=%s)"
                % (
                    self._held_slot_item(),
                    (tx.get("block_runtime_id") or 0) & 0xFFFFFFFF,
                ),
            )
        if BLOCK_HARDNESS.get(key, -1) < 0:
            return self._reject_place(pos, "%s cannot be placed" % key)
        target = get_block(nx, ny, nz)
        if target not in ("air", "water"):
            return self._reject_place(
                pos,
                "destination %d,%d,%d already holds %s" % (nx, ny, nz, target),
            )
        # Do not entomb a player inside a block.
        f = self.feet()
        if nx == math.floor(f[0]) and nz == math.floor(f[2]) and math.floor(f[1]) == ny:
            return self._reject_place(pos, "would place inside the player")
        for other in self.srv.playing(exclude=self):
            of = other.feet()
            if nx == math.floor(of[0]) and nz == math.floor(of[2]) and math.floor(of[1]) == ny:
                return self._reject_place(pos, "would place inside another player")
        if self.gamemode_is_creative():
            return self._place_block(
                nx, ny, nz, key, consume=False, clicked=pos, face=face
            )
        # Only enforce "you must be holding it" when the block came from our own hand
        # lookup; if the client declared the block it has already rendered it, so the
        # correct action is to consume whatever is in hand.
        if source == "hand":
            held = self._held_slot_item()
            if held is None or held[1] <= 0 or held[0] != ITEM_RUNTIME.get(key):
                return self._reject_place(pos, "not holding %s" % key)
        return self._place_block(
            nx, ny, nz, key, consume=True, clicked=pos, face=face
        )

    def _place_block(self, nx, ny, nz, key, consume, clicked=None, face=None):
        ev = events.call(BlockPlaceEvent(self, nx, ny, nz, key))
        if ev.is_cancelled:
            return False
        if not self.srv.set_block(nx, ny, nz, key):
            return False
        if consume:
            self._consume_held_item()
            self._pending_changed_slots.add(self.selected_slot)
        log(
            "World",
            "%s PLACED %s -> %d,%d,%d (clicked %s face %s)"
            % (self.name, key, nx, ny, nz, clicked, face),
        )
        self.play_sound_at(nx, ny, nz, block_sound(key, SOUND_PLACE), 0.7)
        return True

    def _trace_item_use(self, tx, source="transaction"):
        """Log the first few item-use transactions: proves which transport carries it."""
        if len(self.seen_item_use) >= 3:
            return
        self.seen_item_use.add(1)
        declared = tx.get("block_runtime_id") or 0
        log(
            "Inventory",
            "item-use via %s action=%d face=%d clicked=%s runtimeId=%d (%s) held=%s"
            % (
                source,
                tx.get("action", -1),
                tx.get("face", -1),
                tx.get("pos"),
                declared & 0xFFFFFFFF,
                block_key_from_runtime(declared) or "unknown",
                self._held_slot_item(),
            ),
        )

    def _reject_place(self, pos, reason):
        """Log each distinct refusal reason once, so placement failures are never silent."""
        if reason not in self.seen_place_rejects:
            self.seen_place_rejects.add(reason)
            where = ("%d,%d,%d" % (pos[0], pos[1], pos[2])) if pos else "?"
            log("World", "place refused at %s: %s" % (where, reason))
        return False

    def _held_slot_item(self):
        if not 0 <= self.selected_slot < len(self.inventory):
            return None
        return self.inventory[self.selected_slot]

    def _consume_held_item(self):
        """Take one of the held stack, matching the client's own prediction."""
        slot = self.selected_slot
        if not 0 <= slot < len(self.inventory):
            return
        item = self.inventory[slot]
        if item[1] <= 0:
            return
        self.inventory[slot] = item_tuple(item[0], item[1] - 1, item[2])
        self.sync_inventory_slots([slot])

    def handle_release_item(self, tx):
        """Handles ReleaseItemTransactionData (e.g. bow release)."""
        action = tx.get("action", 0) if isinstance(tx, dict) else 0
        if action != 0:
            return False

        # What gets fired is decided from the server's own view of the held slot. The
        # transaction's item id is only the client's claim, and trusting it lets a player
        # release a bow they are not holding at all.
        held_item = self._held_slot_item()
        if held_item is None or held_item[0] not in BOW_IDS:
            return False

        is_creative = (
            self.gamemode_is_creative()
            if hasattr(self, "gamemode_is_creative")
            else False
        )

        arrow_slot = None
        if not is_creative:
            for slot_idx, itm in enumerate(self.inventory):
                if itm and itm[0] in ARROW_IDS and itm[1] > 0:
                    arrow_slot = slot_idx
                    break
            if arrow_slot is None:
                return False

        pitch_rad = math.radians(self.pitch)
        yaw_rad = math.radians(self.yaw)
        speed = 3.0
        vx = -math.sin(yaw_rad) * math.cos(pitch_rad) * speed
        vy = -math.sin(pitch_rad) * speed
        vz = math.cos(yaw_rad) * math.cos(pitch_rad) * speed

        fx, fy, fz = self.feet()
        spawn_pos = (fx, fy + 1.62, fz)
        spawned = False
        if hasattr(self.srv, "entity_mgr"):
            from ..entity.projectile import Arrow

            spawned = (
                self.srv.entity_mgr.spawn(
                    Arrow,
                    shooter_rid=self.rid,
                    pos=spawn_pos,
                    motion=(vx, vy, vz),
                )
                is not None
            )

        # Ammunition is spent only once the arrow actually exists: a plugin that vetoes
        # EntitySpawnEvent refuses the shot, and a refused shot must not eat an arrow.
        if spawned and arrow_slot is not None:
            aid, acnt, admg = self.inventory[arrow_slot]
            if acnt <= 1:
                self.inventory[arrow_slot] = ITEM_AIR
            else:
                self.inventory[arrow_slot] = (aid, acnt - 1, admg)
            try:
                self.sync_inventory_slots([arrow_slot])
            except Exception:
                pass
        return True

    def handle_item_use(self, tx, source):
        """Run one UseItemTransactionData, whichever transport reported it.

        PlayerAuthInput embeds the same UseItemTransactionData in its payload
        (ItemInteractionData, flag PERFORM_ITEM_INTERACTION) that other clients send as a
        standalone InventoryTransaction, and pywer reads both. Whether a client uses one
        or the other - or both for the same click - is not something the protocol
        guarantees, so the first report runs the whole thing (prediction, the interact
        hook, the item's own effect, block placement) and a later report of the same
        click from the other transport reuses that verdict instead of firing the event
        and consuming the item twice.

        Deciding that by "the other transport said the same thing recently" is not
        enough: two genuine clicks can be identical (two air clicks with the same
        position and face), so the reports of each click are counted per transport and
        only a transport that has reported this click identity *more* often than its
        counterpart is a fresh click. That keeps both halves of one click deduplicated
        while still dispatching the next click, in any arrival order.

        Returns True when the click was allowed to proceed.
        """
        action = tx.get("action", -1)
        pos = tx.get("pos")
        key = (action, tuple(pos) if pos is not None else None, tx.get("face"))
        now = time.monotonic()
        if (
            key != self.last_item_use_key
            or (now - self.last_item_use_at) > self.ITEM_USE_DEDUP_WINDOW
        ):
            self.last_item_use_key = key
            self.last_item_use_reports = {}
        self.last_item_use_at = now
        reports = self.last_item_use_reports
        reports[source] = reports.get(source, 0) + 1
        if reports[source] <= sum(n for src, n in reports.items() if src != source):
            return not self.last_item_use_cancelled
        self._trace_item_use(tx, source)
        # The client has already rendered this click locally; record what it expects so
        # stack-id reconciliation compares against its own prediction, not ours.
        self.predictions.predict(
            CONTAINER_INVENTORY,
            self.selected_slot,
            self._held_slot_item() or ITEM_AIR,
        )
        ev = events.call(
            PlayerInteractEvent(
                self,
                self._held_slot_item() or ITEM_AIR,
                action,
                None if action == ACTION_CLICK_AIR else key[1],
                tx.get("face"),
            )
        )
        cancelled = bool(ev.is_cancelled)
        self.last_item_use_cancelled = cancelled
        if cancelled:
            return False
        if not self.handle_use_item(tx) and action == ACTION_CLICK_BLOCK:
            self.try_place_block(tx)
        return True

    def handle_use_item(self, tx):
        """Handles UseItemTransactionData for projectiles like snowballs."""
        held_item = self._held_slot_item()
        # Same rule as the bow release: the server decides what is being thrown from its
        # own inventory, not from the item id the client put in the transaction.
        if held_item is not None and held_item[0] in SNOWBALL_IDS:
            is_creative = (
                self.gamemode_is_creative()
                if hasattr(self, "gamemode_is_creative")
                else False
            )
            slot = None
            if not is_creative and 0 <= self.selected_slot < len(self.inventory):
                slot = self.selected_slot

            pitch_rad = math.radians(self.pitch)
            yaw_rad = math.radians(self.yaw)
            speed = 1.5
            vx = -math.sin(yaw_rad) * math.cos(pitch_rad) * speed
            vy = -math.sin(pitch_rad) * speed
            vz = math.cos(yaw_rad) * math.cos(pitch_rad) * speed
            fx, fy, fz = self.feet()
            spawn_pos = (fx, fy + 1.62, fz)
            spawned = False
            if hasattr(self.srv, "entity_mgr"):
                from ..entity.projectile import Snowball

                spawned = (
                    self.srv.entity_mgr.spawn(
                        Snowball,
                        shooter_rid=self.rid,
                        pos=spawn_pos,
                        motion=(vx, vy, vz),
                    )
                    is not None
                )

            # Same rule as the bow: the snowball is spent only once it really exists, so
            # a plugin vetoing EntitySpawnEvent must not eat the stack.
            if spawned and slot is not None:
                sid, scnt, sdmg = self.inventory[slot]
                if scnt <= 1:
                    self.inventory[slot] = ITEM_AIR
                else:
                    self.inventory[slot] = (sid, scnt - 1, sdmg)
                try:
                    self.sync_inventory_slots([slot])
                except Exception:
                    pass
            return True
        return False


    def play_sound_at(self, x, y, z, sound, volume=1.0, pitch=1.0):
        self.srv.broadcast(
            [self._pk(PID_PLAY_SOUND, build_play_sound(sound, (x, y, z), volume, pitch))]
        )

    def handle_interact(self, body):
        """InteractPacket - this is how the client asks to open its inventory (the E key).

        PocketMine only reacts to ACTION_OPEN_INVENTORY aimed at the player itself; the
        MOUSEOVER spam the client sends constantly is deliberately dropped.
        """
        try:
            r = ByteReader(body)
            action = r.read_u8()
            target = r.read_varuint64()
            if action in (INTERACT_MOUSEOVER, INTERACT_LEAVE_VEHICLE):
                return  # spam, and not actionable
            if action == INTERACT_OPEN_INVENTORY and target == self.rid:
                self.open_main_inventory()
            else:
                dbg(
                    "Inventory",
                    "unhandled InteractPacket action %d (target %d)"
                    % (action, target),
                )
        except Exception as e:
            dbg("Inventory", "bad InteractPacket: %r" % e)

    def open_main_inventory(self):
        """Open the player's inventory.

        Mirrors InventoryManager::onClientOpenMainInventory: a fresh dynamic window id for the
        ContainerOpenPacket and the container name, while the contents themselves stay
        synced under ContainerIds::INVENTORY.
        """
        if self.pending_close_window_id is not None:
            # defer: opening before the previous close is acked makes the client mis-behave
            self.pending_open = self.open_main_inventory
            return False
        self.close_main_inventory(notify=False)
        self.open_window = True
        self.open_window_id = self.srv.next_window_id()
        self.container_id = self.srv.container_id()
        self.send_packet(
            PID_CONTAINER_OPEN,
            build_container_open(self.open_window_id, WINDOW_INVENTORY, self.rid),
        )
        # PocketMine does associateIdWithInventory($windowId, $player->getInventory()) before
        # opening: the new window *is* the player inventory. Without serving the contents
        # under the opened window the client binds its inventory screen to a container it has
        # never seen and crashes, so the window is registered and filled here.
        self.window_to_container[self.open_window_id] = CONTAINER_INVENTORY
        self.sync_container(CONTAINER_INVENTORY, window=self.open_window_id)
        log(
            "Inventory",
            "%s opened the inventory (window %d, contents window %d, container %d)"
            % (
                self.name,
                self.open_window_id,
                self.inventory_window_id,
                self._container_name(),
            ),
        )

    def _fire_block_interact(self, pos, block_key):
        """Dispatch BlockInteractEvent. False means a plugin cancelled the click."""
        ev = events.call(BlockInteractEvent(self, pos[0], pos[1], pos[2], block_key))
        if ev.is_cancelled:
            dbg("World", "%s's click on %s at %d,%d,%d was cancelled" % (self.name, block_key, pos[0], pos[1], pos[2]))
            return False
        return True

    def open_crafting_table(self, pos):
        """Open a 3x3 workbench window at pos. Returns False when a plugin cancelled it."""
        if not self._fire_block_interact(pos, "crafting_table"):
            return False
        if self.open_window:
            self.close_main_inventory(notify=False)
        self.open_window = True
        self.open_window_id = self.srv.next_window_id()
        self.open_window_pos = pos
        self.open_window_type = WINDOW_WORKBENCH
        self.send_packet(
            PID_CONTAINER_OPEN,
            build_container_open(self.open_window_id, WINDOW_WORKBENCH, -1, pos),
        )
        self.window_to_container[self.open_window_id] = CONTAINER_INVENTORY
        log("Inventory", "%s opened crafting table at %s (window %d)" % (self.name, pos, self.open_window_id))
        return True

    def open_chest(self, pos):
        """Open a 27-slot chest container window at pos. Returns False when cancelled."""
        if not self._fire_block_interact(pos, "chest"):
            return False
        if self.open_window:
            self.close_main_inventory(notify=False)
        self.open_window = True
        self.open_window_id = self.srv.next_window_id()
        self.open_window_pos = pos
        self.open_window_type = WINDOW_CONTAINER
        chest_items = self.srv.chests.setdefault(pos, [ITEM_AIR] * 27)
        self.send_packet(
            PID_CONTAINER_OPEN,
            build_container_open(self.open_window_id, WINDOW_CONTAINER, -1, pos),
        )
        self.window_to_container[self.open_window_id] = self.open_window_id
        self.send_packet(
            PID_INVENTORY_CONTENT,
            build_inventory_content(self.open_window_id, chest_items, container_id=self.open_window_id),
        )
        log("Inventory", "%s opened chest at %s (window %d)" % (self.name, pos, self.open_window_id))
        return True

    def close_main_inventory(self, notify=True):
        if not self.open_window:
            return
        window = self.open_window_id or self.inventory_window_id
        wtype = self.open_window_type or WINDOW_INVENTORY
        if self.open_window_type == WINDOW_WORKBENCH:
            c3 = self.containers.complex.get("crafting3x3")
            if c3:
                for i in range(len(c3.items)):
                    it = c3.items[i]
                    if it[0] != 0 and it[1] > 0:
                        leftover = add_item(self.inventory, it)
                        placed = 0
                        if leftover > 0:
                            ikey = item_key_for_id(it[0])
                            if ikey:
                                placed = self.srv.drop_item(self.feet(), ikey, leftover)
                        # Anything the world refused to take stays in the container
                        # instead of disappearing with the cleared slot.
                        c3.items[i] = item_tuple(it[0], leftover - placed, it[2])
                self.sync_inventory()
        self.open_window = False
        self.open_window_id = 0
        self.open_window_pos = None
        self.open_window_type = None
        self.window_to_container.pop(window, None)
        if notify:
            self.send_packet(
                PID_CONTAINER_CLOSE,
                build_container_close(window, wtype, True),
            )
            # a server-initiated close needs the client's ack before another window opens
            self.pending_close_window_id = window
        log("Inventory", "%s closed the window %d" % (self.name, window))

    def on_client_close_window(self, window_id):
        """PocketMine InventoryManager::onClientRemoveWindow.

        The ack is always sent back - the client expects one even when it initiated the
        close itself - and any window open deferred behind this close now runs.
        """
        wtype = self.open_window_type or WINDOW_INVENTORY
        self.send_packet(
            PID_CONTAINER_CLOSE,
            build_container_close(window_id, wtype),
        )
        if window_id == self.open_window_id:
            self.close_main_inventory(notify=False)
        if self.pending_close_window_id == window_id:
            self.pending_close_window_id = None
            if self.pending_open is not None:
                todo = self.pending_open
                self.pending_open = None
                todo()
            else:
                log("Inventory", "%s acknowledged window %d close" % (self.name, window_id))

    def sync_selected_hotbar(self):
        """PocketMine syncSelectedHotbarSlot: MobEquipmentPacket carrying the held stack."""
        if not 0 <= self.selected_slot < len(self.inventory):
            return
        sid = self.stack_id_for(CONTAINER_INVENTORY, self.selected_slot)
        self.send_packet(
            PID_MOB_EQUIPMENT,
            build_mob_equipment(
                self.rid,
                self.inventory[self.selected_slot],
                self.selected_slot,
                self.selected_slot,
                CONTAINER_INVENTORY,
                sid,
            ),
        )

    def handle_player_action(self, body):
        """Legacy PlayerActionPacket break actions.

        Only used as a fallback: some clients send these instead of the PlayerAuthInput
        block actions, and once a session has shown us PlayerAuthInput actions we ignore
        them so the same break is never processed twice.
        """
        if self.seen_block_actions:
            return
        try:
            r = ByteReader(body)
            actor = r.read_varuint64()
            action = r.read_varint32()
            pos = read_block_pos(r)
            read_block_pos(r)  # result position
            face = r.read_varint32()
        except Exception as e:
            dbg("World", "bad PlayerAction: %r" % e)
            return
        if actor != self.rid:
            return
        if action == BA_START_BREAK:
            self.start_break(pos, face)
        elif action in (BA_CONTINUE_DESTROY_BLOCK, BA_CRACK_BREAK):
            # Same heartbeat the PlayerAuthInput path gives: without it a legacy client
            # starts the break and the server timer never sees another input, so the
            # block never finishes breaking.
            self.continue_break(pos, face)
        elif action == BA_PREDICT_DESTROY_BLOCK:
            # The client's guess that the block is gone. The server owns the timing
            # (serverAuthoritativeBlockBreaking), so acting on it would destroy the block
            # long before hardness*5 elapsed - logged instead of honoured.
            if self.break_target == tuple(pos):
                dbg(
                    "World",
                    "client predicted destroy at %.0f%%, waiting for the server timer"
                    % (self.break_progress * 100),
                )
        elif action in (BA_ABORT_BREAK, BA_STOP_BREAK):
            self.stop_break(pos)

    def max_reach(self):
        """PocketMine Player::MAX_REACH_DISTANCE_SURVIVAL = 7, CREATIVE = 13."""
        return 13.0 if self.gamemode_is_creative() else 7.0

    def _block_reach_ok(self, pos):
        f = self.feet()
        dx = (pos[0] + 0.5) - f[0]
        dy = (pos[1] + 0.5) - (f[1] + 1.62)
        dz = (pos[2] + 0.5) - f[2]
        reach = self.max_reach()
        return dx * dx + dy * dy + dz * dz <= reach * reach

    def held_item_id(self):
        if not 0 <= self.selected_slot < len(self.inventory):
            return 0
        return self.inventory[self.selected_slot][0]

    def _break_duration(self, key):
        """Seconds needed to break `key` with the currently held item.

        None means "cannot be broken"; 0.0 means "breaks instantly" (creative mode).
        Delegates to world.blocks.break_seconds so hardness, tool tier, tool type, the
        airborne penalty and the underwater penalty all follow PocketMine's formula.
        """
        if key == "air":
            return None
        if BLOCK_HARDNESS.get(key, -1) < 0:
            return None
        if self.gamemode_is_creative():
            return 0.0
        return break_seconds(
            key,
            self.held_item_id(),
            on_ground=self.on_ground,
            flying=self.flying or self.gliding,
            underwater=self.head_in_water(),
        )

    def gamemode_is_creative(self):
        return self.gamemode in (1, 6)

    def sync_abilities(self):
        """Send UpdateAbilitiesPacket built from *this* session's state.

        gamemode, flying and allow_flight are all per-player (allow_flight is restored
        from the save, gamemode too), so taking any of them from the server default would
        tell a restored creative player it is in survival, or a player who is currently
        flying that it is not.
        """
        self.send_packet(
            PID_UPDATE_ABILITIES,
            build_update_abilities(
                self.rid,
                gamemode=self.gamemode,
                flying=self.flying,
                allow_flight=self.allow_flight,
            ),
        )

    def head_in_water(self):
        return (
            get_block(
                math.floor(self.pos[0]),
                math.floor(self.pos[1]),
                math.floor(self.pos[2]),
            )
            == "water"
        )

    def _send_break_event(self, event_id, pos, data=0):
        self.srv.broadcast(
            [self._pk(PID_LEVEL_EVENT, build_level_event(event_id, data, pos))]
        )

    def _clear_break(self, notify=True, reason="cancelled"):
        if self.break_target is None:
            return
        pos = self.break_target
        self.break_target = None
        if notify:
            self._send_break_event(LEVEL_EVENT_BLOCK_STOP_BREAK, pos, 0)
        log(
            "World",
            "break %s at %d,%d,%d (progress %.0f%%)"
            % (reason, pos[0], pos[1], pos[2], self.break_progress * 100),
        )

    def start_break(self, pos, face):
        if not self._block_reach_ok(pos):
            return self._reject_break(pos, "out of reach")
        key = get_block(*pos)
        duration = self._break_duration(key)
        if duration is None:
            return self._reject_break(pos, "cannot break %s" % key)
        if duration == 0.0:
            return self.finish_break(pos)
        if self.break_target == tuple(pos):
            self.break_face = face
            now = time.time()
            self.break_last = now
            self.break_input = now
            return True
        if self.break_target is not None:
            self._clear_break(reason="target changed")
        self.break_target = tuple(pos)
        self.break_face = face
        self.break_started = time.time()
        self.break_last = self.break_started
        self.break_input = self.break_started
        self.break_progress = 0.0
        # SurvivalBlockBreakHandler sends the crack *speed*, not a frame index:
        # LevelEvent data = (int)(65535 * progressPerTick), progressPerTick = 1/(breakTime*20).
        self.break_speed = 1.0 / (duration * 20.0)
        self._send_break_event(
            LEVEL_EVENT_BLOCK_START_BREAK, self.break_target, self._break_fx_value()
        )
        self._break_fx = 0
        log(
            "World",
            "%s started breaking %s at %d,%d,%d (%.1fs)"
            % (self.name, key, pos[0], pos[1], pos[2], duration),
        )
        return True

    def _break_fx_value(self):
        return int(65535 * self.break_speed)

    def broadcast_arm_swing(self):
        """Player::missSwing/attackBlock: broadcast AnimatePacket::ACTION_SWING_ARM."""
        self.srv.broadcast(
            [self._pk(PID_ANIMATE, build_animate(self.rid, ANIMATE_ACTION_SWING))]
        )

    def play_punch_sound(self, key):
        """Mining feedback: LevelSoundEvent::HIT with the target block's network id (PM parity)."""
        pos = self.break_target
        self.srv.broadcast(
            [
                self._pk(
                    PID_LEVEL_SOUND_EVENT,
                    build_level_sound_event(
                        SOUND_HIT, pos, BLOCK_RUNTIME.get(key, 0) & 0xFFFFFFFF
                    ),
                )
            ]
        )
        # SurvivalBlockBreakHandler also broadcasts the arm swing every fxTickInterval.
        self.broadcast_arm_swing()

    def _reject_break(self, pos, reason):
        """Log why a break was refused, once per reason, so it is visible without DEBUG."""
        if reason not in self.seen_break_rejects:
            self.seen_break_rejects.add(reason)
            log("World", "break refused at %d,%d,%d: %s" % (pos[0], pos[1], pos[2], reason))
        return False

    def continue_break(self, pos, face):
        if self.break_target == tuple(pos):
            self.break_face = face
            # The client only keeps sending this while the button is held, so it doubles as
            # the "still breaking" heartbeat that tick_break() requires. break_last is left
            # alone so tick_break() can still integrate progress between heartbeats.
            self.break_input = time.time()
            return True
        return False

    def stop_break(self, pos):
        if pos is None or self.break_target is None:
            self._clear_break()
            return True
        if tuple(pos) != self.break_target:
            return True
        self._clear_break()
        return True

    def tick_break(self, now):
        if self.break_target is None:
            return
        if not self._block_reach_ok(self.break_target):
            self._clear_break(reason="out of reach")
            return
        key = get_block(*self.break_target)
        duration = self._break_duration(key)
        # duration <= 0 means the target is no longer something that takes time to break
        # (already replaced by air, or an instant-break block). Cancel instead of dividing.
        if duration is None:
            self._clear_break(reason="no longer breakable")
            return
        if duration <= 0.0 or get_block(*self.break_target) != key:
            self._clear_break()
            return
        # Releasing the button is handled explicitly by STOP_BREAK / ABORT_BREAK. This timeout is
        # only a safety net against a stalled client: it fires when no PlayerAuthInput and no
        # break action has arrived for a while, so a dropped packet stream cannot leave a
        # block cracking forever.
        if now - max(self.break_input, self.last_input_at) > BREAK_INPUT_TIMEOUT:
            self._clear_break()
            return
        self.break_progress = min(
            1.0, self.break_progress + max(0.0, now - self.break_last) / duration
        )
        self.break_last = now
        # SurvivalBlockBreakHandler::update punches the block every fxTickInterval (5 ticks)
        # with a sound, and only re-sends BLOCK_BREAK_SPEED when the speed actually changes.
        self._break_fx += 1
        if self._break_fx % 5 == 0 and self.break_progress < 1.0:
            self.play_punch_sound(key)
            # PM re-sends BLOCK_BREAK_SPEED whenever the break speed changes; ours is constant,
            # so refresh it periodically to keep the client's crack animation in step.
            self._send_break_event(
                LEVEL_EVENT_BLOCK_BREAK_SPEED,
                self.break_target,
                self._break_fx_value(),
            )
        if self.break_progress >= 1.0:
            pos = self.break_target
            self._clear_break(reason="finished")
            self.finish_break(pos)

    def finish_break(self, pos):
        if not self._block_reach_ok(pos):
            return False
        key = get_block(*pos)
        if key in ("air", "bedrock") or key not in BLOCK_RUNTIME:
            return False
        if self._break_duration(key) is None:
            return False
        # The block is gone either way; drop any in-progress break on it so tick_break()
        # cannot keep integrating progress against an already-replaced block.
        if self.break_target == tuple(pos):
            self._clear_break()
        ev = events.call(BlockBreakEvent(self, pos[0], pos[1], pos[2], key))
        if ev.is_cancelled:
            return False
        log("World", "%s BROKE %s at %d,%d,%d" % (self.name, key, pos[0], pos[1], pos[2]))
        self.play_sound_at(pos[0], pos[1], pos[2], block_sound(key, SOUND_BREAK), 0.8)
        return self.srv.break_block(self, pos[0], pos[1], pos[2], key)

    def teleport(self, x, y, z, yaw=None, pitch=None):
        """Player::teleport: x/y/z are the feet position. Loads the target area first, then moves the client."""
        if yaw is not None:
            self.yaw = yaw % 360
        if pitch is not None:
            self.pitch = pitch
        self._set_feet((x, y, z))
        self.fall_distance = 0.0
        self.on_ground = False
        self.center = None
        self.stream_chunks()
        while self.chunk_queue:
            self.stream_chunks()  # send the whole area before the client arrives
        self.sync_movement(self.feet(), MODE_TELEPORT)
        self.last_loc = self.loc()
        self.srv.broadcast(
            [self._pk(PID_MOVE_ACTOR_ABSOLUTE, build_move_actor_absolute(self))],
            exclude=self,
        )

    def send_publisher(self, pos):
        w = ByteWriter()
        w.write_varint32(int(pos[0])).write_varint32(int(pos[1])).write_varint32(int(pos[2]))
        w.write_varuint32(self.radius * 16).write_u32_le(0)
        self.send_packet(PID_PUBLISHER, w.get())

    def on_chunk_ready(self, cx, cz, payload):
        """Callback from background worker when a chunk is built."""
        self.chunks_in_flight.discard((cx, cz))
        if self.center is not None:
            dist_sq = (cx - self.center[0]) ** 2 + (cz - self.center[1]) ** 2
            if dist_sq > (self.radius + 2) ** 2:
                return
        self.chunk_send_queue.append((cx, cz, payload))

    def on_chunk_failed(self, cx, cz, error):
        """Callback from background worker when a chunk could not be built.

        Releases the in-flight slot queue_chunks() claimed before submitting the
        job. Without this the coord stays claimed for the rest of the session and
        queue_chunks() skips it forever, which is a permanently missing chunk.

        The coord is then queued for a delayed retry instead of being re-queued
        outright. Re-queueing outright resubmits a job that is failing for a
        reason on every chunk boundary the player crosses, forever; doing nothing
        at all leaves a hole under a player who never moves, because queue_chunks()
        only runs on a boundary crossing or a spawn. A bounded number of retries
        with a delay between them covers the transient case and then stops.
        """
        coord = (cx, cz)
        self.chunks_in_flight.discard(coord)
        attempts = self.chunk_attempts.get(coord, 0) + 1
        self.chunk_attempts[coord] = attempts
        log(
            "Worker",
            "chunk (%s, %s) build failed (attempt %d/%d): %r"
            % (cx, cz, attempts, self.CHUNK_MAX_ATTEMPTS, error),
        )
        if attempts >= self.CHUNK_MAX_ATTEMPTS:
            log("Worker", "giving up on chunk (%s, %s)" % (cx, cz))
            return
        if len(self.chunk_retries) >= self.MAX_CHUNK_RETRIES:
            return
        delay = self.CHUNK_RETRY_DELAY * (self.CHUNK_RETRY_BACKOFF ** (attempts - 1))
        self.chunk_retries.append((time.time() + delay, cx, cz))

    def _flush_chunk_retries(self):
        """Resubmit failed coords whose retry delay has elapsed.

        Runs once per tick from stream_chunks(), so a retry costs nothing while
        nothing is waiting. A coord that has meanwhile been sent, is in flight
        again, or has drifted out of range is dropped rather than resubmitted -
        it is not lost, queue_chunks() will ask for it when it comes back into
        range or the player crosses back into its chunk.
        """
        if not self.chunk_retries:
            return
        now = time.time()
        due = [entry for entry in self.chunk_retries if entry[0] <= now]
        if not due:
            return
        self.chunk_retries = [entry for entry in self.chunk_retries if entry[0] > now]
        cache = getattr(self.srv, "chunk_cache", None)
        worker_pool = getattr(self.srv, "worker_pool", None)
        for _ready_at, cx, cz in due:
            coord = (cx, cz)
            if coord in self.chunks_in_flight or coord in self.sent_chunks:
                continue
            if self.center is not None and (
                abs(cx - self.center[0]) > self.radius + 2
                or abs(cz - self.center[1]) > self.radius + 2
            ):
                continue
            self._request_chunk(cx, cz, cache, worker_pool)

    def _request_chunk(self, x, z, cache, worker_pool):
        """Put one coord into chunk_send_queue, from cache, worker or in-process."""
        cached = cache.get(x, z) if cache else None
        if cached is not None:
            self.chunk_send_queue.append((x, z, cached))
        elif worker_pool:
            self.chunks_in_flight.add((x, z))
            worker_pool.submit("CHUNK", self.rid, _build_chunk_job, x, z)
        else:
            payload = build_chunk(x, z)
            if cache:
                cache.put(x, z, payload)
            self.chunk_send_queue.append((x, z, payload))

    def queue_chunks(self):
        cx, cz = self.center
        r = self.radius
        # Attempt counts are only interesting while the coord is in range.
        # Forgetting the rest keeps the table bounded over a long session and
        # gives a coord the player has left for good a fresh set of attempts
        # when they come back, long after whatever failed has had time to clear.
        in_range = {
            (x, z)
            for x in range(cx - r - 2, cx + r + 3)
            for z in range(cz - r - 2, cz + r + 3)
        }
        for coord in [c for c in self.chunk_attempts if c not in in_range]:
            del self.chunk_attempts[coord]
        want = [
            (x, z)
            for x in range(cx - r, cx + r + 1)
            for z in range(cz - r, cz + r + 1)
            if (x, z) not in self.sent_chunks
            and (x, z) not in self.chunks_in_flight
            and self.chunk_attempts.get((x, z), 0) < self.CHUNK_MAX_ATTEMPTS
        ]
        self.chunk_queue = sorted(
            want, key=lambda c: (c[0] - cx) ** 2 + (c[1] - cz) ** 2
        )
        cache = getattr(self.srv, "chunk_cache", None)
        worker_pool = getattr(self.srv, "worker_pool", None)
        to_remove = []
        for x, z in self.chunk_queue:
            self._request_chunk(x, z, cache, worker_pool)
            to_remove.append((x, z))
        for item in to_remove:
            self.chunk_queue.remove(item)

    def stream_chunks(self):
        """Send ready-to-send chunks and monitor position for new chunk loads."""
        self._flush_chunk_retries()
        c = (math.floor(self.pos[0]) >> 4, math.floor(self.pos[2]) >> 4)
        if c != self.center:
            self.center = c
            self.send_publisher(self.pos)
            self.queue_chunks()
            keep = {
                (x, z)
                for x in range(c[0] - self.radius - 2, c[0] + self.radius + 3)
                for z in range(c[1] - self.radius - 2, c[1] + self.radius + 3)
            }
            self.sent_chunks &= keep  # chunks far away are forgotten by the client
        if self.chunk_send_queue:
            batch = self.chunk_send_queue[: config.CHUNKS_PER_TICK]
            self.chunk_send_queue = self.chunk_send_queue[config.CHUNKS_PER_TICK :]
            self.send_packets(
                [self._pk(PID_CHUNK, payload) for _x, _z, payload in batch]
            )
            self.sent_chunks.update((x, z) for x, z, _ in batch)

    def chat_to(self, msg):
        self.send_packets([self._pk(PID_TEXT, build_text(0, "", msg))])

    @staticmethod
    def _pk(pid, body):
        return ByteWriter().write_varuint32(pid).write_bytes(body).get()

    def stage1_done(self):
        self.state = "RESOURCE_PACKS"
        w = ByteWriter()
        w.write_bool(False).write_bool(False).write_bool(False)  # mustAccept, hasAddons, hasScripts
        w.write_uuid(uuid.UUID(int=0)).write_string("").write_u16_le(0)  # worldTemplate id/version, 0 packs
        self.send_packet(PID_PACKS_INFO, w.get())
        log("Bedrock", "PlayStatus(LoginSuccess) + ResourcePacksInfo (0 packs) sent")

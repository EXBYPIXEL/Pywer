"""Unit tests for PluginManager lifecycle, dependency resolution, and auto-cleanup."""

import contextlib
import io
import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import List
from unittest import mock

from pywer.command import Command, CommandManager, CommandSender
from pywer.event import (
    EventManager,
    Listener,
    listen,
    PlayerJoinEvent,
    PluginDisableEvent,
    PluginEnableEvent,
)
from pywer.plugin.base import (
    PLUGIN_API_VERSION,
    PluginBase,
    api_version_supported,
    parse_api_version,
)
from pywer.plugin.compiler import PluginCompiler
from pywer.plugin.manager import PluginManager
from pywer.scheduler import ServerScheduler


class DummyServer:
    def __init__(self):
        self.event_manager = EventManager()
        self.command_manager = CommandManager(self)
        self.scheduler = ServerScheduler(self)


class TestPluginLifecycle(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="pywer_test_lifecycle_")
        self.plugins_dir = Path(self.temp_dir) / "plugins"
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir = self.plugins_dir / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.server = DummyServer()
        self.mgr = PluginManager(self.server, self.plugins_dir, self.data_dir)

    def tearDown(self):
        self.mgr.disable_all()
        self.server.scheduler.shutdown()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_plugin_pkg(
        self,
        name: str,
        deps: List[str] = None,
        main_code: str = "",
        api_version: str = "1.0.0",
        soft_deps: List[str] = None,
    ) -> Path:
        src = Path(self.temp_dir) / f"src_{name}"
        src.mkdir(parents=True, exist_ok=True)
        manifest = {
            "name": name,
            "version": "1.0.0",
            "main": f"main:{name}",
            "api_version": api_version,
            "dependencies": deps or [],
        }
        if soft_deps is not None:
            manifest["soft_dependencies"] = soft_deps
        with open(src / "plugin.json", "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        default_code = f"""from pywer.plugin.base import PluginBase
class {name}(PluginBase):
    def __init__(self):
        super().__init__()
        self.enabled = False
        self.disabled = False
    def on_enable(self):
        self.enabled = True
    def on_disable(self):
        self.disabled = True
"""
        code = main_code or default_code
        with open(src / "main.py", "w", encoding="utf-8") as f:
            f.write(code)

        pkg_path = self.plugins_dir / f"{name}.pywer"
        return PluginCompiler.pack(src, pkg_path)

    def _create_raw_pkg(self, name: str, manifest) -> Path:
        """Write a .pywer straight to disk, bypassing the packer's own validation."""
        pkg_path = self.plugins_dir / f"{name}.pywer"
        with zipfile.ZipFile(pkg_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("plugin.json", json.dumps(manifest))
            zf.writestr("main.py", f"class {name}:\n    pass\n")
        return pkg_path

    def _load_in_glob_order(self, *pkg_files):
        """load_all_plugins() with discovery order forced rather than left to the OS.

        glob() order must not decide anything, so both orders have to give the
        same answer for the same directory.
        """
        with mock.patch.object(Path, "glob", return_value=iter(pkg_files)):
            return self.mgr.load_all_plugins()

    def test_dependency_resolution_order(self):
        # PluginA depends on PluginB
        self._create_plugin_pkg("PluginA", deps=["PluginB"])
        self._create_plugin_pkg("PluginB")

        loaded = self.mgr.load_all_plugins()
        names = [p.name for p in loaded]

        self.assertEqual(names, ["PluginB", "PluginA"])

    def test_disable_cleans_up_all_subsystems(self):
        main_code = """from pywer.plugin.base import PluginBase
from pywer.event import Listener, listen, PlayerJoinEvent
from pywer.command import Command

class ActivePlugin(PluginBase):
    def on_enable(self):
        self.join_count = 0
        self.tick_count = 0

        # Register event
        class JoinListener(Listener):
            @listen()
            def on_join(l_self, event: PlayerJoinEvent):
                self.join_count += 1

        self.register_listener(JoinListener())

        # Register command
        class TestCmd(Command):
            def __init__(self):
                super().__init__("plugincmd")
            def execute(cmd_self, sender, args):
                sender.send_message("ok")
                return True

        self.register_command(TestCmd())

        # Register repeating task
        def tick_task():
            self.tick_count += 1

        self.run_repeating(1, 1, tick_task)
"""
        pkg = self._create_plugin_pkg("ActivePlugin", main_code=main_code)
        self.mgr.load_all_plugins()
        self.mgr.enable_all()

        plugin = self.mgr.get_plugin("ActivePlugin")
        self.assertIsNotNone(plugin)
        self.assertTrue(plugin.is_enabled)

        # Verify command registered
        self.assertIsNotNone(self.server.command_manager.get_command("plugincmd"))

        # Verify event listener active
        self.server.event_manager.call(PlayerJoinEvent(None, "Hello"))
        self.assertEqual(plugin.join_count, 1)

        # Verify scheduled task ticking
        self.server.scheduler.tick()
        self.assertEqual(plugin.tick_count, 1)

        # Disable the plugin
        self.mgr.disable_plugin(plugin)
        self.assertFalse(plugin.is_enabled)

        # 1. Event listener must be detached
        self.server.event_manager.call(PlayerJoinEvent(None, "Hello again"))
        self.assertEqual(plugin.join_count, 1)  # No change

        # 2. Command must be unregistered
        self.assertIsNone(self.server.command_manager.get_command("plugincmd"))

        # 3. Scheduled task must be cancelled
        self.server.scheduler.tick()
        self.assertEqual(plugin.tick_count, 1)  # No change

    def test_enable_disable_events(self):
        fired_events = []

        class LifecycleListener(Listener):
            @listen()
            def on_enable(self, event: PluginEnableEvent):
                fired_events.append(("ENABLE", event.plugin.name))

            @listen()
            def on_disable(self, event: PluginDisableEvent):
                fired_events.append(("DISABLE", event.plugin.name))

        self.server.event_manager.register_listener(LifecycleListener())

        self._create_plugin_pkg("EventPlugin")
        self.mgr.load_all_plugins()
        self.mgr.enable_all()
        self.assertEqual(fired_events, [("ENABLE", "EventPlugin")])

        self.mgr.disable_all()
        self.assertEqual(fired_events, [("ENABLE", "EventPlugin"), ("DISABLE", "EventPlugin")])

    def test_reload_plugin(self):
        self._create_plugin_pkg("ReloadablePlugin")
        self.mgr.load_all_plugins()
        self.mgr.enable_all()

        p1 = self.mgr.get_plugin("ReloadablePlugin")
        self.assertTrue(p1.is_enabled)

        p2 = self.mgr.reload_plugin("ReloadablePlugin")
        self.assertIsNotNone(p2)
        self.assertTrue(p2.is_enabled)
        self.assertFalse(p1.is_enabled)
        self.assertIs(self.mgr.get_plugin("ReloadablePlugin"), p2)

    def test_api_version_from_a_different_major_is_refused(self):
        self._create_plugin_pkg("Future", api_version="2.0")
        self._create_plugin_pkg("Ancient", api_version="0.9")
        self.assertEqual(self.mgr.load_all_plugins(), [])
        self.assertIsNone(self.mgr.get_plugin("Future"))
        self.assertIsNone(self.mgr.get_plugin("Ancient"))

    def test_api_version_newer_than_the_server_is_refused(self):
        # This server implements PLUGIN_API_VERSION; a plugin built against a later
        # minor would call methods the server does not have.
        self._create_plugin_pkg("NeedsNewApi", api_version="1.9")
        self.assertEqual(self.mgr.load_all_plugins(), [])
        self.assertIsNone(self.mgr.get_plugin("NeedsNewApi"))

    def test_compatible_api_versions_still_load(self):
        for name, version in (("Exact", "1.0"), ("Short", "1"), ("Patched", "1.0.7")):
            self._create_plugin_pkg(name, api_version=version)
        loaded = self.mgr.load_all_plugins()
        self.assertEqual(
            sorted(p.name for p in loaded), ["Exact", "Patched", "Short"]
        )

    def test_missing_hard_dependency_refuses_the_plugin(self):
        self._create_plugin_pkg("Dependent", deps=["Ghost"])
        self.assertEqual(self.mgr.load_all_plugins(), [])
        self.assertIsNone(self.mgr.get_plugin("Dependent"))

    def test_refused_dependency_takes_its_dependents_down(self):
        self._create_plugin_pkg("BadBase", api_version="9.9")
        self._create_plugin_pkg("Layer1", deps=["BadBase"])
        self._create_plugin_pkg("Layer2", deps=["Layer1"])
        self._create_plugin_pkg("Independent")
        loaded = self.mgr.load_all_plugins()
        self.assertEqual([p.name for p in loaded], ["Independent"])

    def test_independent_plugin_still_loads_when_another_is_refused(self):
        # An unrelated package in the same directory must not be swallowed by the
        # refusal cascade above.
        self._create_plugin_pkg("Dependent", deps=["Ghost"])
        self._create_plugin_pkg("Lib")
        loaded = self.mgr.load_all_plugins()
        self.assertEqual([p.name for p in loaded], ["Lib"])

    def test_a_refusal_cannot_leak_past_a_cycle(self):
        # CycleA <-> CycleB, with CycleB also missing a hard dependency. Deciding
        # a refusal while a node was still being entered meant CycleA was checked
        # before CycleB had refused, so it loaded without the dependency it
        # declared - but only when glob() happened to hand back CycleB first.
        pkg_a = self._create_plugin_pkg("CycleA", deps=["CycleB"])
        pkg_b = self._create_raw_pkg(
            "CycleB",
            {
                "name": "CycleB",
                "version": "1.0.0",
                "main": "main:CycleB",
                "api_version": "1.0",
                "dependencies": ["CycleA", "Ghost"],
            },
        )
        for order in ((pkg_a, pkg_b), (pkg_b, pkg_a)):
            with self.subTest(discovered_as=[p.name for p in order]):
                loaded = self._load_in_glob_order(*order)
                self.assertEqual(loaded, [])
                self.assertIsNone(self.mgr.get_plugin("CycleA"))
                self.assertIsNone(self.mgr.get_plugin("CycleB"))

    def test_a_cycle_on_its_own_is_a_warning_and_both_still_load(self):
        # A cycle with nothing wrong with it is a warning, not a refusal: only the
        # missing dependency above makes its pair unservable.
        pkg_a = self._create_plugin_pkg("LoopA", deps=["LoopB"])
        pkg_b = self._create_plugin_pkg("LoopB", deps=["LoopA"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            loaded = self._load_in_glob_order(pkg_a, pkg_b)
        self.assertEqual(sorted(p.name for p in loaded), ["LoopA", "LoopB"])
        self.assertIn("Circular dependency", out.getvalue())

    def test_soft_dependency_decides_order_but_is_not_required(self):
        self._create_plugin_pkg("User", soft_deps=["Helper"])
        self._create_plugin_pkg("Helper")
        loaded = self.mgr.load_all_plugins()
        self.assertEqual([p.name for p in loaded], ["Helper", "User"])

    def test_absent_soft_dependency_does_not_refuse_the_plugin(self):
        self._create_plugin_pkg("Lone", soft_deps=["Nobody"])
        loaded = self.mgr.load_all_plugins()
        self.assertEqual([p.name for p in loaded], ["Lone"])

    def test_refused_soft_dependency_still_loads_its_dependent(self):
        self._create_plugin_pkg("BadHelper", api_version="9.9")
        self._create_plugin_pkg("User", soft_deps=["BadHelper"])
        loaded = self.mgr.load_all_plugins()
        self.assertEqual([p.name for p in loaded], ["User"])
        self.assertIsNone(self.mgr.get_plugin("BadHelper"))

    def test_manifest_the_packer_would_reject_is_refused_at_load(self):
        # PluginCompiler.inspect reads a .pywer without validating it, so these are
        # written directly: a hand-made or corrupt package reaching load time must
        # be refused instead of being handed to the loader.
        self._create_raw_pkg(
            "NoVersion",
            {"name": "NoVersion", "main": "main:NoVersion", "api_version": "1.0"},
        )
        self._create_raw_pkg(
            "BadMain",
            {"name": "BadMain", "version": "1.0.0", "main": "main", "api_version": "1.0"},
        )
        self._create_raw_pkg(
            "BadDeps",
            {
                "name": "BadDeps",
                "version": "1.0.0",
                "main": "main:BadDeps",
                "api_version": "1.0",
                "dependencies": "PluginB",
            },
        )
        self.assertEqual(self.mgr.load_all_plugins(), [])

    def test_a_manifest_without_a_name_is_refused_by_the_manifest_checks(self):
        # This used to raise KeyError on manifest_data["name"] and be reported as
        # an unreadable package, which also kept _manifest_error - the one place
        # that formats refusals - from ever producing its reason.
        self._create_raw_pkg(
            "Nameless",
            {"version": "1.0.0", "main": "main:Nameless", "api_version": "1.0"},
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            loaded = self.mgr.load_all_plugins()
        self.assertEqual(loaded, [])
        message = out.getvalue()
        self.assertIn("Nameless.pywer", message)
        self.assertIn("missing required field 'name'", message)
        self.assertNotIn("Failed to read package", message)

    def test_a_manifest_whose_json_is_not_an_object_is_refused(self):
        # PluginCompiler.inspect returns whatever JSON parses to, so a package
        # whose plugin.json is a list reaches discovery with nothing to index.
        self._create_raw_pkg("NotAnObject", ["not", "a", "dict"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            loaded = self.mgr.load_all_plugins()
        self.assertEqual(loaded, [])
        self.assertIn("not a plugin.json object", out.getvalue())

    def test_a_second_package_cannot_take_a_name_that_is_already_taken(self):
        # Two packages claiming one name used to overwrite each other silently,
        # so which file the loader actually opened came down to glob() order.
        self._create_plugin_pkg("Twin")
        self._create_raw_pkg(
            "TwinOther",
            {"name": "Twin", "version": "1.0.0", "main": "main:Twin", "api_version": "1.0"},
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            loaded = self.mgr.load_all_plugins()
        self.assertEqual([p.name for p in loaded], ["Twin"])
        self.assertIn("already provided by 'Twin.pywer'", out.getvalue())

    def test_a_manifest_with_a_negative_api_version_is_refused(self):
        # int() takes "1.-1", and (1, -1) then passes the minor <= server minor
        # test, so the manifest walked straight through the version gate.
        self._create_plugin_pkg("Sneaky", api_version="1.-1")
        self.assertEqual(self.mgr.load_all_plugins(), [])
        self.assertIsNone(self.mgr.get_plugin("Sneaky"))


class TestApiVersionCompatibility(unittest.TestCase):
    def test_parse_accepts_the_shapes_manifests_actually_carry(self):
        self.assertEqual(parse_api_version("1.2.3"), (1, 2))
        self.assertEqual(parse_api_version("1.2"), (1, 2))
        self.assertEqual(parse_api_version("1"), (1, 0))
        self.assertEqual(parse_api_version(" 1.0 "), (1, 0))

    def test_parse_rejects_anything_unusable(self):
        for bad in ("", "abc", "1.x", None, 3, [], " "):
            self.assertIsNone(parse_api_version(bad), bad)

    def test_a_negative_segment_is_not_a_version(self):
        # Version numbers are non-negative. Before this was checked, "1.-1"
        # parsed to (1, -1) and then satisfied `minor <= server minor`.
        for bad in ("1.-1", "-1.0", "0.-2"):
            self.assertIsNone(parse_api_version(bad), bad)
            self.assertFalse(api_version_supported(bad), bad)

    def test_supported_requires_an_equal_major_and_an_older_or_equal_minor(self):
        for good in ("1.0", "1", "1.0.0", "1.0.7"):
            self.assertTrue(api_version_supported(good), good)
        for bad in ("1.1", "2.0", "0.9", "nope", None):
            self.assertFalse(api_version_supported(bad), bad)

    def test_the_constant_this_all_measures_against_is_usable(self):
        self.assertIsNotNone(parse_api_version(PLUGIN_API_VERSION))


if __name__ == "__main__":
    unittest.main()

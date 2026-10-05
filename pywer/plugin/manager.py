"""PluginManager handles scanning, topological dependency loading, lifecycle, and auto-cleanup."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from ..event.server import PluginDisableEvent, PluginEnableEvent
from .base import PLUGIN_API_VERSION, PluginBase, api_version_supported
from .compiler import PluginCompiler
from .loader import VirtualPluginLoader


def _manifest_error(manifest: Dict[str, Any]) -> Optional[str]:
    """Load-time manifest checks, or None when the manifest is usable.

    The packer enforces all of this, but ``PluginCompiler.inspect`` reads an
    already-built .pywer without validating it, so a hand-made or corrupt package
    reaches this point carrying a manifest the loader cannot honour. Every problem
    is a refusal reason rather than an exception: one bad package must not stop the
    others from loading.
    """
    for req in PluginCompiler.REQUIRED_FIELDS:
        if not manifest.get(req):
            return f"missing required field '{req}'"
    if not isinstance(manifest.get("name"), str):
        return "field 'name' must be a string"
    if ":" not in str(manifest["main"]):
        return "field 'main' must be in format 'module_name:ClassName'"
    if not api_version_supported(manifest.get("api_version")):
        return (
            f"requires plugin API {manifest.get('api_version')!r}, "
            f"this server implements {PLUGIN_API_VERSION}"
        )
    for key in ("dependencies", "soft_dependencies"):
        raw = manifest.get(key, [])
        if not isinstance(raw, list) or not all(isinstance(d, str) for d in raw):
            return f"field '{key}' must be a list of plugin names"
    return None


def _dependency_names(manifest: Dict[str, Any], key: str) -> List[str]:
    """The manifest's dependency names for ``key``; absent or malformed reads as none."""
    raw = manifest.get(key, [])
    if not isinstance(raw, list):
        return []
    return [d for d in raw if isinstance(d, str)]


class PluginManager:
    """Manages the full lifecycle of plugins, dependency resolution, and state isolation."""

    def __init__(
        self,
        server: Any,
        plugins_dir: Union[str, Path],
        data_dir: Union[str, Path],
    ) -> None:
        self.server = server
        self.plugins_dir = Path(plugins_dir).resolve()
        self.data_dir = Path(data_dir).resolve()
        self.plugins: Dict[str, PluginBase] = {}
        self._plugin_paths: Dict[str, Path] = {}

    def get_plugin(self, name: str) -> Optional[PluginBase]:
        """Retrieves a loaded plugin instance by its registered name."""
        return self.plugins.get(name)

    def load_all_plugins(self) -> List[PluginBase]:
        """Discovers, topologically sorts, and virtually loads all .pywer packages."""
        if not self.plugins_dir.exists():
            self.plugins_dir.mkdir(parents=True, exist_ok=True)
            return []

        # 1. Discover all .pywer packages and inspect manifests
        discovered: Dict[str, Dict[str, Any]] = {}
        file_map: Dict[str, Path] = {}

        # Sorted because the directory listing differs by filesystem and must not
        # decide anything on its own - starting with which of two packages that
        # claim one name is the one that gets loaded.
        for pkg_file in sorted(self.plugins_dir.glob("*.pywer")):
            try:
                manifest_data = PluginCompiler.inspect(pkg_file)
            except Exception as e:
                print(f"[ERROR] [Plugin] Failed to read package '{pkg_file.name}': {e}")
                continue
            name = manifest_data.get("name") if isinstance(manifest_data, dict) else None
            if not isinstance(name, str) or not name:
                # manifest_data["name"] used to be read directly, so a package
                # without a usable name raised KeyError and landed in the message
                # above as an unreadable file - which also kept _manifest_error,
                # the one place that formats refusals, from ever seeing it.
                reason = (
                    _manifest_error(manifest_data)
                    if isinstance(manifest_data, dict)
                    else None
                )
                print(
                    f"[ERROR] [Plugin] Skipped '{pkg_file.name}': "
                    f"{reason or 'manifest is not a plugin.json object'}"
                )
                continue
            if name in discovered:
                print(
                    f"[ERROR] [Plugin] Skipped '{pkg_file.name}': name '{name}' "
                    f"is already provided by '{file_map[name].name}'"
                )
                continue
            discovered[name] = manifest_data
            file_map[name] = pkg_file

        # 2. Refuse anything this server cannot serve, then order what is left.
        #    A refusal on a hard dependency takes its dependents down with it;
        #    soft dependencies only decide order and never take a plugin down.
        skipped: Dict[str, str] = {}
        for p_name, manifest in discovered.items():
            problem = _manifest_error(manifest)
            if problem:
                skipped[p_name] = problem

        load_order: List[str] = []
        visited: Set[str] = set()
        visiting: Set[str] = set()

        def visit(p_name: str) -> None:
            if p_name in visiting:
                print(f"[WARN] [Plugin] Circular dependency detected involving '{p_name}'.")
                return
            if p_name in visited:
                return
            visiting.add(p_name)

            manifest = discovered[p_name]
            hard = _dependency_names(manifest, "dependencies")
            soft = _dependency_names(manifest, "soft_dependencies")
            # Walk dependencies first so that whatever is loadable is loadable
            # before its dependents. Nothing is decided here - see below.
            for dep in hard + soft:
                if dep in discovered:
                    visit(dep)

            visiting.remove(p_name)
            visited.add(p_name)
            load_order.append(p_name)

        for p_name in list(discovered.keys()):
            if p_name not in visited:
                visit(p_name)

        # Refusals are decided in one pass over the finished order rather than
        # inside the walk above. Deciding them while a node was still being
        # entered made the answer depend on where the walk started: around a
        # cycle A -> B -> A where B also lacks a hard dependency, A was checked
        # before B had refused, so A loaded without B - and whether it did came
        # down to the order glob() happened to return the files in. Sweeping to a
        # fixed point gives one answer for every discovery order. Monotone: a
        # name only ever enters skipped, so this terminates.
        changed = True
        while changed:
            changed = False
            for p_name in load_order:
                if p_name in skipped:
                    continue
                for dep in _dependency_names(discovered[p_name], "dependencies"):
                    if dep not in discovered:
                        reason = f"missing hard dependency '{dep}'"
                    elif dep in skipped:
                        reason = f"dependency '{dep}' was skipped: {skipped[dep]}"
                    else:
                        continue
                    skipped[p_name] = reason
                    changed = True
                    break

        # 3. Virtual load each plugin in dependency order
        loaded: List[PluginBase] = []
        for p_name in load_order:
            reason = skipped.get(p_name)
            if reason:
                print(f"[ERROR] [Plugin] Skipped '{p_name}': {reason}")
                continue
            pkg_path = file_map[p_name]
            try:
                plugin = VirtualPluginLoader.load_plugin(
                    pkg_path, self.server, self.data_dir
                )
                self.plugins[p_name] = plugin
                self._plugin_paths[p_name] = pkg_path
                loaded.append(plugin)
                print(f"[INFO] [Plugin] Loaded '{plugin.name}' v{plugin.version}.")
            except Exception as e:
                print(f"[ERROR] [Plugin] Failed to load plugin '{p_name}': {e}")

        return loaded

    def enable_plugin(self, plugin: PluginBase) -> bool:
        """Enables a loaded plugin and dispatches PluginEnableEvent."""
        if plugin.is_enabled:
            return True

        plugin._is_enabled = True

        try:
            plugin.on_enable()
        except Exception as e:
            plugin.logger.error(f"Exception during on_enable(): {e!r}")

        # Dispatch enable event
        if hasattr(self.server, "event_manager") and self.server.event_manager:
            self.server.event_manager.call(PluginEnableEvent(plugin))

        return True

    def disable_plugin(self, plugin: PluginBase) -> bool:
        """Disables a plugin, cleans up events, commands, and scheduler tasks."""
        if not plugin.is_enabled:
            return True

        # Dispatch disable event first
        if hasattr(self.server, "event_manager") and self.server.event_manager:
            self.server.event_manager.call(PluginDisableEvent(plugin))

        try:
            plugin.on_disable()
        except Exception as e:
            plugin.logger.error(f"Exception during on_disable(): {e!r}")

        # Comprehensive auto-cleanup:
        # 1. Unregister event listeners
        if hasattr(self.server, "event_manager") and self.server.event_manager:
            self.server.event_manager.unregister_by_plugin(plugin)

        # 2. Unregister commands
        if hasattr(self.server, "command_manager") and self.server.command_manager:
            self.server.command_manager.unregister_by_plugin(plugin)

        # 3. Cancel scheduled tasks
        if hasattr(self.server, "scheduler") and self.server.scheduler:
            self.server.scheduler.cancel_by_plugin(plugin)

        plugin._is_enabled = False
        return True

    def reload_plugin(self, name: str) -> Optional[PluginBase]:
        """Safely disables, reloads virtual modules from .pywer, and re-enables a plugin."""
        plugin = self.plugins.get(name)
        pkg_path = self._plugin_paths.get(name)
        if not plugin or not pkg_path:
            return None

        self.disable_plugin(plugin)

        try:
            new_plugin = VirtualPluginLoader.load_plugin(
                pkg_path, self.server, self.data_dir
            )
            self.plugins[name] = new_plugin
            self.enable_plugin(new_plugin)
            print(f"[INFO] [Plugin] Reloaded '{name}' v{new_plugin.version}.")
            return new_plugin
        except Exception as e:
            print(f"[ERROR] [Plugin] Failed to reload plugin '{name}': {e}")
            return None

    def enable_all(self) -> None:
        """Enables all loaded plugins in load order."""
        for plugin in list(self.plugins.values()):
            self.enable_plugin(plugin)

    def disable_all(self) -> None:
        """Disables all plugins in reverse dependency order."""
        for plugin in reversed(list(self.plugins.values())):
            self.disable_plugin(plugin)

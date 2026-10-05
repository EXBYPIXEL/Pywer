"""Pywer Plugin Architecture.

Provides packaging, virtual in-memory loading, lifecycle management,
and runtime APIs for Bedrock server plugins.
"""

from .base import (
    PLUGIN_API_VERSION,
    PluginBase,
    PluginConfig,
    PluginLogger,
    PluginManifest,
    api_version_supported,
    parse_api_version,
)
from .compiler import PluginCompileError, PluginCompiler
from .loader import PywerZipFinder, PywerZipLoader, VirtualPluginLoader
from .manager import PluginManager

__all__ = [
    "PLUGIN_API_VERSION",
    "PluginBase",
    "PluginConfig",
    "PluginLogger",
    "PluginManifest",
    "PluginCompileError",
    "PluginCompiler",
    "PywerZipFinder",
    "PywerZipLoader",
    "VirtualPluginLoader",
    "PluginManager",
    "api_version_supported",
    "parse_api_version",
]

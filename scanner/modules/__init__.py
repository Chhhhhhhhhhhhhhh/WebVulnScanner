"""Module registry — maps CLI ids to module classes."""

from __future__ import annotations

from .base import BaseModule  # noqa: F401  (re-exported for module authors)
from .cmdi import CmdiModule
from .cors import CorsModule
from .domxss import DomXssModule
from .fingerprint import FingerprintModule
from .headers import HeadersModule
from .lfi import LfiModule
from .redirect import RedirectModule
from .sensitive import SensitiveModule
from .sqli import SqliModule
from .ssti import SstiModule
from .timing import TimingModule
from .xss import XssModule

MODULES = {
    HeadersModule.id: HeadersModule,
    FingerprintModule.id: FingerprintModule,
    SensitiveModule.id: SensitiveModule,
    SqliModule.id: SqliModule,
    XssModule.id: XssModule,
    CmdiModule.id: CmdiModule,
    LfiModule.id: LfiModule,
    RedirectModule.id: RedirectModule,
    CorsModule.id: CorsModule,
    SstiModule.id: SstiModule,
    # opt-in modules: slower or require extra setup, never in the default set
    TimingModule.id: TimingModule,
    DomXssModule.id: DomXssModule,
}

# Modules that run when the user does not select any explicitly.
DEFAULT_MODULES = [m for m in MODULES if m not in (TimingModule.id, DomXssModule.id)]


def resolve_modules(module_ids: list) -> list:
    """Return module classes for the requested ids; raises ValueError on unknown ids.

    Order follows the registry (including opt-in modules), regardless of
    the order the user listed them in."""
    unknown = [m for m in module_ids if m not in MODULES]
    if unknown:
        raise ValueError(
            f"unknown module(s): {', '.join(unknown)}. Valid modules: {', '.join(MODULES)}"
        )
    return [MODULES[m] for m in MODULES if m in module_ids]

"""API v1 router composition.

Domain routers register themselves by convention: any package under
`app.modules` exposing `router.py:router` is mounted automatically. This keeps
domains independently evolvable and avoids a merge-conflict-prone central file.
"""

from __future__ import annotations

import importlib
import pkgutil

from fastapi import APIRouter

from app.core.logging import get_logger

logger = get_logger("hispanshield.router")

api_router = APIRouter()

_MOUNTED: list[str] = []


def _mount_domain_routers() -> None:
    import app.modules as modules_package

    for module_info in sorted(pkgutil.iter_modules(modules_package.__path__), key=lambda item: item.name):
        name = module_info.name
        if name.startswith("_"):
            continue
        router_module = f"app.modules.{name}.router"
        try:
            module = importlib.import_module(router_module)
        except ModuleNotFoundError as exc:
            if exc.name == router_module:
                continue
            raise
        router = getattr(module, "router", None)
        if router is None:
            continue
        api_router.include_router(router)
        _MOUNTED.append(name)


_mount_domain_routers()


@api_router.get("/meta/domains", tags=["Operations"], summary="Mounted domain modules")
def list_domains() -> dict:
    return {"domains": _MOUNTED, "count": len(_MOUNTED)}

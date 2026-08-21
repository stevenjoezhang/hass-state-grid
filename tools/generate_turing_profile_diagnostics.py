#!/usr/bin/env python3
"""Generate a private, policy-aware Turing profile JSON for inspection."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CUSTOM_COMPONENTS = ROOT / "custom_components"
PACKAGE = CUSTOM_COMPONENTS / "state_grid"

custom_components = types.ModuleType("custom_components")
custom_components.__path__ = [str(CUSTOM_COMPONENTS)]
sys.modules.setdefault("custom_components", custom_components)

state_grid = types.ModuleType("custom_components.state_grid")
state_grid.__path__ = [str(PACKAGE)]
sys.modules.setdefault("custom_components.state_grid", state_grid)

from custom_components.state_grid.turing.feature_profile import (  # noqa: E402
    StableProfile,
)
from custom_components.state_grid.turing.profile_diagnostics import (  # noqa: E402
    build_profile_diagnostics,
)


def write_private(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(document, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    os.replace(temporary, path)
    path.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output", type=Path, default=ROOT / "sgcc_device_profile.json"
    )
    parser.add_argument("--timestamp-ms", type=int)
    parser.add_argument("--boot-epoch-ms", type=int)
    parser.add_argument("--install-epoch-ms", type=int)
    parser.add_argument("--redacted", action="store_true")
    args = parser.parse_args()
    timestamp_ms = args.timestamp_ms or int(time.time() * 1000)
    boot_epoch_ms = args.boot_epoch_ms or timestamp_ms - 86_400_000
    profile = StableProfile(
        bytes(range(32)),
        boot_epoch_ms=boot_epoch_ms,
        install_epoch_ms=args.install_epoch_ms,
    )
    document = build_profile_diagnostics(
        profile,
        timestamp_ms=timestamp_ms,
        include_values=not args.redacted,
    )
    write_private(args.output, document)
    print(json.dumps(document["summary"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Local simulation of what the workflow does: verify -> execute -> summary."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bridge import payload


def main() -> int:
    key = os.environ["BRIDGE_KEY"]
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'echo hello\necho "second line"'
    request = payload.build_request(cmd, key, callback="https://example.test/cb")
    env = {
        "BRIDGE_VERSION": request["v"],
        "BRIDGE_TS": str(request["ts"]),
        "BRIDGE_NONCE": request["nonce"],
        "BRIDGE_CMD_B64": request["cmd_b64"],
        "BRIDGE_CALLBACK": request["callback"],
        "BRIDGE_SIG": request["sig"],
    }
    print(json.dumps(env))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Independent, public-only semantic observation vectors; no Rust codec imports."""
from hashlib import sha256
from pathlib import Path
from struct import pack

ROOT = Path(__file__).parent
PAYLOAD = ROOT.parent / "cloud-payload-v1"


def field(value):
    return pack(">I", len(value)) + value


def text(value):
    return field(value.encode())


def optional(value):
    return b"\x00" if value is None else b"\x01" + pack(">Q", value)


def command_body(name, kind):
    raw = bytes.fromhex((PAYLOAD / f"{name}.hex").read_text())
    label = b"nocterm/cloud-command-payload/v1"
    prefix = field(label) + pack(">H", kind)
    assert raw.startswith(prefix)
    return raw[len(prefix):]


RUN = bytes([0x21]) * 16 + pack(">Q", 2)
APPROVAL = command_body("approval", 3)
# The exact public approval body, with this observation's original run.
APPROVAL = APPROVAL[:48] + RUN + APPROVAL[72:]
EXECUTION = APPROVAL[48:-1]
ARGS = bytes.fromhex((PAYLOAD / "tool-list.hex").read_text())
COMMAND = (bytes([3]) * 16 + pack(">H", 1) + bytes([4]) * 32
           + text("device") + bytes([5]) * 32 + bytes([6]) * 32 + pack(">Q", 7))
DISPLAY = text("list_terminals") + text("{}") + b"\x00\x00\x01"
INTENT = (bytes([8]) * 16 + bytes([9]) * 16 + EXECUTION + sha256(ARGS).digest()
          + b"\x00" + field(ARGS) + DISPLAY)
JOB = bytes([8]) * 16 + EXECUTION + text("original-terminal") + text("original-job") + b"\x00"


def event(tag, body, index):
    return (field(b"nocterm/cloud-event-payload/v1") + pack(">QQ", 8 + index // 3, 100_000 + index)
            + bytes([tag]) + body)


SESSION = EXECUTION[24:-24]
TARGET = SESSION[24:]
ACCEPTED_PROMPT = (text("openai") + text("model") + text("pricing") + b"\x01" + TARGET
                   + b"\x01" + SESSION + pack(">H", 2) + b"\x01" + text("public fixture prompt")
                   + b"\x02\x01" + field(b"public image fixture"))
BACKGROUND = JOB + bytes([9]) * 16 + sha256(ARGS).digest() + b"\x00" + pack(">QQ", 1, 3)
BODIES = [
    COMMAND + b"\x01" + RUN,
    COMMAND + RUN + ACCEPTED_PROMPT,
    RUN + b"\x03",
    RUN + b"\x01" + bytes([9]) * 16 + b"\x02" + text("sensitive-text"),
    RUN + optional(None) + optional(0) + optional(None) * 4,
    INTENT,
    INTENT + pack(">Q", 200_000),
    bytes([10]) * 16 + APPROVAL,
    RUN + bytes([8]) * 16 + text("[]") + DISPLAY + b"\x03" + JOB + b"\x00",
    bytes([11]) * 16,
    BACKGROUND + b"\x01",
]
NAMES = ["command", "prompt", "status", "text", "usage", "intent", "approval", "answer", "result", "deleted", "background-retained"]
EVENTS = [event(index + 1, body, index) for index, body in enumerate(BODIES)]
VECTORS = dict(zip(NAMES, EVENTS))
VECTORS["background-exit-zero"] = event(11, BACKGROUND + b"\x02" + pack(">I", 0), 10)
VECTORS["background-exit-failed"] = event(11, BACKGROUND + b"\x02" + pack(">I", 7), 10)
VECTORS["background-unknown"] = event(11, BACKGROUND + b"\x03", 10)
VECTORS["snapshot"] = (field(b"nocterm/cloud-snapshot-payload/v1") + pack(">QQ", 12, 200_000)
                       + b"\x01" + pack(">I", len(EVENTS)) + b"".join(EVENTS))

if __name__ == "__main__":
    for name, raw in VECTORS.items():
        (ROOT / f"{name}.hex").write_text(raw.hex() + "\n")
    print(f"Generated {len(EVENTS)} public event vectors and one snapshot")

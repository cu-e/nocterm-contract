# Semantic Cloud observations, version 1

`generate.py` uses Python's standard library and the public command/argument
vectors in `cloud-payload-v1`. It imports no Rust codec or native implementation.
Every `.hex` file is a complete canonical event body; `snapshot.hex` is a complete
bounded display snapshot including all eleven event kinds.

All integers are unsigned big endian. A field has a u32 byte length; an event
starts with the field `nocterm/cloud-event-payload/v1`, u64 control revision,
u64 original publication time and a closed one-byte semantic tag. A snapshot
starts with `nocterm/cloud-snapshot-payload/v1`, its u64 control/time head,
a strict 0/1 omitted-history flag, u32 count and complete event bodies.

Tags 1–11 are accepted-command, accepted-prompt, status, text, usage, tool-intent,
approval, resolved-approval, tool-result deletion and original background lifecycle. Existing command payload
sub-layouts and exact tool-argument bytes are reused. This is public display data,
not a native checkpoint, execution grant or private journal representation.

Run `python3 fixtures/cloud-events-v1/generate.py` from the repository root.
The hub-model tests compare both directions with the checked-in bytes. Altered
tags/options, truncated or suffixed bodies, invalid argument digests, mismatched
background run/intent and regressing snapshot heads are rejected separately.

Accepted-prompt body2 carries only model/optional target/session and bounded
content. It has no inference limits; the SubmitPrompt command layout is unchanged.
Background body11 is the existing BackgroundJob sub-layout followed by step16,
arguments-digest32, strict mutation0/1, positive dispatch-writer/revision u64s,
and outcome tag1 Retained, tag2 plus u32 actual exit, or tag3 Unknown. Its outer
record uses the original execution run while the current writer can differ.
The four background files separately pin all outcomes, including exit0 versus7.

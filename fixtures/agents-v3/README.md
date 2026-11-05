# Definition model edit vector

`model-edit.hex` is a recorded format 3 model edit, including the public flat manifest,
one complete format 2 base and the encrypted latest model set. It opens with these test-only
coordinates:

- Owner X25519 seed: 32 bytes of `11` hex.
- Pool X25519 seed: 32 bytes of `22` hex.
- Agent UUID: `33333333-3333-3333-3333-333333333333`.
- Scope: account.
- Pool UUID: `44444444-4444-4444-4444-444444444444`.
- Original complete definition version: 1; edited definition version: 7.
- Original fields: `keys::agents::definition_v2::sample_v2`; latest models: `gpt`, `second`.

Every seed and secret in this fixture is artificial. The ignored `write_model_edit_fixture`
test records fresh nonces and ephemeral keys when a format change deliberately needs a new
vector. The ordinary golden test opens the recorded bytes under the exact original context
and compares every resolved field. Repeated edits must retain only this complete base and
the latest model set, rather than growing a chain.

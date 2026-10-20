# New-machine first WD2 activation: captured chain

Run: `captures/20261022T132423.573463Z/` (private, gitignored).
The user reported reaching the game; no more specific gameplay result was recorded here.

Offline checks of saved metadata/binary payloads, without printing tokens:

- Activation-cache directory was absent at run baseline.
- Aux pipe `terminal_3_uplay_aux_ipc_pipe_` read sequence 873 contained a
  357-byte request, with a 340-byte base64 request token (253 decoded bytes).
- That exact request token occurs in the captured outgoing BCrypt plaintext stream
  of launcher PID 16756 (grouped by PID and CNG key handle).
- The newly captured activation-cache snapshot is 1592 bytes and contains a
  1576-byte base64 activation token (1180 decoded bytes).
- That exact activation token occurs in the captured incoming BCrypt plaintext
  stream of launcher PID 16756.
- That exact activation token also occurs in the 1597-byte launcher aux-pipe write,
  sequence 896, PID 16756.

Thus both the game request token and server-issued answer were retained across
launcher transport and the game-facing aux channel. This is stronger evidence than
cache creation alone. Those capture-only checks did not by themselves explain the
protocol or prove an independent launch. Subsequent work implemented live issuance
and achieved a user-confirmed launch with PoC login and generated IPC; see
[docs/09-fresh-activation.md](../docs/09-fresh-activation.md) and
[docs/10-denuvo.md](../docs/10-denuvo.md). The capture coverage
limitations below still apply; the later success does not repair missing events.

## Coverage limitations

Not everything was captured. The latest health for worker PID 3308 reported 318000
dropped events; launcher PID 16756 reported zero dropped events/send errors in the
checked health records. Four worker process instances were attached and exited.
At the first post-launch check there were seven explicit pipe gaps (four closed
before completion, three expired pending reads). These are coverage gaps, not
successful capture. Worker startup polling, allowlisted-pipe-only coverage, CNG-only
plaintext interception and other limits remain applicable.

The download phase was captured in earlier run `20261022T121210.389795Z/`; a Frida
pipe feedback incident interrupted continuity before this launch run. Capture was
not uninterrupted from download through launch. Old captures and token files are not safe
to publish and were not deleted or overwritten by these verification steps.

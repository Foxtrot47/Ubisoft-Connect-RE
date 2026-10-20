# Current-machine WD2 first-install capture

Collector: `activation_capture.py`; hooks: `activation_capture.js`.

A synthetic self-test passed for byte-exact BCrypt encryption input, decryption
output, synchronous named-pipe write input and read output. The first self-test
failed because its marker was 17 bytes while the AES operation used 16; the marker
was corrected and the test rerun successfully. This does not validate all launcher
execution paths.

Live run: `captures/20261022T121210.389795Z/`, collector PID 15708 at startup.
The official launcher was absent, then spawned suspended, instrumented and resumed.
Initial health: all required hooks installed, 0 capture errors, actual CNG traffic
and pipe creation observed. The destination activation-cache directory was absent
before launcher startup. No game was downloaded or launched by this collector.

Files (sensitive, gitignored):

- `events.jsonl`: timestamps, process/thread identity, sequence, hook lifecycle,
  CNG key-handle correlation (not key bytes), payload offsets/lengths/SHA256.
- `payloads.bin`: full captured buffers, no text/hex truncation.
- `status.json`: metadata-only live health; safe to inspect without printing tokens.
- Activation-cache changes: captured as binary records, with stable-read checks.

Keep running through download, installation, first launch, activation, user-confirmed
menu/gameplay, and game exit. Mark phase times. Do not print payloads or attach hooks
to the game/anti-cheat process. Do not delete caches or reuse old-machine activation
artifacts. Do not infer a fresh activation from cache existence alone.

Stop gracefully only after the test: create an empty `STOP` file inside the live
run directory. The collector detaches and flushes outputs. The official client
continues running. This does not terminate the client or game.

## Coverage limits

This is not literally an all-system capture. It covers BCrypt plaintext and selected
launcher-side pipe APIs. No Schannel/other TLS-library plaintext, IOCP/completion-
routine pipe completions, game-side internals, or packet capture is included.
GetOverlappedResult is hooked, but other completion mechanisms are not. Pending
pipe I/O is reported in health. Independently started launcher/service processes
are polled every 200 ms, so early worker traffic can be missed; elevated workers
may reject attachment. Cache polling can miss short-lived intermediate versions.
Frida/target failure, disk pressure and uninstrumented code paths remain possible.
Review live health and attach-error records before game launch. Retain these limits
when describing evidence; a running collector is not proof of complete capture.

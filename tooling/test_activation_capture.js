'use strict';
// Offline regression tests: never attaches to a launcher.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
let receiver;
let heartbeat;
const sent = [];
let copies = 0;
let reenter = false;
const context = vm.createContext({
  Process: {id: 1, getCurrentThreadId: () => 1, findModuleByName: () => null,
    attachModuleObserver() {}},
  recv(type, callback) { assert.equal(type, 'capture-ack'); receiver = callback; },
  send(metadata, data) {
    sent.push({metadata, size: data ? data.byteLength : 0});
    if (reenter) vm.runInContext("event('recursive-send')", context);
  },
  setInterval(callback) { heartbeat = callback; },
});
vm.runInContext(fs.readFileSync(require('node:path').join(__dirname, 'activation_capture.js'), 'utf8'), context);
function evaluate(source) { return vm.runInContext(source, context); }
for (const name of [String.raw`\\.\pipe\terminal_1_uplay_ipc`, String.raw`\\.\pipe\terminal_3_uplay_service_ipc_pipe_`,
  String.raw`\\.\pipe\activation_capture_test_1`]) {
  context.name = name;
  assert.equal(evaluate('allowedPipe(name)'), true, name);
}
for (const name of [String.raw`\\.\pipe\frida-abc`, String.raw`\\.\pipe\mojo-abc`,
  'preexisting-pipe:0x100', String.raw`C:\terminal_1_other`, String.raw`\\.\pipe\unrelated`]) {
  context.name = name;
  assert.equal(evaluate('allowedPipe(name)'), false, name);
}
// A stalled writer must not let the JS->host transport queue grow without bound.
evaluate("for (let i = 0; i < 100000; i++) event('burst')");
assert.equal(sent.length, 128);
assert.equal(evaluate('inflight.size'), 128);
assert.equal(evaluate('counts.dropped_events'), 100000 - 128);
for (const item of sent) receiver({payload: {sequence: item.metadata.sequence}});
assert.equal(evaluate('inflight.size'), 0);
sent.length = 0;
context.bufferPointer = {isNull: () => false, readByteArray(n) { copies++; return new ArrayBuffer(n); }};
evaluate("for (let i = 0; i < 100; i++) bytes('payload', bufferPointer, 1024 * 1024)");
assert.equal(copies, 8);
assert.equal(evaluate('inflightBytes'), 8 * 1024 * 1024);
// No source-buffer copy is made when the transport budget is exhausted.
evaluate("bytes('payload', bufferPointer, 16)");
assert.equal(copies, 8);
for (const item of sent) receiver({payload: {sequence: item.metadata.sequence}});
assert.equal(evaluate('inflightBytes'), 0);
sent.length = 0;
evaluate("bytes('payload', bufferPointer, 1024 * 1024 + 1)");
assert.equal(copies, 8);
assert.equal(sent[0].metadata.kind, 'gap');
assert.equal(sent[0].metadata.reason, 'invalid-or-oversize');
receiver({payload: {sequence: sent[0].metadata.sequence}});
reenter = true;
const before = sent.length;
evaluate("event('outer-send')");
assert.equal(sent.length, before + 1);
reenter = false;
for (const item of sent) receiver({payload: {sequence: item.metadata.sequence}});
// Pending metadata cannot grow indefinitely when completions never arrive.
evaluate("for (let i = 0; i < 10000; i++) trackPending(String(i), {operation: 'ReadFile', handle: 'h'})");
assert.equal(evaluate('pending.size'), 1024);
evaluate('for (const item of pending.values()) item.created = 0');
heartbeat();
assert.equal(evaluate('pending.size'), 0);
console.log('PASS: pipe allowlist, 100k-event backpressure, byte budget, ACK release, oversize gap, reentrancy, pending cap/expiry');

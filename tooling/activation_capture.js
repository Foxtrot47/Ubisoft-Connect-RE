// Passive launcher-side capture. No patches, key extraction, or game injection.
'use strict';
const hooks = new Set();
const pipes = new Map();
const pending = new Map();
const counts = {};
let sequence = 0;
const MAX_MESSAGES = 128;
const MAX_INFLIGHT_BYTES = 8 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 1024 * 1024;
const MAX_PENDING = 1024;
const MAX_PIPES = 1024;
const inflight = new Map();
let inflightBytes = 0;
let sending = false;
function acknowledge(message) {
  const id = message.payload && message.payload.sequence;
  if (inflight.has(id)) {
    inflightBytes -= inflight.get(id);
    inflight.delete(id);
  }
  recv('capture-ack', acknowledge);
}
recv('capture-ack', acknowledge);
function event(kind, extra = {}, data = null) {
  counts[kind] = (counts[kind] || 0) + 1;
  const size = data === null ? 0 : data.byteLength;
  if (sending || inflight.size >= MAX_MESSAGES || inflightBytes + size > MAX_INFLIGHT_BYTES) {
    counts.dropped_events = (counts.dropped_events || 0) + 1;
    return;
  }
  const id = ++sequence;
  inflight.set(id, size);
  inflightBytes += size;
  sending = true;
  try { send({kind, sequence: id, timestamp_ms: Date.now(),
    pid: Process.id, tid: Process.getCurrentThreadId(), ...extra}, data); }
  catch (_) {
    inflight.delete(id); inflightBytes -= size;
    counts.send_errors = (counts.send_errors || 0) + 1;
  } finally { sending = false; }
}
function allowedPipe(name) {
  // Capturing Frida's own transport creates an amplifying feedback loop.
  const slash = String.fromCharCode(92);
  const prefix = slash + slash + '.' + slash + 'pipe' + slash;
  const lower = name.toLowerCase();
  if (!lower.startsWith(prefix)) return false;
  const relative = lower.slice(prefix.length);
  return /^terminal_[0-9]+_/.test(relative) || relative.startsWith('activation_capture_test_');
}
function trackPending(key, item) {
  if (!pending.has(key) && pending.size >= MAX_PENDING) {
    event('gap', {operation: 'pipe-pending', reason: 'pending-limit'});
    return;
  }
  pending.set(key, {...item, created: Date.now()});
}
function bytes(kind, p, n, extra = {}) {
  if (!n) return;
  // An explicit gap record replaces silent truncation or invalid reads.
  if (n < 0 || n > MAX_PAYLOAD_BYTES || p.isNull()) {
    event('gap', {operation: kind, length: n, reason: 'invalid-or-oversize', ...extra});
    return;
  }
  // Check credits before allocating a copy of target memory.
  if (inflight.size >= MAX_MESSAGES || inflightBytes + n > MAX_INFLIGHT_BYTES) {
    counts.dropped_events = (counts.dropped_events || 0) + 1;
    return;
  }
  try { event(kind, {length: n, ...extra}, p.readByteArray(n)); }
  catch (e) { event('gap', {operation: kind, length: n, reason: String(e), ...extra}); }
}
function hook(module, name, callbacks) {
  const key = module + '!' + name;
  if (hooks.has(key)) return;
  const m = Process.findModuleByName(module);
  if (!m) return;
  const address = m.findExportByName(name);
  if (!address) return;
  try {
    Interceptor.attach(address, callbacks);
    hooks.add(key);
    event('hook', {name: key, address: String(address)});
  } catch (e) { event('hook-error', {name: key, reason: String(e)}); }
}
function text(p, wide) {
  try { return p.isNull() ? '' : wide ? p.readUtf16String() : p.readAnsiString(); }
  catch (_) { return ''; }
}
function valid(h) { return !h.isNull() && !h.equals(ptr(-1)); }
function complete(overlapped, n, success, via) {
  const key = String(overlapped);
  const item = pending.get(key);
  if (!item) return;
  pending.delete(key);
  if (!success || n > item.capacity) {
    event('gap', {operation: item.operation, name: item.name, reason: 'failed-or-invalid-completion', via});
    return;
  }
  if (item.operation === 'ReadFile')
    bytes('pipe-read-output', item.buffer, n, {name: item.name, handle: item.handle, via});
}
function install() {
  hook('bcrypt.dll', 'BCryptEncrypt', {
    onEnter(a) {
      this.key = String(a[0]); this.call = sequence + 1;
      bytes('encrypt-input', a[1], a[2].toUInt32(), {key_handle: this.key, call: this.call});
    },
    onLeave(r) { event('encrypt-result', {key_handle: this.key, call: this.call, status: r.toInt32()}); }
  });
  hook('bcrypt.dll', 'BCryptDecrypt', {
    onEnter(a) { this.out = a[6]; this.capacity = a[7].toUInt32(); this.length = a[8]; this.key = String(a[0]); },
    onLeave(r) {
      if (r.toInt32() < 0 || this.out.isNull()) return;
      try {
        const n = this.length.readU32();
        if (n > this.capacity) { event('gap', {operation: 'decrypt-output', reason: 'length-exceeds-capacity'}); return; }
        bytes('decrypt-output', this.out, n, {key_handle: this.key, status: r.toInt32()});
      } catch (e) { event('gap', {operation: 'decrypt-output', reason: String(e)}); }
    }
  });
  for (const wide of [true, false]) {
    const suffix = wide ? 'W' : 'A';
    for (const prefix of ['CreateNamedPipe', 'CreateFile']) {
      hook('kernel32.dll', prefix + suffix, {
        onEnter(a) { this.name = text(a[0], wide); },
        onLeave(r) {
          if (!valid(r) || !allowedPipe(this.name)) return;
          if (pipes.size >= MAX_PIPES && !pipes.has(String(r))) {
            event('gap', {operation: 'pipe-open', reason: 'pipe-handle-limit'}); return;
          }
          pipes.set(String(r), this.name);
          event('pipe-open', {name: this.name, handle: String(r)});
        }
      });
    }
  }
  for (const operation of ['ReadFile', 'WriteFile']) {
    hook('kernel32.dll', operation, {
      onEnter(a) {
        this.name = pipes.get(String(a[0]));
        if (!this.name) return;
        this.h = String(a[0]); this.buffer = a[1]; this.capacity = a[2].toUInt32();
        this.length = a[3]; this.overlapped = a[4];
        if (operation === 'WriteFile') bytes('pipe-write-input', this.buffer, this.capacity, {name: this.name, handle: this.h});
      },
      onLeave(r) {
        if (!this.name) return;
        if (!r.toInt32()) {
          if (this.lastError === 997 && !this.overlapped.isNull()) {
            trackPending(String(this.overlapped), {name: this.name, handle: this.h,
              buffer: this.buffer, capacity: this.capacity, operation});
            event('pipe-pending', {name: this.name, operation});
          } else event('pipe-io-error', {name: this.name, operation, error: this.lastError});
          return;
        }
        if (operation === 'ReadFile') {
          if (this.length.isNull()) {
            event('gap', {operation, name: this.name, reason: 'no-synchronous-length'}); return;
          }
          const n = this.length.readU32();
          if (n <= this.capacity) bytes('pipe-read-output', this.buffer, n, {name: this.name, handle: this.h});
          else event('gap', {operation, reason: 'length-exceeds-capacity'});
        }
      }
    });
  }
  for (const name of ['GetOverlappedResult', 'GetOverlappedResultEx']) {
    hook('kernel32.dll', name, {
      onEnter(a) { this.ov = a[1]; this.length = a[2]; },
      onLeave(r) {
        if (r.toInt32() && !this.length.isNull())
          complete(this.ov, this.length.readU32(), true, name);
      }
    });
  }
  hook('kernel32.dll', 'GetQueuedCompletionStatus', {
    onEnter(a) { this.length = a[1]; this.ov = a[3]; },
    onLeave(r) {
      if (!this.ov.isNull()) {
        const ov = this.ov.readPointer();
        if (!ov.isNull()) complete(ov, this.length.readU32(), !!r.toInt32(), 'IOCP');
      }
    }
  });
  hook('kernel32.dll', 'GetQueuedCompletionStatusEx', {
    onEnter(a) { this.entries = a[1]; this.capacity = a[2].toUInt32(); this.count = a[3]; },
    onLeave(r) {
      if (!r.toInt32() || this.count.isNull()) return;
      const count = this.count.readU32();
      if (count > this.capacity) { event('gap', {operation: 'IOCPEx', reason: 'invalid-count'}); return; }
      const size = Process.pointerSize === 8 ? 32 : 16;
      for (let i = 0; i < count; i++) {
        const entry = this.entries.add(i * size);
        const ov = entry.add(Process.pointerSize).readPointer();
        const status = entry.add(Process.pointerSize * 2).readPointer();
        const n = entry.add(Process.pointerSize * 3).readU32();
        complete(ov, n, status.isNull(), 'IOCPEx');
      }
    }
  });
  hook('kernel32.dll', 'CloseHandle', {
    onEnter(a) { this.h = String(a[0]); },
    onLeave(r) {
      if (!r.toInt32()) return;
      pipes.delete(this.h);
      for (const [key, item] of pending) {
        if (item.handle === this.h) {
          pending.delete(key);
          event('gap', {operation: item.operation, reason: 'closed-before-completion'});
        }
      }
    }
  });
}
Process.attachModuleObserver({onAdded() { install(); }});
install();
setInterval(() => {
  for (const [key, item] of pending) {
    if (Date.now() - item.created > 60000) {
      pending.delete(key);
      event('gap', {operation: item.operation, reason: 'pending-expired'});
    }
  }
  event('health', {hooks: Array.from(hooks), counts: {...counts},
    tracked_pipes: pipes.size, pending_io: pending.size,
    inflight_messages: inflight.size, inflight_bytes: inflightBytes,
    limitations: ['No Schannel/SSL-library plaintext hooks', 'No ReadFileEx completion routines or direct native I/O',
      'No game or anti-cheat injection', 'Only allowlisted handles opened after attachment are tracked',
      'Oversize/busy events are reported as gaps/drops, not retained']});
}, 2000);

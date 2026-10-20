// Launch + runtime instrumentation for Ubisoft Connect (attach to upc.exe).
//
// Captures:
//   - process spawns (exe / args / cwd)
//   - named-pipe traffic (ticket / API handshake)
//   - registry writes
//   - plaintext HTTP inside the launcher's custom TLS (cloud saves, play session)
//
// BLOCK_SPAWN = true prevents the game from ever starting (safe mode).

var BLOCK_SPAWN = false;

function getAddr(mod, exp) {
  try {
    var m = Process.getModuleByName(mod);
    return m ? m.findExportByName(exp) : null;
  } catch (e) { return null; }
}
function log(tag, msg) { try { send({ tag: tag, msg: msg }); } catch (e) {} }
function hex(b, n) {
  if (!b) return "(null)";
  var s = "", k = Math.min(b.length, n || 128);
  for (var i = 0; i < k; i++) s += ("0" + (b[i] & 0xff).toString(16)).slice(-2);
  return b.length > k ? s + "...(+" + (b.length - k) + ")" : s;
}
function asc(b, n) {
  if (!b) return "";
  var s = "", k = Math.min(b.length, n || 400);
  for (var i = 0; i < k; i++) { var c = b[i] & 0xff; s += (c >= 32 && c < 127) ? String.fromCharCode(c) : "."; }
  return s;
}
function readBytes(p, n) {
  if (p.isNull() || n <= 0 || n > (1 << 22)) return null;
  try { return new Uint8Array(p.readByteArray(n)); } catch (e) { return null; }
}

// ---------------------------------------------------------------- spawn ----
["CreateProcessW", "CreateProcessAsUserW"].forEach(function (fn) {
  var a = getAddr("kernel32.dll", fn) || getAddr("advapi32.dll", fn);
  if (!a) return;
  Interceptor.attach(a, {
    onEnter: function (args) {
      var app = args[0], cmd = args[1], cwd = args[7];
      var appS = "", cmdS = "", cwdS = "";
      try { if (!app.isNull()) appS = app.readUtf16String(); } catch (e) {}
      try { if (!cmd.isNull()) cmdS = cmd.readUtf16String(); } catch (e) {}
      try { if (!cwd.isNull()) cwdS = cwd.readUtf16String(); } catch (e) {}
      log("SPAWN", fn + "\n    app=" + appS + "\n    cmd=" + cmdS + "\n    cwd=" + cwdS);
      this.block = BLOCK_SPAWN;
    },
    onLeave: function (ret) {
      log("SPAWN", "  -> returned " + ret + (this.block ? " (BLOCKED)" : ""));
      if (this.block) ret.replace(ptr(0));
    }
  });
});

// ----------------------------------------------------------------- pipes --
(function () {
  ["CreateNamedPipeW", "CreateNamedPipeA"].forEach(function (fn) {
    var a = getAddr("kernel32.dll", fn);
    if (!a) return;
    Interceptor.attach(a, { onEnter: function (args) {
      try {
        var name = fn.slice(-1) === "W" ? args[0].readUtf16String() : args[0].readAnsiString();
        if (name && name.indexOf("mojo") < 0) log("PIPE", "CreateNamedPipe " + name);
      } catch (e) {}
    }});
  });

  ["CreateFileW", "CreateFileA"].forEach(function (fn) {
    var a = getAddr("kernel32.dll", fn);
    if (!a) return;
    Interceptor.attach(a, { onEnter: function (args) {
      try {
        var p = fn.slice(-1) === "W" ? args[0].readUtf16String() : args[0].readAnsiString();
        if (p && p.indexOf("\\pipe\\") >= 0 && p.indexOf("mojo") < 0) log("PIPE", "CreateFile " + p);
      } catch (e) {}
    }});
  });

  ["ReadFile", "WriteFile"].forEach(function (fn) {
    var a = getAddr("kernel32.dll", fn);
    if (!a) return;
    Interceptor.attach(a, {
      onEnter: function (args) { this.buf = args[1]; this.len = args[2].toInt32(); this.tag = fn; },
      onLeave: function (ret) {
        if (this.len <= 0 || this.len > (1 << 20)) return;
        var d = readBytes(this.buf, this.len);
        if (!d) return;
        var s = asc(d, 120);
        var head = d.length >= 4 ? (d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)) : -1;
        var framed = head > 0 && head <= this.len - 4;
        if (!framed && s.indexOf("{") < 0 && s.indexOf("eyJ") < 0) return;
        log("PIPE-" + this.tag, "len=" + this.len + " ret=" + ret.toInt32() +
            " hex=" + hex(d, 96) + " asc=" + asc(d, 300));
      }
    });
  });
  log("init", "pipe hooks installed");
})();

// ------------------------------------------------------- registry writes ----
(function () {
  var a = getAddr("advapi32.dll", "RegSetValueExW");
  if (!a) return;
  Interceptor.attach(a, { onEnter: function (args) {
    try {
      var name = args[1].readUtf16String();
      if (!/ubisoft|uplay|childoflight|watchdogs/i.test(name)) return;
      var type = args[3].toInt32(), data = args[4], cb = args[5].toInt32();
      var v = "";
      if (type === 1 && !data.isNull()) v = data.readUtf16String();
      else if (type === 4 && !data.isNull()) v = "0x" + data.readU32().toString(16);
      log("REG", name + " = " + v);
    } catch (e) {}
  }});
})();

// ------------------------------------------- plaintext HTTP (custom TLS) ----
(function () {
  var enc = getAddr("bcrypt.dll", "BCryptEncrypt");
  if (enc) Interceptor.attach(enc, { onEnter: function (args) {
    var d = readBytes(args[1], args[2].toInt32());
    if (!d) return;
    var s = asc(d, 600);
    if (s.indexOf("GET ") === 0 || s.indexOf("POST ") === 0 || s.indexOf("PUT ") === 0 ||
        s.indexOf("DELETE ") === 0 || s.indexOf("HTTP/1.") >= 0) {
      var req = asc(d, 4000)
        .replace(/Authorization: (Basic|Ubi_v1|ubi_v1|ubi_2fa_v1) [^\r\n]+/gi,
                 "Authorization: $1 [REDACTED]");
      log("HTTP-REQ", req);
    }
  }});

  var dec = getAddr("bcrypt.dll", "BCryptDecrypt");
  if (dec) Interceptor.attach(dec, {
    onEnter: function (args) {
      this.out = args[6];
      this.cb = args[7].toInt32();
      this.res = args[8];
    },
    onLeave: function (ret) {
      var n = this.cb;
      try { if (!this.res.isNull()) n = this.res.readU32(); } catch (e) {}
      var d = readBytes(this.out, Math.min(n, 1 << 20));
      if (!d) return;
      var s = asc(d, 400);
      if (s.indexOf("{") >= 0 || s.indexOf("cloudsave") >= 0 || s.indexOf("savegame") >= 0 ||
          s.indexOf("HTTP/1.") >= 0 || s.indexOf("part") >= 0) {
        log("HTTP-RESP", asc(d, 3000));
      }
    }
  });
  log("init", "http hooks installed");
})();

log("init", "launch+runtime instrumentation ready (BLOCK_SPAWN=" + BLOCK_SPAWN + ")");

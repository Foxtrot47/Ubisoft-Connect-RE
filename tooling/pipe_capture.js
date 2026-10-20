// Pipe/registry instrumentation for the Ubisoft launcher <-> game handshake.
//
// Goal: capture the exact pipe name and the protobuf conversation that hands the
// game its ticket (mg.protocol.uplaydll.SetGameSessionReq / TicketPush).
//
// Attach in SPAWN mode (see launch_capture.py --spawn) so pipe creation is caught.

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
  var s = "", k = Math.min(b.length, n || 160);
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

// handle -> pipe name for the pipes we care about
var pipeByHandle = {};

// ------------------------------------------------------------ pipe create --
["CreateNamedPipeW", "CreateNamedPipeA"].forEach(function (fn) {
  var a = getAddr("kernel32.dll", fn);
  if (!a) return;
  Interceptor.attach(a, {
    onEnter: function (args) {
      try {
        this.name = fn.slice(-1) === "W" ? args[0].readUtf16String() : args[0].readAnsiString();
      } catch (e) { this.name = null; }
    },
    onLeave: function (ret) {
      if (this.name && this.name.indexOf("mojo") < 0) {
        log("PIPE-NAME", this.name + "  (handle " + ret + ")");
        pipeByHandle[ret.toString()] = this.name;
      }
    }
  });
});

// ------------------------------------------------------- pipe connect (cli) --
["CreateFileW", "CreateFileA"].forEach(function (fn) {
  var a = getAddr("kernel32.dll", fn);
  if (!a) return;
  Interceptor.attach(a, {
    onEnter: function (args) {
      try {
        this.path = fn.slice(-1) === "W" ? args[0].readUtf16String() : args[0].readAnsiString();
      } catch (e) { this.path = null; }
    },
    onLeave: function (ret) {
      if (this.path && this.path.indexOf("\\pipe\\") >= 0 && this.path.indexOf("mojo") < 0) {
        log("PIPE-OPEN", this.path + "  (handle " + ret + ")");
        pipeByHandle[ret.toString()] = this.path;
      }
    }
  });
});

// --------------------------------------------------------------- pipe I/O --
function pipeNameFor(h) {
  try { return pipeByHandle[h.toString()] || null; } catch (e) { return null; }
}

["ReadFile", "WriteFile"].forEach(function (fn) {
  var a = getAddr("kernel32.dll", fn);
  if (!a) return;
  Interceptor.attach(a, {
    onEnter: function (args) {
      this.fn = fn;
      this.buf = args[1];
      this.len = args[2].toInt32();
      // ReadFile: args[3] = lpNumberOfBytesRead (out)
      this.pread = (fn === "ReadFile") ? args[3] : null;
      this.name = pipeNameFor(args[0]);
    },
    onLeave: function (ret) {
      if (!this.name || this.name.indexOf("overlay") >= 0) return;
      var n = this.len;
      if (this.pread && !this.pread.isNull()) {
        try { n = this.pread.readU32(); } catch (e) {}
      }
      if (n <= 0 || n > (1 << 16)) n = Math.min(this.len, 1 << 16);
      var d = readBytes(this.buf, n);
      if (!d || d.length === 0) return;
      log("PIPE-" + this.fn, "pipe=" + this.name + " bytes=" + d.length +
          " ret=" + ret.toInt32() +
          "\n    hex=" + hex(d, 65536) +
          "\n    asc=" + asc(d, 1500));
    }
  });
});

// ------------------------------------------------------------ registry all --
(function () {
  var a = getAddr("advapi32.dll", "RegSetValueExW");
  if (!a) return;
  Interceptor.attach(a, { onEnter: function (args) {
    try {
      var name = args[1].readUtf16String();
      var type = args[3].toInt32(), data = args[4];
      var v = "";
      if (type === 1 && !data.isNull()) v = data.readUtf16String();
      else if (type === 4 && !data.isNull()) v = "dword:" + data.readU32();
      else if (type === 3 && !data.isNull()) {
        var b = readBytes(data, 260);
        v = "bin:" + hex(b, 64);
      }
      log("REG", name + " = " + v);
    } catch (e) {}
  }});
  log("init", "registry hook (all values)");
})();

// ---------------------------------------------------------------- spawns ---
["CreateProcessW", "CreateProcessAsUserW"].forEach(function (fn) {
  var a = getAddr("kernel32.dll", fn) || getAddr("advapi32.dll", fn);
  if (!a) return;
  Interceptor.attach(a, {
    onEnter: function (args) {
      var cmd = args[1], cwd = args[7];
      var cmdS = "", cwdS = "";
      try { if (!cmd.isNull()) cmdS = cmd.readUtf16String(); } catch (e) {}
      try { if (!cwd.isNull()) cwdS = cwd.readUtf16String(); } catch (e) {}
      log("SPAWN", "cmd=" + cmdS + "  cwd=" + cwdS);
      this.block = BLOCK_SPAWN;
    },
    onLeave: function (ret) { if (this.block) ret.replace(ptr(0)); }
  });
});

log("init", "pipe/registry instrumentation ready");

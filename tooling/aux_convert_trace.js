// Find the launcher-side activation conversion in upc.exe.
//
// The game's GetCachedOrFreshTokenReq arrives on the aux pipe via ReadFile, the
// ActivateRsp leaves via WriteFile. The stack at that write is the converter.

function log(tag, msg) { try { send({ tag: tag, msg: msg }); } catch (e) {} }
function addr(mod, fn) {
  try { var m = Process.getModuleByName(mod); return m.findExportByName(fn); }
  catch (e) { return null; }
}
function hex(b, n) {
  if (!b) return "(null)";
  var k = Math.min(b.length, n || 160), s = "";
  for (var i = 0; i < k; i++) s += ("0" + (b[i] & 0xff).toString(16)).slice(-2);
  return b.length > k ? s + "...(+" + (b.length - k) + ")" : s;
}
function sym(a) {
  try {
    var m = Process.findModuleByAddress(a);
    return m ? m.name + "+0x" + a.sub(m.base).toString(16) : a.toString();
  } catch (e) { return "?"; }
}
function bt(ctx) {
  try { return Thread.backtrace(ctx, Backtracer.FUZZY).map(sym).join("\n    "); }
  catch (e) { return "(no stack)"; }
}

var auxHandles = {};

["CreateNamedPipeW", "CreateNamedPipeA"].forEach(function (fn) {
  var a = addr("kernel32.dll", fn);
  if (!a) return;
  Interceptor.attach(a, {
    onEnter: function (args) {
      try { this.name = fn.slice(-1) === "W" ? args[0].readUtf16String() : args[0].readAnsiString(); }
      catch (e) { this.name = null; }
    },
    onLeave: function (ret) {
      if (this.name && this.name.indexOf("uplay_aux") >= 0) {
        auxHandles[ret.toString()] = this.name;
        log("AUX", "server pipe " + this.name + " handle=" + ret);
      }
    }
  });
});

var rf = addr("kernel32.dll", "ReadFile");
if (rf) Interceptor.attach(rf, {
  onEnter: function (args) {
    this.h = args[0].toString();
    this.buf = args[1];
    this.want = args[2].toInt32();
  },
  onLeave: function (ret) {
    if (!auxHandles[this.h]) return;
    try {
      var d = new Uint8Array(this.buf.readByteArray(Math.min(this.want, 4096)));
      // Strip the trailing zero padding of the 64 KB read buffer.
      var end = d.length;
      while (end > 0 && d[end - 1] === 0) end--;
      log("REQ", end + "B " + hex(d.subarray(0, end), 400));
    } catch (e) { log("REQ", "read failed"); }
  }
});

var cf = addr("kernel32.dll", "CreateFileW");
if (cf) Interceptor.attach(cf, {
  onEnter: function (args) {
    try { this.p = args[0].readUtf16String(); } catch (e) { this.p = null; }
  },
  onLeave: function (ret) {
    if (this.p && this.p.indexOf("uplay_aux") >= 0) {
      auxHandles[ret.toString()] = this.p;
      log("AUX", "client handle " + this.p + " handle=" + ret);
    }
  }
});

var nrf = addr("ntdll.dll", "NtReadFile");
if (nrf) Interceptor.attach(nrf, {
  onEnter: function (args) {
    this.h = args[0].toString();
    this.buf = args[5];
    this.len = args[6].toInt32();
    this.iosb = args[4];
  },
  onLeave: function (ret) {
    if (!auxHandles[this.h]) return;
    var got = 0;
    try { got = this.iosb.add(4).readU32(); } catch (e) {}
    if (!got) return;
    try {
      var d = new Uint8Array(this.buf.readByteArray(Math.min(got, 4096)));
      log("REQ", got + "B " + hex(d, 400));
    } catch (e) { log("REQ", "read failed"); }
  }
});

var wf = addr("kernel32.dll", "WriteFile");
if (wf) Interceptor.attach(wf, {
  onEnter: function (args) {
    if (!auxHandles[args[0].toString()]) return;
    var n = args[2].toInt32();
    try {
      log("RSP", n + "B " + hex(new Uint8Array(args[1].readByteArray(Math.min(n, 200))), 200));
      if (n > 1000) log("STACK", "\n    " + bt(this.context));
    } catch (e) { log("RSP", "read failed"); }
  }
});

var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function b64(u8) {
  var out = "", i = 0;
  for (; i + 2 < u8.length; i += 3) {
    var n = (u8[i] << 16) | (u8[i + 1] << 8) | u8[i + 2];
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  if (i < u8.length) {
    var n2 = u8[i] << 16;
    var more = u8.length - i - 1;
    if (more) { n2 |= u8[i + 1] << 8; }
    out += B64[(n2 >> 18) & 63] + B64[(n2 >> 12) & 63]
         + (more ? B64[(n2 >> 6) & 63] : "=") + "=";
  }
  return out;
}

rpc.exports = {
  ranges: function () {
    var m = Process.getModuleByName("upc.exe");
    var out = [];
    Process.enumerateRanges("r-x").concat(Process.enumerateRanges("r--"))
      .forEach(function (r) {
        if (r.base.compare(m.base) < 0 || r.base.compare(m.base.add(m.size)) >= 0) return;
        out.push([r.base.sub(m.base).toInt32(), r.size]);
      });
    return { base: m.base.toString(), size: m.size, ranges: out };
  },
  chunk: function (off, len) {
    var m = Process.getModuleByName("upc.exe");
    return b64(new Uint8Array(m.base.add(off).readByteArray(len)));
  }
};

log("init", "aux conversion trace ready; base=0x" + Process.getModuleByName("upc.exe").base.toString(16));

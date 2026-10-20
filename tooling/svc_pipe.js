// Dump I/O on uplay_service_ipc_pipe_ (upc side).
function log(tag, msg) { try { send({ tag: tag, msg: msg }); } catch (e) {} }
function addr(mod, fn) {
  try { var m = Process.getModuleByName(mod); return m.findExportByName(fn); }
  catch (e) { return null; }
}
function hex(b, n) {
  var k = Math.min(b.length, n || 200), s = "";
  for (var i = 0; i < k; i++) s += ("0" + (b[i] & 0xff).toString(16)).slice(-2);
  return b.length > k ? s + "...(+" + (b.length - k) + ")" : s;
}

var handles = {};
function note(name, ret) {
  if (name && name.indexOf("uplay_service") >= 0) {
    handles[ret.toString()] = name;
    log("SVC", "handle " + ret + " " + name);
  }
}
["CreateNamedPipeW", "CreateNamedPipeA"].forEach(function (fn) {
  var a = addr("kernel32.dll", fn);
  if (!a) return;
  Interceptor.attach(a, {
    onEnter: function (args) {
      try { this.n = fn.slice(-1) === "W" ? args[0].readUtf16String() : args[0].readAnsiString(); }
      catch (e) { this.n = null; }
    },
    onLeave: function (ret) { note(this.n, ret); }
  });
});
var cf = addr("kernel32.dll", "CreateFileW");
if (cf) Interceptor.attach(cf, {
  onEnter: function (args) { try { this.n = args[0].readUtf16String(); } catch (e) { this.n = null; } },
  onLeave: function (ret) { note(this.n, ret); }
});

["ReadFile", "WriteFile"].forEach(function (fn) {
  var a = addr("kernel32.dll", fn);
  if (!a) return;
  Interceptor.attach(a, {
    onEnter: function (args) {
      if (!handles[args[0].toString()]) return;
      var n = args[2].toInt32();
      try {
        var d = new Uint8Array(args[1].readByteArray(Math.min(n, 4096)));
        var end = d.length;
        var s = "";
        for (var i = 0; i < Math.min(end, 10); i++) s += String.fromCharCode(d[i]);
        log(fn === "ReadFile" ? "SVC-READ" : "SVC-WRITE", n + "B '" + s + "' " + hex(d, 200));
      } catch (e) {}
    }
  });
});
log("init", "service pipe hooked");

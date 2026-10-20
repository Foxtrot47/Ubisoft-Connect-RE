// Capture the request token the game writes on uplay_aux_ipc_pipe_ (game side).
function log(tag, msg) { try { send({ tag: tag, msg: msg }); } catch (e) {} }
function addr(mod, fn) {
  try { var m = Process.getModuleByName(mod); return m.findExportByName(fn); }
  catch (e) { return null; }
}
function hex(b, n) {
  var k = Math.min(b.length, n || 400), s = "";
  for (var i = 0; i < k; i++) s += ("0" + (b[i] & 0xff).toString(16)).slice(-2);
  return b.length > k ? s + "...(+" + (b.length - k) + ")" : s;
}

var aux = {};
var cf = addr("kernel32.dll", "CreateFileW");
if (cf) Interceptor.attach(cf, {
  onEnter: function (a) { try { this.p = a[0].readUtf16String(); } catch (e) { this.p = null; } },
  onLeave: function (r) {
    if (this.p && this.p.indexOf("uplay_aux") >= 0) {
      aux[r.toString()] = this.p;
      log("AUX", "handle=" + r);
    }
  }
});

var wf = addr("kernel32.dll", "WriteFile");
if (wf) Interceptor.attach(wf, {
  onEnter: function (a) {
    if (!aux[a[0].toString()]) return;
    var n = a[2].toInt32();
    try { log("REQ", n + "B " + hex(new Uint8Array(a[1].readByteArray(n)), n)); }
    catch (e) { log("REQ", "read failed"); }
  }
});
log("init", "game aux hook ready");

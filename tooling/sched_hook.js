// AES decryption key-schedule hook: logs the key and the caller stack.
function log(tag, msg) { try { send({ tag: tag, msg: msg }); } catch (e) {} }
function sym(a) {
  try { var m = Process.findModuleByAddress(a); return m ? m.name + "+0x" + a.sub(m.base).toString(16) : a.toString(); }
  catch (e) { return "?"; }
}
function bt(ctx) {
  var base;
  try { base = Process.getModuleByName("upc.exe").base; } catch (e) { return ""; }
  var out = [], sp = ctx.esp;
  for (var i = 0; i < 64; i++) {
    try {
      var v = sp.add(i * 4).readPointer();
      if (v.compare(base) >= 0 && v.compare(base.add(0x2b76000)) < 0) {
        out.push("s[" + i + "]=" + v.sub(base).toString(16));
      }
    } catch (e) {}
  }
  return out.join(" ");
}
function hex(u8) {
  var s = "";
  for (var i = 0; i < u8.length; i++) s += ("0" + (u8[i] & 0xff).toString(16)).slice(-2);
  return s;
}
var base = Process.getModuleByName("upc.exe").base;
Interceptor.attach(base.add(0xe4caf0), {
  onEnter: function (a) {
    var kp = a[0];
    try {
      var d = new Uint8Array(kp.readByteArray(32));
      log("SCHED", "key=" + hex(d));
    } catch (e) { log("SCHED", "key read fail"); }
    log("SCHED", bt(this.context));
  }
});
log("init", "AES decrypt schedule hooked");

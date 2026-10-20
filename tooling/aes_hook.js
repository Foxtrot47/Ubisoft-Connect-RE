// Hook the AES/base64 decode wrapper in upc.exe and dump key + input for every
// call. During an activation one call is the denuvo JWE (input starts eyJlbmMi).
function log(tag, msg) { try { send({ tag: tag, msg: msg }); } catch (e) {} }
function hex(u8, n) {
  var k = Math.min(u8.length, n || 256), s = "";
  for (var i = 0; i < k; i++) s += ("0" + (u8[i] & 0xff).toString(16)).slice(-2);
  return s;
}
function str(p, n) {
  try { return new Uint8Array(p.readByteArray(Math.min(n, 4096))); } catch (e) { return null; }
}

var base = Process.getModuleByName("upc.exe").base;
Interceptor.attach(base.add(0x8dae40), {
  onEnter: function (a) {
    var key = a[0];                    // struct { ptr, len }
    try {
      var kp = key.readPointer();
      var kl = key.add(4).readU32();
      log("KEY", kl + "B " + hex(str(kp, kl), 64));
    } catch (e) { log("KEY", "fail"); }
    var inPtr = a[1];
    var inLen = a[2].toInt32();
    var d = str(inPtr, inLen);
    if (d) {
      var s = "";
      for (var i = 0; i < Math.min(d.length, 12); i++) s += String.fromCharCode(d[i]);
      log("IN", inLen + "B " + s + " " + hex(d, 80));
    }
  }
});
log("init", "aes wrapper hooked at " + base.add(0x8dae40));

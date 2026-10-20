// Ubisoft Connect instrumentation v2 — capture plaintext HTTP (custom TLS via BCrypt)
// and DPAPI operations. Frida 17 API.

function getAddr(modName, expName) {
  try {
    var m = Process.getModuleByName(modName);
    if (!m) return null;
    var a = m.findExportByName(expName);
    return a || null;
  } catch (e) { return null; }
}

function hex(bytes, max) {
  if (bytes === null) return "(null)";
  var n = Math.min(bytes.length, max || 256);
  var s = "";
  for (var i = 0; i < n; i++) { var b = bytes[i]; s += ("0" + (b & 0xff).toString(16)).slice(-2); }
  if (bytes.length > n) s += "...(+ " + (bytes.length - n) + "B)";
  return s;
}
function ascii(bytes, max) {
  if (bytes === null) return "(null)";
  var n = Math.min(bytes.length, max || 4096);
  var s = "";
  for (var i = 0; i < n; i++) { var c = bytes[i] & 0xff; s += (c >= 32 && c < 127) ? String.fromCharCode(c) : "."; }
  return s;
}
function log(tag, msg) { try { send({ tag: tag, msg: msg, ts: Date.now() }); } catch (e) {} }

function readBytes(p, n) {
  if (p.isNull() || n <= 0 || n > (1 << 22)) return null;
  try { return new Uint8Array(p.readByteArray(n)); } catch (e) { return null; }
}

var installed = {};

function installDPAPI() {
  if (installed.dpapi) return;
  function readBlob(ptr) {
    if (ptr.isNull()) return null;
    try {
      var cb = ptr.readU32();
      var pb = ptr.add(8).readPointer();
      if (pb.isNull() || cb === 0 || cb > (1 << 24)) return null;
      return pb.readByteArray(cb);
    } catch (e) { return null; }
  }
  ["CryptProtectData", "CryptUnprotectData"].forEach(function (name) {
    var addr = getAddr("crypt32.dll", name);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.name = name;
        this.data = readBlob(args[0]);
        this.entropy = readBlob(args[2]);
        this.outPtr = args[6];
      },
      onLeave: function (ret) {
        log("DPAPI", this.name + " ret=" + ret + " inLen=" + (this.data ? this.data.byteLength : 0) +
            " inHex=" + hex(this.data ? new Uint8Array(this.data) : null, 24) +
            " entropyLen=" + (this.entropy ? this.entropy.byteLength : 0));
        if (this.name === "CryptUnprotectData" && !this.outPtr.isNull()) {
          var out = readBlob(this.outPtr);
          log("DPAPI", "  -> plaintext len=" + (out ? out.byteLength : 0) +
              " hex=" + hex(out ? new Uint8Array(out) : null, 48) +
              " ascii=" + ascii(out ? new Uint8Array(out) : null, 400));
        }
      }
    });
  });
  installed.dpapi = true;
  log("init", "DPAPI hooks installed");
}

function installCNG() {
  if (installed.cng) return;

  // Encrypt: plaintext = pbInput(args[1]) / cbInput(args[2])  -> HTTP REQUEST
  var enc = getAddr("bcrypt.dll", "BCryptEncrypt");
  if (enc) Interceptor.attach(enc, {
    onEnter: function (args) {
      var n = args[2].toInt32();
      var p = args[1];
      if (p.isNull() || n <= 0 || n > (1 << 20)) return;
      var d = readBytes(p, n);
      if (!d) return;
      var s = ascii(d, 600);
      var isHttp = s.indexOf("GET ") === 0 || s.indexOf("POST ") === 0 || s.indexOf("PUT ") === 0 ||
                   s.indexOf("DELETE ") === 0 || s.indexOf("HTTP/1.") >= 0;
      if (isHttp) {
        var req = ascii(d, 24000)
          .replace(/Authorization: (Basic|Ubi_v1|ubi_v1|ubi_2fa_v1) [^\r\n]+/gi,
                   "Authorization: $1 [REDACTED]");
        log("HTTP-REQ", "len=" + n + "\n" + req);
      } else if (n > 8) {
        // non-HTTP application data -> likely the binary demux protobuf
        log("ENC-RAW", "len=" + n + " hex=" + hex(d, 20000));
      }
    }
  });

  // Decrypt: plaintext = pbOutput(args[6]) -> HTTP RESPONSE (read onLeave)
  var dec = getAddr("bcrypt.dll", "BCryptDecrypt");
  if (dec) Interceptor.attach(dec, {
    onEnter: function (args) {
      this.out = args[6];       // pbOutput
      this.cbOut = args[7].toInt32(); // cbOutput
      this.pcbResult = args[8]; // ULONG* pcbResult
    },
    onLeave: function (ret) {
      var n = this.cbOut;
      try {
        if (!this.pcbResult.isNull()) n = this.pcbResult.readU32();
      } catch (e) {}
      if (n <= 0) return;
      var d = readBytes(this.out, Math.min(n, 1 << 20));
      if (!d) return;
      var s = ascii(d, 400);
      var interesting = (s.indexOf("{") >= 0 && s.indexOf("}") >= 0) ||
                        s.indexOf("http") >= 0 || s.indexOf("cdn") >= 0 ||
                        s.indexOf("url") >= 0 || s.indexOf("space") >= 0 ||
                        s.indexOf("download") >= 0 || s.indexOf("manifest") >= 0 ||
                        s.indexOf("Host:") >= 0 || s.indexOf("HTTP/1.") >= 0;
      if (interesting) {
        // keep hex for config-catalog (contains QC signatures) so records are parseable
        var extra = s.indexOf("QC") >= 0 || s.indexOf("version: 2.0") >= 0
                  ? " hex=" + hex(d, 20000) : "";
        log("HTTP-RESP", "len=" + n + extra + "\n" + ascii(d, 6000));
      } else if (n > 8) {
        // non-HTTP plaintext -> demux protobuf responses (ownership JWS, etc.)
        log("DEC-RAW", "len=" + n + " hex=" + hex(d, 20000) + " ascii=" + ascii(d, 300));
      }
    }
  });

  installed.cng = true;
  log("init", "CNG hooks installed");
}

function installWS2() {
  if (installed.ws2) return;
  // plain-HTTP response bodies (CDN manifest / licenses / slices on port 80)
  var recv = getAddr("ws2_32.dll", "recv");
  if (recv) Interceptor.attach(recv, {
    onEnter: function (a) { this.buf = a[1]; this.len = a[2].toInt32(); },
    onLeave: function (ret) {
      var n = ret.toInt32();
      if (n > 0 && n < (1 << 22)) {
        var d = readBytes(this.buf, n);
        if (d) {
          var s = ascii(d, 600);
          if (s.indexOf("HTTP/") === 0 || n > 128) {
            log("RECV", "len=" + n + " ascii=" + ascii(d, 2000) + " hex=" + hex(d, 48));
          }
        }
      }
    }
  });
  var connect = getAddr("ws2_32.dll", "connect");
  if (connect) Interceptor.attach(connect, { onEnter: function (a) {
    try {
      var sa = a[1];
      if (sa.readU16() === 2) {
        var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
        var ip = sa.add(4).readU8() + "." + sa.add(5).readU8() + "." + sa.add(6).readU8() + "." + sa.add(7).readU8();
        log("SOCKET", "connect " + ip + ":" + port);
      }
    } catch (e) {}
  }});
  installed.ws2 = true;
  log("init", "ws2_32 hooks installed");
}

function installWinHTTP() {
  if (installed.winhttp) return;
  var hostByHandle = {};
  var conn = getAddr("winhttp.dll", "WinHttpConnect");
  if (conn) Interceptor.attach(conn, {
    onEnter: function (a) { this.server = a[1].readUtf16String(); this.port = a[2].toInt32(); },
    onLeave: function (ret) { if (!ret.isNull()) hostByHandle[ret.toString()] = this.server + ":" + this.port; }
  });
  var openReq = getAddr("winhttp.dll", "WinHttpOpenRequest");
  if (openReq) Interceptor.attach(openReq, {
    onEnter: function (a) { this.conn = a[0]; this.verb = a[1].readUtf16String(); this.path = a[2].readUtf16String(); },
    onLeave: function (ret) {
      var host = hostByHandle[this.conn.toString()] || "(host?)";
      log("WINHTTP", this.verb + " https://" + host + this.path);
    }
  });
  installed.winhttp = true;
  log("init", "winhttp hooks installed");
}

function installWinINet() {
  if (installed.wininet) return;
  ["InternetOpenUrlW", "InternetOpenUrlA"].forEach(function (name) {
    var addr = getAddr("wininet.dll", name);
    if (!addr) return;
    Interceptor.attach(addr, { onEnter: function (a) {
      try {
        var url = name.indexOf("W") >= 0 ? a[1].readUtf16String() : a[1].readUtf8String();
        log("WININET", "OpenUrl " + url);
      } catch (e) {}
    }});
  });
  var ic = getAddr("wininet.dll", "InternetConnectW");
  if (ic) Interceptor.attach(ic, { onEnter: function (a) {
    try { log("WININET", "Connect host=" + a[1].readUtf16String() + " port=" + a[2].toInt32()); } catch (e) {}
  }});
  var hr = getAddr("wininet.dll", "HttpOpenRequestW");
  if (hr) Interceptor.attach(hr, { onEnter: function (a) {
    try { log("WININET", "OpenRequest " + a[1].readUtf16String() + " " + a[2].readUtf16String()); } catch (e) {}
  }});
  installed.wininet = true;
  log("init", "wininet hooks installed");
}

function installAll() {
  installDPAPI();
  installCNG();
  installWS2();
  installWinHTTP();
  installWinINet();
  if (!(installed.dpapi && installed.cng && installed.ws2 && installed.winhttp && installed.wininet)) {
    setTimeout(installAll, 400);
  } else {
    log("init", "ALL HOOKS INSTALLED");
  }
}

installAll();

// Dump demux TLS writes/reads of the Janus node runtime.
const fs = require('fs');
const tls = require('tls');
const net = require('net');
const LOG = 'D:/Projects/ubisoft-re/tooling/janus/demux.txt';
const CV = Buffer.from('1205220308', 'hex');
try { fs.appendFileSync(LOG, `START ${process.pid}` + '\n'); } catch (e) {}

function mark(sock, buf) {
  if (sock.__dmx) return true;
  if (buf && Buffer.isBuffer(buf) && buf.includes(CV)) {
    sock.__dmx = true;
    sock.on('data', function (d) { dump('IN', sock, d); });
    sock.on('error', function (e) { try { fs.appendFileSync(LOG, `ERR ${e.message}` + '\n'); } catch (_) {} });
    sock.on('close', function () { try { fs.appendFileSync(LOG, 'CLOSE\n'); } catch (_) {} });
    return true;
  }
  return false;
}
function dump(dir, sock, buf) {
  try { fs.appendFileSync(LOG, `${dir} ${buf.toString('hex')}\n`); } catch (e) {}
}
const ow = net.Socket.prototype.write;
net.Socket.prototype.write = function (data, ...rest) {
  try {
    if (mark(this, data)) dump('OUT', this, Buffer.isBuffer(data) ? data : Buffer.from(data));
  } catch (e) {}
  return ow.call(this, data, ...rest);
};
const oe = net.Socket.prototype.emit;
net.Socket.prototype.emit = function (ev, ...args) {
  if (ev === 'data') {
    try { if (this.__dmx) dump('IN', this, args[0]); } catch (e) {}
  }
  return oe.call(this, ev, ...args);
};

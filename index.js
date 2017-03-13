'use strict';

const pcapp = require('pcap-parser');

const sourceIP = process.argv[2]
const parser = pcapp.parse(process.argv[3]);
const dests = {};
let first;
let last;
parser.on('packet', packet => {
  const tcpData = parse_pcap_tcp(packet.data);
  if (!tcpData) {
    return;
  }
  if (tcpData.sourceIP !== sourceIP) {
    return;
  }
  if (!first) {
    first = getTimestamp(packet);
  }
  last = getTimestamp(packet);

  const key = tcpData.destinationIP + ':' + tcpData.destinationPort;
  if (!dests[key]) {
    dests[key] = { size: 0, str: '' };
  }
  let data = tcpData.data.toString();
  dests[key].size += data.length;
  dests[key].str += data;
});

function getTimestamp(p) {
  return p.header.timestampSeconds + p.header.timestampMicroseconds / 1000000;
}

parser.on('end', () => {
  const res = {};
  const totalChannels = {};
  let duration = last - first;
  let total = 0;
  Object.keys(dests).forEach(key => {
    let speed = dests[key].size / duration * 8;
    res[key] = {
      speed,
      size: dests[key].size
    };
  });
  console.log(JSON.stringify(res));
  console.log(JSON.stringify(totalChannels));
})


function parse_pcap_tcp(buffer) {
  if (buffer.length <= 0x35) {
    return null;
  }

  if (buffer.readUInt8(14) != 0x45) {
    return null;
  }

  var sourceIP = buffer.readUInt8(0x1A).toString() + '.' +
  buffer.readUInt8(0x1B).toString() + '.' +
  buffer.readUInt8(0x1C).toString() + '.' +
  buffer.readUInt8(0x1D).toString();

  var destinationIP = buffer.readUInt8(0x1E).toString() + '.' +
  buffer.readUInt8(0x1F).toString() + '.' +
  buffer.readUInt8(0x20).toString() + '.' +
  buffer.readUInt8(0x21).toString();

  var sourcePort = buffer.readUInt16BE(0x22);
  var destinationPort = buffer.readUInt16BE(0x24);

  var data = buffer.slice(0x36);

  return {
    sourceIP: sourceIP,
    destinationIP: destinationIP,
    sourcePort: sourcePort,
    destinationPort: destinationPort,
    data: data
  }
}


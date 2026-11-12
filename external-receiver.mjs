import { get } from 'node:https';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';

const hostnamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const forbidden = new Set(['nostrwot.com', 'nostr-wot.com', 'zaps.nostr-wot.com', 'zaps.nostrwot.com', 'localhost']);
function publicHostname(host) {
  return hostnamePattern.test(host) && !isIP(host) && !forbidden.has(host) && !host.endsWith('.local') && !host.endsWith('.localhost');
}

export function receiverUrl(address) {
  if (typeof address !== 'string' || address.length > 320) return null;
  const parts = address.split('@');
  if (parts.length !== 2 || !/^[a-z0-9._-]{1,64}$/.test(parts[0]) || !publicHostname(parts[1])) return null;
  return new URL('/.well-known/lnurlp/' + parts[0], 'https://' + parts[1]);
}

// Pin the connection to the vetted DNS answer while TLS verifies the original hostname.
async function publicAddresses(host) {
  const answers = await lookup(host, { all: true, verbatim: true });
  if (!answers.length || answers.some(({ address }) => ipaddr.parse(address).range() !== 'unicast')) throw Error('Unavailable destination');
  return answers;
}

export function readPayRequest(address) {
  const url = receiverUrl(address);
  if (!url) throw Error('Invalid receiver');
  return new Promise((resolve, reject) => {
    const request = get(url, { agent: false, headers: { Accept: 'application/json' },
      lookup(host, options, callback) {
        publicAddresses(host).then(answers => options.all ? callback(null, answers) : callback(null, answers[0].address, answers[0].family), callback);
      },
    }, response => {
      if (response.statusCode !== 200) { request.destroy(Error('Unavailable receiver')); return; }
      const chunks = [];
      let size = 0;
      response.on('error', reject);
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 65536) request.destroy(Error('Response too large'));
        else chunks.push(chunk);
      });
      response.on('end', () => {
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          const callback = new URL(data.callback);
          if (data.tag !== 'payRequest' || callback.protocol !== 'https:' || callback.username || callback.password || callback.port || !publicHostname(callback.hostname)
              || typeof data.metadata !== 'string' || !Array.isArray(JSON.parse(data.metadata)) || !Number.isSafeInteger(data.minSendable)
              || !Number.isSafeInteger(data.maxSendable) || data.minSendable <= 0 || data.maxSendable < data.minSendable) throw Error('Invalid payment metadata');
          resolve(data);
        } catch (error) { reject(error); }
      });
    });
    const timer = setTimeout(() => request.destroy(Error('Receiver timeout')), 5000);
    request.on('error', reject);
    request.once('close', () => clearTimeout(timer));
  });
}

// safe-fetch-undici.mjs: SSRF guard as an undici dispatcher, for code that uses fetch().
// Requires the `undici` package (npm i undici). Works with undici's fetch and with Node's
// global fetch (pass it as `dispatcher`).
//
// The guard runs inside the connector, so it sees EVERY connection, including each redirect
// hop and IP-literal hosts that never touch DNS:
//
//   import { createSsrfSafeAgent } from './safe-fetch-undici.mjs';
//   const ssrfSafe = createSsrfSafeAgent();            // create once, reuse
//   const res = await fetch(userUrl, { dispatcher: ssrfSafe, redirect: 'follow' });
//
// Use this Agent ONLY for untrusted URLs. Never set it as the global dispatcher for
// everything, or calls to your own internal services start failing.
// fetch() has no response-size cap: read bodies with a limit, or use safe-fetch.mjs, which buffers with a cap.

import { Agent, buildConnector } from 'undici';
import net from 'node:net';
import { createGuardedLookup, isPublicAddress, SsrfBlockedError } from './safe-fetch.mjs';

/**
 * @param {{ isAllowedAddress?: (ip: string) => boolean, allowedPorts?: number[] | null, connect?: object } & Record<string, unknown>} [opts]
 *   connect: extra TLS/socket options for undici's buildConnector (e.g. { timeout: 5000 }).
 *   Other options are passed to the Agent (e.g. headersTimeout, bodyTimeout).
 */
export function createSsrfSafeAgent(opts = {}) {
  const { isAllowedAddress = isPublicAddress, allowedPorts = [80, 443], connect = {}, ...agentOpts } = opts;
  const baseConnect = buildConnector({ ...connect, lookup: createGuardedLookup(isAllowedAddress) });
  return new Agent({
    ...agentOpts,
    connect(options, callback) {
      const host = String(options.hostname).replace(/^\[|\]$/g, '');
      const port = Number(options.port) || (options.protocol === 'https:' ? 443 : 80);
      if (allowedPorts && !allowedPorts.includes(port)) return callback(new SsrfBlockedError(`port ${port} is not allowed`), null);
      if (net.isIP(host) && !isAllowedAddress(host)) return callback(new SsrfBlockedError(`address ${host} is blocked`), null);
      return baseConnect(options, callback);
    },
  });
}

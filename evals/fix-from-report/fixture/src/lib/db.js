// Tiny async "database" standing in for Postgres. Every call yields like a real network round-trip.
const tables = { coupons: new Map([['WELCOME10', { code: 'WELCOME10', redeemedBy: null }]]), users: new Map(), balances: new Map() };
const tick = () => new Promise((r) => setTimeout(r, 2));
export const db = {
  async get(table, key) { await tick(); const v = tables[table].get(key); return v ? { ...v } : undefined; },
  async put(table, key, value) { await tick(); tables[table].set(key, { ...value }); },
  // Atomic conditional update (like UPDATE ... SET ... WHERE <predicate>): returns the number of rows changed.
  async updateWhere(table, key, predicate, changes) { await tick(); const v = tables[table].get(key); if (!v || !predicate(v)) return 0; tables[table].set(key, { ...v, ...changes }); return 1; },
  _reset() { tables.coupons = new Map([['WELCOME10', { code: 'WELCOME10', redeemedBy: null }]]); },
};

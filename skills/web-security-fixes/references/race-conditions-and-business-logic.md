# Race conditions and business logic

Limits that hold one request at a time but break when 20 arrive at once: double-spending balances or credits, redeeming a coupon or gift card twice, exceeding a seat or invite limit, voting twice, withdrawing during a transfer. Attackers send requests in parallel (HTTP/2 "single-packet" attacks land dozens within about a millisecond), so a 5 ms gap between check and write is plenty.

## Contents
- [Spot it](#spot-it)
- [Fixes that don't hold](#fixes-that-dont-hold)
- [The fix that holds](#the-fix-that-holds)
- [Idempotency keys](#idempotency-keys)
- [Business-logic checks](#business-logic-checks)
- [Regression tests: prove it under concurrency](#regression-tests-prove-it-under-concurrency)

## Spot it

The shape: **read state → decide in application code → write state**, as separate steps.

```ts
const acct = await db.account.findUnique({ where: { id } });
if (acct.balance < amount) throw new Error('insufficient');        // check
await db.account.update({ where: { id }, data: { balance: acct.balance - amount } });   // act (lost update)
```

Look for: `if (!coupon.used)` … `coupon.used = true`; `count < limit` then insert; `exists()` then `create()`; `GET` then `SET` in Redis; and "already processed?" lookups before handling a webhook or payment.

## Fixes that don't hold

| Fix | Why it fails |
|---|---|
| "Node is single-threaded" | Every `await` yields. Two requests interleave between your read and your write. You also run more than one process or pod. |
| In-process mutex / lock map | Works on one instance only. Breaks the moment you scale out or restart. |
| Wrap read + write in a transaction at the default isolation (Postgres and SQL Server: READ COMMITTED) | Both transactions read the same old balance and both write. A transaction alone doesn't serialize a read-modify-write. |
| `SELECT` inside a transaction, without `FOR UPDATE` | Same: plain reads take no lock. |
| Check-then-insert for "one per user" | Two inserts both pass the check. Without a unique constraint, the database accepts both. |
| Disable the button in the UI | Attackers don't use your UI. |
| Rate limit with `GET count` then `SET count+1` | Same race inside the rate limiter. |

## The fix that holds

Make the database do the check and the write in **one atomic statement**, or hold a row lock across them.

**1. Conditional update. Check the affected row count.**

```sql
UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1;   -- 0 rows → insufficient funds
UPDATE coupons  SET used_at = now(), used_by = $2 WHERE code = $1 AND used_at IS NULL;   -- 0 rows → already used
```

```ts
// Prisma: updateMany returns { count }
const { count } = await db.account.updateMany({ where: { id, balance: { gte: amount } }, data: { balance: { decrement: amount } } });
if (count === 0) throw new InsufficientFunds();
```

```python
# Django: filter(...).update() is a single UPDATE ... WHERE; F() does the arithmetic in SQL
updated = Account.objects.filter(pk=acct_id, balance__gte=amount).update(balance=F("balance") - amount)
if updated == 0:
    raise InsufficientFunds()
```

**2. Unique constraints for "at most once":** `UNIQUE (coupon_id, user_id)`, `UNIQUE (user_id, poll_id)`, `UNIQUE (provider, event_id)`. Insert and treat a unique violation as "already done": Postgres `INSERT ... ON CONFLICT DO NOTHING RETURNING id`, Prisma error `P2002`, Django `IntegrityError`.

**3. Row locks when the decision needs several reads:**

```python
with transaction.atomic():
    acct = Account.objects.select_for_update().get(pk=acct_id)       # SQLAlchemy: .with_for_update()
    if acct.balance < amount or acct.frozen:
        raise InsufficientFunds()
    acct.balance -= amount
    acct.save(update_fields=["balance"])
    Ledger.objects.create(account=acct, delta=-amount)
```

```ts
await db.$transaction(async (tx) => {
  const [acct] = await tx.$queryRaw`SELECT * FROM accounts WHERE id = ${id} FOR UPDATE`;
  // ...decide, write, insert ledger row...
});
```

Lock rows in a consistent order (e.g. by ID) when a transfer touches two accounts, or you'll deadlock.

**4. SERIALIZABLE isolation with retry** for complex invariants. Postgres aborts one of the conflicting transactions with SQLSTATE `40001`; retry it a few times.

**5. Counts and limits** (seats, invites, API quotas): enforce them in the same statement, e.g. `INSERT ... SELECT ... WHERE (SELECT count(*) ...) < limit` under a lock on the parent row, or keep a counter column updated with `UPDATE ... SET used = used + 1 WHERE used < limit`.

**6. Redis:** use atomic primitives. `INCR` then `EXPIRE` set together via `SET key 0 EX 60 NX` + `INCR`, or a Lua script. `SET lock NX PX 30000` for short locks, released only with your token via Lua compare-and-delete. Redis locks aren't a substitute for database constraints on money.

**7. Ledgers:** for balances, insert immutable ledger rows and derive or verify the balance. That makes double-spends visible and reversible.

## Idempotency keys

For payments, orders, and anything a client may retry:

```sql
CREATE TABLE idempotency_keys (
  user_id uuid NOT NULL, key text NOT NULL, request_hash text NOT NULL,
  response jsonb, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, key)
);
```

1. `INSERT ... ON CONFLICT DO NOTHING RETURNING` the key, in the same transaction as the side effect.
2. If the insert returned nothing, the key exists:
   - same `request_hash`: return the stored response (or 409 "in progress")
   - different hash: return 422.
3. Scope keys to the user and expire them (e.g. after 24 h).

"Find existing key, then insert" has the race this whole section is about.

## Business-logic checks

- **Never trust client-computed values:** price, total, discount, currency, and quantity come from the server's catalog and rules. The client sends IDs and quantities only.
- **Validate ranges:** quantity ≥ 1 and below a sane max; no negative amounts (refund via a negative purchase); integer money in minor units (cents), never floats.
- **Workflow state machines:** each step checks the current state server-side (`WHERE status = 'pending_payment'`). Calling `/orders/:id/ship` directly mustn't skip payment.
- **Coupons and promotions:** one redemption per user via a unique constraint; stacking rules on the server; expiry checked in the same statement as redemption.
- **Re-check authorization on every step** of multi-step flows (see `authorization-idor-mass-assignment.md`). A step-2 endpoint must not assume step 1 ran.

## Regression tests: prove it under concurrency

Write the test against the real database (not mocks), fire requests **in parallel**, and assert the invariant:

```ts
// vitest + supertest against a test DB
test('balance cannot be double-spent', async () => {
  const acct = await seedAccount({ balance: 100 });
  const results = await Promise.all(Array.from({ length: 20 }, () =>
    request(app).post('/api/withdraw').set(auth(acct.owner)).send({ amount: 100 })));
  expect(results.filter((r) => r.status === 200)).toHaveLength(1);
  expect((await getAccount(acct.id)).balance).toBe(0);           // never negative
});
```

```python
# pytest: threads hit the same endpoint (Django: use TransactionTestCase / pytest-django transaction=True, not the default wrapped transaction)
from concurrent.futures import ThreadPoolExecutor
def test_coupon_single_use(client_factory, coupon):
    with ThreadPoolExecutor(20) as pool:
        codes = list(pool.map(lambda _: client_factory().post("/redeem", json={"code": coupon.code}).status_code, range(20)))
    assert codes.count(200) == 1
```

A race test must **fail on the old code** before you trust it. If it passes on the vulnerable version, it isn't concurrent enough: raise N, add a barrier so all requests start together, or run against a server process instead of an in-process client that serializes requests.

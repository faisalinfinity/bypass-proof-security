import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';
const listen = () => new Promise((r) => { const s = createApp().listen(0, () => r(s)); });
test('downloads a nested document', async () => {
  const s = await listen(); const res = await fetch(`http://127.0.0.1:${s.address().port}/files?name=2024/q1/report.txt`);
  assert.equal(res.status, 200); assert.match(await res.text(), /Q1 report/); s.close();
});
test('login callback redirects to the requested page', async () => {
  const s = await listen(); const res = await fetch(`http://127.0.0.1:${s.address().port}/login/callback?next=/dashboard`, { redirect: 'manual' });
  assert.equal(res.headers.get('location'), '/dashboard'); s.close();
});

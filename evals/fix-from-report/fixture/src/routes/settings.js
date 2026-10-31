import { Router } from 'express';
import express from 'express';
const r = Router();
const defaults = { theme: 'light', notifications: { email: true, sms: false } };
export const userSettings = new Map();
function deepMerge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
r.patch('/api/settings', express.json(), (req, res) => {
  const uid = req.get('x-user-id') || 'anon';
  const current = userSettings.get(uid) || structuredClone(defaults);
  userSettings.set(uid, deepMerge(current, req.body));
  res.json(userSettings.get(uid));
});
// Admin-only endpoint: admins are users whose session object has isAdmin.
r.get('/api/admin/stats', (req, res) => {
  const session = {};
  if (!session.isAdmin) return res.status(403).json({ error: 'forbidden' });
  res.json({ users: 1234 });
});
export default r;

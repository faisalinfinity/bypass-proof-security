import { Router } from 'express';
import { currentUser } from '../lib/auth.js';
const r = Router();
// After the hosted login page succeeds it sends the user here with ?next=<where they were going>.
r.get('/login/callback', (req, res) => {
  const next = req.query.next || '/';
  res.redirect(302, next);
});
r.get('/api/me', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'unauthenticated' });
  res.json(user);
});
export default r;

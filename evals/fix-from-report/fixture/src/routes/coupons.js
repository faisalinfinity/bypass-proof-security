import { Router } from 'express';
import express from 'express';
import { db } from '../lib/db.js';
const r = Router();
r.post('/api/coupons/redeem', express.json(), async (req, res) => {
  const { code, userId } = req.body;
  const coupon = await db.get('coupons', code);
  if (!coupon) return res.status(404).json({ error: 'unknown coupon' });
  if (coupon.redeemedBy) return res.status(409).json({ error: 'already redeemed' });
  await db.put('coupons', code, { ...coupon, redeemedBy: userId });
  res.json({ ok: true, credit: 10 });
});
export default r;

import { Router } from 'express';
import express from 'express';
const r = Router();
export const processed = [];
// Payment provider webhook. Provider docs: every request carries
//   X-Payments-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of `${t}.${rawBody}` keyed with the endpoint secret>
// and "reject events whose timestamp is more than 5 minutes old".
r.post('/webhooks/payments', express.json(), (req, res) => {
  const event = req.body;
  processed.push(event.id);
  res.json({ received: true });
});
export default r;

import jwt from 'jsonwebtoken';
// Access tokens are issued by https://auth.acme.example (HS256, iss/aud set, 15 min exp).
export function currentUser(req) {
  const header = req.get('authorization') || '';
  const token = header.replace(/^Bearer /, '');
  if (!token) return null;
  const claims = jwt.decode(token);
  return claims && claims.sub ? { id: claims.sub, role: claims.role || 'user' } : null;
}

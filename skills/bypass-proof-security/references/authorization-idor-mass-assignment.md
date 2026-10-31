# Authorization: IDOR/BOLA, multi-tenancy, mass assignment

The most common serious bug class in real apps (OWASP API #1). The code authenticates the user, then never checks that *this* user may touch *this* record. Or it lets the user set fields they shouldn't.

## Contents
- [Spot it](#spot-it)
- [Fixes that don't hold](#fixes-that-dont-hold)
- [The fix that holds: scope at the data layer](#the-fix-that-holds-scope-at-the-data-layer)
- [Multi-tenant defense in depth: Postgres RLS](#multi-tenant-defense-in-depth-postgres-rls)
- [Mass assignment](#mass-assignment)
- [GraphQL](#graphql)
- [Regression tests: the two-user test](#regression-tests-the-two-user-test)

## Spot it

```bash
# fetch-by-id without an owner/tenant filter
grep -rnE "findUnique\(\{\s*where:\s*\{\s*id|findById\(|findByPk\(|\.get\(pk=|\.get\(id=|objects\.get\(|session\.get\(|\.find\(params\[:id\]\)|::find\(\\\$id|findOrFail\(|getById\(|WHERE id = \\$1" .
# whole request bodies flowing into writes
grep -rnE "data:\s*(req\.body|body|input)\b|\.update\((req\.body|request\.data|params)\)|Object\.assign\([a-z]+,\s*req\.body|\.\.\.req\.body|fields\s*=\s*['\"]__all__|permit!|\\\$guarded\s*=\s*\[\]|\*\*request\.(json|data|POST)|model_dump\(\)\)" .
```

Every route with an ID in the path, query, or body (including nested IDs like `projectId` inside a JSON payload) needs an answer to "where does this code check that the caller may access this ID?"

## Fixes that don't hold

| Fix | Why it fails |
|---|---|
| Hide the button or link in the UI | The API is still callable. |
| "IDs are UUIDs, nobody can guess them" | IDs leak through URLs, logs, Referer, shared links, exports, and other API responses. Unguessable isn't authorization. |
| Check ownership on `GET /items/:id` only | `PUT`, `PATCH`, `DELETE`, `/items/:id/export`, and `/items/:id/share` were added later without the check. |
| Check the parent, fetch the child by its own ID | `/orgs/:orgId/projects/:projectId`: org membership is checked, then `Project.findById(projectId)` returns a project from *another* org. |
| `if (item.ownerId !== user.id) return 403` after fetching | Works for one route, but it's easy to forget, and it gives different responses for "exists" and "doesn't exist" (enumeration). Scope the query instead. |
| Filter list results in the frontend | The API returned everything. |
| Authorization in `proxy.ts`/middleware by URL pattern | Breaks with new routes, rewrites, encoded paths, and alternate methods. Check where the data is read or written. |
| Trust `orgId` / `userId` from the request body | The attacker sets them. Take identity and tenant from the session, never the payload. |
| Blocklist fields: `delete body.role` | `isAdmin`, `is_staff`, `orgId`, `ownerId`, `emailVerified`, `plan`, `credits`, nested `profile.account.role`, and every field added next year. Use allowlists. |

## The fix that holds: scope at the data layer

Put the caller's identity **in the query**, and return 404 when nothing matches. Then "not yours" and "doesn't exist" look the same.

```ts
// Prisma: every read and write is scoped
const project = await db.project.findFirst({ where: { id: projectId, orgId: session.orgId } });
if (!project) notFound();
await db.project.update({ where: { id: projectId, orgId: session.orgId }, data: { name } });   // Prisma 5+: non-unique filters in where
// deleteMany/updateMany return a count, so a mismatched org updates 0 rows instead of someone else's record
const { count } = await db.project.deleteMany({ where: { id: projectId, orgId: session.orgId } });
if (count === 0) notFound();
```

```python
# Django
project = get_object_or_404(Project, pk=project_id, org=request.user.org)
# Even better: a manager that requires the tenant
class TenantQuerySet(models.QuerySet):
    def for_user(self, user): return self.filter(org_id=user.org_id)
Project.objects.for_user(request.user).get(pk=project_id)
# SQLAlchemy
project = session.scalar(select(Project).where(Project.id == project_id, Project.org_id == current_user.org_id))
```

Centralize it:
- One data-access module per resource exposes only scoped functions (`getProjectForUser(user, id)`). Route handlers can't call the ORM directly. Lint for it, or keep the ORM client unexported.
- Use a policy function or library (`can(user, 'update', project)`; CASL, Pundit, Django Guardian, Laravel Policies) for role logic beyond ownership. Call it in the data-access function, not in the route.

## Multi-tenant defense in depth: Postgres RLS

If one forgotten `where` would leak another customer's data, add row-level security so the database refuses even when the code is wrong:

```sql
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;           -- applies to the table owner too
CREATE POLICY tenant_isolation ON projects
  USING (org_id = current_setting('app.org_id', true)::uuid)        -- missing setting → NULL → no rows (fails closed)
  WITH CHECK (org_id = current_setting('app.org_id', true)::uuid);
```

```ts
// per request, inside the transaction (SET LOCAL semantics; safe with connection pools)
await db.$transaction(async (tx) => {
  await tx.$executeRaw`SELECT set_config('app.org_id', ${session.orgId}, true)`;
  return tx.project.findMany();
});
```

Things to get right:
- The app's database role must not be a superuser or have `BYPASSRLS`.
- Use `set_config(..., true)` (transaction-local), never a session-level `SET` on a pooled connection. The next request on that connection would inherit the tenant.
- Supabase: RLS protects the `anon`/`authenticated` keys. The `service_role` key bypasses it, so never ship that key to clients.

## Mass assignment

Parse requests into an **explicit allowlist** of fields, separate from the database model:

```ts
// zod: .strict() rejects unknown keys (use .strip(), the default, to drop them silently)
const UpdateProfile = z.object({ name: z.string().max(100), bio: z.string().max(1000).optional() }).strict();
const input = UpdateProfile.parse(await req.json());
await db.user.update({ where: { id: session.userId }, data: input });
```

```python
# Pydantic: separate input models; forbid extras
class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: constr(max_length=100)
    bio: Optional[constr(max_length=1000)] = None
# FastAPI: def update(body: ProfileUpdate, user=Depends(current_user)) -> never accept the ORM/DB model as the body type
```

- Django REST Framework: `fields = ["name", "bio"]` and `read_only_fields = [...]`, never `"__all__"` on writable serializers. Django forms: explicit `fields`.
- Rails: `params.require(:user).permit(:name, :bio)`, never `permit!`.
- Laravel: `$fillable = ['name', 'bio']`, never `$guarded = []`. `$request->validated()` only.
- Spring: bind to a DTO, not the `@Entity`. With `@InitBinder`, use `setAllowedFields`.

Role, plan, tenant, ownership, verification, and balance fields change only through dedicated, authorized code paths, never through a generic update.

## GraphQL

- Authorize in each **resolver** or in the data layer it calls, not only on the root query. Nested fields (`user { organization { invoices } }`) and the `node(id:)` interface are classic bypasses.
- DataLoaders: scope by the caller. A loader cache keyed only on ID can serve one user's object to another within a request if the loader is shared across users.
- Turn off introspection in production only as noise reduction. It isn't access control.
- Limit depth and complexity, and cap aliases and batching, so authorization checks can't be multiplied into a DoS.

## Regression tests: the two-user test

The highest-value security test in most codebases:

```ts
// vitest / jest + supertest: user A owns the resource, user B must not touch it
const a = await login('alice'); const b = await login('bob');
const { id } = await request(app).post('/api/projects').set(a).send({ name: 'secret' }).expect(201).then((r) => r.body);
for (const [method, path] of [['get', `/api/projects/${id}`], ['patch', `/api/projects/${id}`], ['delete', `/api/projects/${id}`], ['get', `/api/projects/${id}/export`]]) {
  await request(app)[method](path).set(b).send({ name: 'pwned' }).expect(404);
}
const list = await request(app).get('/api/projects').set(b).expect(200);
expect(list.body.map((p) => p.id)).not.toContain(id);
// mass assignment
await request(app).patch('/api/me').set(b).send({ name: 'Bob', role: 'admin', orgId: 'other-org', isAdmin: true }).expect(400); // .strict()
```

Write the test first and watch it fail on the vulnerable route. Then generate the same test for every route with an ID, not only the one that was reported.

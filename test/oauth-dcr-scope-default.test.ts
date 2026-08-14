/**
 * DCR registration scope default (RFC 7591).
 *
 * When a client self-registers via Dynamic Client Registration and OMITS the
 * `scope` field, the stored client scope must default to `read write` — NOT the
 * empty string. Managed MCP connectors (claude.ai and others) register without
 * a scope field; storing '' left the client with an empty registered grant, so
 * the authorize-grant scope clamp (request ∩ registered) could only ever yield
 * [], and every minted token was scopeless. Result: OAuth completes, the
 * connector "connects", then every op fails `insufficient_scope` with
 * `your_scopes: []` and never self-heals.
 *
 * The default is deliberately `read write`, never `admin`: a DCR client uses the
 * consent-bearing authorization_code flow, so everyday read+write is the safe
 * floor — an unauthenticated walk-in must not get the master key by default.
 * An explicit `scope` on the registration request is still honored verbatim and
 * still validated against ALLOWED_SCOPES.
 */
import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'bun:test';
import { PGLiteEngine } from '../src/core/pglite-engine.ts';
import { GBrainOAuthProvider } from '../src/core/oauth-provider.ts';
import { sqlQueryForEngine } from '../src/core/sql-query.ts';

let engine: PGLiteEngine;
let provider: GBrainOAuthProvider;
let sql: ReturnType<typeof sqlQueryForEngine>;

beforeAll(async () => {
  engine = new PGLiteEngine();
  await engine.connect({});
  await engine.initSchema();
  sql = sqlQueryForEngine(engine);
  provider = new GBrainOAuthProvider({ sql });
});

afterAll(async () => {
  await engine.disconnect();
});

beforeEach(async () => {
  await (engine as any).db.exec('DELETE FROM oauth_tokens');
  await (engine as any).db.exec('DELETE FROM oauth_codes');
  await (engine as any).db.exec('DELETE FROM oauth_clients');
});

// authorize() writes the granted scope into oauth_codes then redirects; we
// assert on the stored grant directly, so the redirect is a no-op.
const noopRes = { redirect() {} } as any;

async function dcrRegister(scope?: string) {
  // registerClient is optional on the SDK's clients-store interface (DCR is
  // opt-in per RFC 7591); GBrainClientsStore always implements it.
  return provider.clientsStore.registerClient!({
    client_name: 'dcr-test',
    redirect_uris: ['https://example.test/cb'],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    ...(scope !== undefined ? { scope } : {}),
  } as any);
}

async function authorizedScopes(clientId: string): Promise<string[]> {
  const client = await provider.clientsStore.getClient(clientId);
  expect(client).toBeTruthy();
  await provider.authorize(
    client!,
    {
      // Mirror a connector that omits `scope` on /authorize.
      scopes: undefined,
      codeChallenge: 'test-challenge',
      redirectUri: 'https://example.test/cb',
      state: 'xyz',
    } as any,
    noopRes,
  );
  const rows = (await sql`
    SELECT scopes FROM oauth_codes WHERE client_id = ${clientId}
  `) as Array<{ scopes: string[] }>;
  expect(rows.length).toBe(1);
  return (rows[0].scopes ?? []).sort();
}

describe('DCR registerClient() scope default — omitted scope becomes read write', () => {
  test('omitted scope → stored client scope defaults to "read write"', async () => {
    const reg = await dcrRegister(undefined);
    const client = await provider.clientsStore.getClient(reg.client_id);
    expect((client!.scope ?? '').split(' ').filter(Boolean).sort()).toEqual(['read', 'write']);
  });

  test('omitted scope → an omit-scope authorize grants read write (not [])', async () => {
    const reg = await dcrRegister(undefined);
    expect(await authorizedScopes(reg.client_id)).toEqual(['read', 'write']);
  });

  test('explicit scope on registration is honored verbatim (not overridden)', async () => {
    const reg = await dcrRegister('read');
    const client = await provider.clientsStore.getClient(reg.client_id);
    expect(client!.scope).toBe('read');
    expect(await authorizedScopes(reg.client_id)).toEqual(['read']);
  });

  test('empty-string scope on registration also defaults to read write', async () => {
    const reg = await dcrRegister('');
    const client = await provider.clientsStore.getClient(reg.client_id);
    expect((client!.scope ?? '').split(' ').filter(Boolean).sort()).toEqual(['read', 'write']);
  });
});

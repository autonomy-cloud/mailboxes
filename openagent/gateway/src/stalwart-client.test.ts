import { describe, expect, it, vi } from 'vitest';

import type { GatewayConfig } from './config.js';
import { StalwartClient } from './stalwart-client.js';

const config: GatewayConfig = {
  port: 6402,
  identityIssuer: 'https://id.openagent.md/oidc',
  identityJwksUrl: 'https://id.openagent.md/oidc/jwks',
  mailAudience: 'https://mail.openagent.md',
  mailDomain: 'agents.openagent.md',
  requiredScopes: ['mail:read'],
  stalwartBaseUrl: 'http://stalwart:8080',
  stalwartPublicUrl: 'https://inbox.openagent.md',
  stalwartMailHost: 'mail.openagent.md',
  stalwartSmtpSubmissionPort: 465,
  stalwartImapPort: 993,
  stalwartAdminUsername: 'admin',
  stalwartAdminPassword: 'a-long-test-password',
  stalwartServerHostname: 'mail.openagent.md',
  stalwartRequestTlsCertificate: false,
  stalwartAutoBootstrap: false,
  stalwartConfigureOpenAgentOidc: false,
  bootstrapOnly: false,
};

const session = {
  apiUrl: 'https://mail.openagent.md/jmap/',
  accounts: { admin: {} },
  primaryAccounts: { 'urn:ietf:params:jmap:mail': 'admin' },
};

function methodResponse() {
  return new Response(JSON.stringify({
    methodResponses: [['x:Action/set', { accountId: 'admin', created: {} }, 'openagent']],
  }), { headers: { 'Content-Type': 'application/json' } });
}

describe('StalwartClient.ensureBearerAccess', () => {
  it('accepts an agent token that Stalwart already authorizes', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    const client = new StalwartClient(config, fetchMock as unknown as typeof fetch);

    await expect(client.ensureBearerAccess('agent-token')).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('reloads OIDC settings and caches after a transient rejection', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(methodResponse())
      .mockResolvedValueOnce(methodResponse())
      .mockResolvedValueOnce(new Response(null, { status: 200 }));
    const client = new StalwartClient(config, fetchMock as unknown as typeof fetch);

    await expect(client.ensureBearerAccess('agent-token')).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });
});

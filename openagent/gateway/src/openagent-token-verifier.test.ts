import { describe, expect, it } from 'vitest';

import type { GatewayConfig } from './config.js';
import { validateAgentClaims } from './openagent-token-verifier.js';

const config: GatewayConfig = {
  port: 6402,
  identityIssuer: 'https://id.openagent.md/oidc',
  identityJwksUrl: 'https://id.openagent.md/oidc/jwks',
  mailAudience: 'https://mail.openagent.md',
  mailDomain: 'agents.openagent.md',
  requiredScopes: ['mail:read'],
  stalwartBaseUrl: 'http://stalwart:8080',
  stalwartPublicUrl: 'https://mail.openagent.md',
  stalwartAdminUsername: 'admin',
  stalwartAdminPassword: 'a-long-test-password',
  stalwartServerHostname: 'mail.openagent.md',
  stalwartAutoBootstrap: false,
  stalwartConfigureOpenAgentOidc: false,
};

function validClaims() {
  return {
    sub: 'agt_123',
    client_id: 'agt_123',
    agent: true,
    agent_id: 'agt_123',
    agent_name: 'Research agent',
    agent_email: 'agt_123@agents.openagent.md',
    agent_controller: { type: 'user', id: 'usr_123' },
    agent_runtime: 'codex',
    agent_runtime_instance: 'runtime_123',
    amr: ['agent_key'],
    scope: 'mail:read mail:send calendar:read',
    iat: 1_000,
    exp: 1_300,
    jti: 'token_123',
  };
}

describe('validateAgentClaims', () => {
  it('accepts a short-lived identity-bound mail token', () => {
    expect(validateAgentClaims(validClaims(), config)).toMatchObject({
      agentId: 'agt_123',
      agentEmail: 'agt_123@agents.openagent.md',
      runtime: 'codex',
    });
  });

  it('rejects an agent token bound to a different client', () => {
    const claims = { ...validClaims(), client_id: 'agt_other' };
    expect(() => validateAgentClaims(claims, config)).toThrow('exactly one OpenAgent identity');
  });

  it('rejects an address outside the agent domain', () => {
    const claims = { ...validClaims(), agent_email: 'agt_123@example.com' };
    expect(() => validateAgentClaims(claims, config)).toThrow('agents.openagent.md');
  });

  it('rejects a token without the approved mail scope', () => {
    const claims = { ...validClaims(), scope: 'workers:read' };
    expect(() => validateAgentClaims(claims, config)).toThrow('mail:read');
  });

  it('rejects a long-lived bearer token', () => {
    const claims = { ...validClaims(), exp: 2_000 };
    expect(() => validateAgentClaims(claims, config)).toThrow('lifetime');
  });
});

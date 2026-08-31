import { describe, expect, it } from 'vitest';

import { loadConfig } from './config.js';

const castNativeEnvironment: NodeJS.ProcessEnv = {
  STALWART_BASE_URL: 'http://stalwart:8080',
  STALWART_PUBLIC_URL: 'https://inbox.openagent.md',
  STALWART_MAIL_HOST: 'mail.openagent.md',
  STALWART_ADMIN_USERNAME: 'admin',
  STALWART_ADMIN_PASSWORD: 'a-long-test-password',
  CAST_MAILBOX_GATEWAY_TOKEN: 'a-separate-long-cast-service-token',
};

describe('gateway configuration', () => {
  it('starts Cast-native mode with no legacy Identity settings', () => {
    const config = loadConfig(castNativeEnvironment);
    expect(config.identityIssuer).toBeUndefined();
    expect(config.identityJwksUrl).toBeUndefined();
    expect(config.castMailboxGatewayToken).toBe(
      'a-separate-long-cast-service-token',
    );
  });

  it('requires legacy Identity only when legacy OIDC configuration is enabled', () => {
    expect(() => loadConfig({
      ...castNativeEnvironment,
      STALWART_CONFIGURE_OPENAGENT_OIDC: 'true',
    })).toThrow('OPENAGENT_IDENTITY_ISSUER is required');
  });

  it('normalizes and validates the explicit legacy cleanup allowlist', () => {
    expect(loadConfig({
      ...castNativeEnvironment,
      LEGACY_AGENT_MAIL_DOMAINS: 'Agents.Visca.AI, legacy.example.com agents.visca.ai',
    }).legacyAgentMailDomains).toEqual(['agents.visca.ai', 'legacy.example.com']);
    expect(() => loadConfig({
      ...castNativeEnvironment,
      LEGACY_AGENT_MAIL_DOMAINS: 'agents.openagent.md',
    })).toThrow('must not include OPENAGENT_MAIL_DOMAIN');
    expect(() => loadConfig({
      ...castNativeEnvironment,
      LEGACY_AGENT_MAIL_DOMAINS: 'https://agents.visca.ai',
    })).toThrow('invalid mail domain');
  });
});

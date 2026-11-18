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
  it('starts with the Cast service settings alone', () => {
    const config = loadConfig(castNativeEnvironment);
    expect(config.castMailboxGatewayToken).toBe(
      'a-separate-long-cast-service-token',
    );
    expect(config.stalwartAutoBootstrap).toBe(false);
    expect(config.stalwartConfigureCastMail).toBe(false);
  });

  it('ignores every retired Identity setting, whatever its value', () => {
    const expected = loadConfig(castNativeEnvironment);
    // What deployed ConfigMaps still carry.
    expect(loadConfig({
      ...castNativeEnvironment,
      STALWART_CONFIGURE_OPENAGENT_OIDC: 'false',
    })).toEqual(expected);
    // The settings no longer exist, so none of them can change the result.
    const config = loadConfig({
      ...castNativeEnvironment,
      OPENAGENT_IDENTITY_ISSUER: 'https://identity.example.test/oidc',
      OPENAGENT_IDENTITY_JWKS_URL: 'https://identity.example.test/oidc/jwks',
      OPENAGENT_MAIL_AUDIENCE: 'https://audience.example.test',
      OPENAGENT_REQUIRED_SCOPES: '',
      STALWART_CONFIGURE_OPENAGENT_OIDC: 'true',
      OPENAGENT_BOOTSTRAP_ONLY: 'true',
    });
    expect(config).toEqual(expected);
    expect(Object.keys(config).filter((key) => /identity|audience|scope|oidc|bootstrapOnly/iu.test(key)))
      .toEqual([]);
  });

  it('names the mail server after the mail host unless told otherwise', () => {
    expect(loadConfig({
      ...castNativeEnvironment,
      STALWART_MAIL_HOST: 'Mail.Example.Test',
    }).stalwartServerHostname).toBe('mail.example.test');
    expect(loadConfig({
      ...castNativeEnvironment,
      STALWART_MAIL_HOST: 'mail.example.test',
      STALWART_SERVER_HOSTNAME: 'Server.Example.Test',
    }).stalwartServerHostname).toBe('server.example.test');
  });

  it('normalizes and validates the explicit legacy cleanup allowlist', () => {
    expect(loadConfig({
      ...castNativeEnvironment,
      LEGACY_AGENT_MAIL_DOMAINS: 'Agents.Old.Example, legacy.example.com agents.old.example',
    }).legacyAgentMailDomains).toEqual(['agents.old.example', 'legacy.example.com']);
    expect(() => loadConfig({
      ...castNativeEnvironment,
      LEGACY_AGENT_MAIL_DOMAINS: 'agents.visca.ai',
    })).toThrow('must not include OPENAGENT_MAIL_DOMAIN');
    expect(() => loadConfig({
      ...castNativeEnvironment,
      LEGACY_AGENT_MAIL_DOMAINS: 'https://agents.visca.ai',
    })).toThrow('invalid mail domain');
  });
});

import { z } from 'zod';

const url = z.string().url().transform((value) => value.replace(/\/$/, ''));

const environmentSchema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(6402),
  OPENAGENT_IDENTITY_ISSUER: url,
  OPENAGENT_IDENTITY_JWKS_URL: url.optional(),
  OPENAGENT_MAIL_AUDIENCE: url.default('https://mail.openagent.md'),
  OPENAGENT_MAIL_DOMAIN: z.string().trim().min(3).default('agents.openagent.md'),
  OPENAGENT_REQUIRED_SCOPES: z.string().default('mail:read'),
  STALWART_BASE_URL: url,
  STALWART_PUBLIC_URL: url,
  STALWART_ADMIN_USERNAME: z.string().min(1),
  STALWART_ADMIN_PASSWORD: z.string().min(12),
  STALWART_SERVER_HOSTNAME: z.string().trim().min(3).default('mail.openagent.md'),
  STALWART_AUTO_BOOTSTRAP: z.enum(['true', 'false']).default('false'),
  STALWART_CONFIGURE_OPENAGENT_OIDC: z.enum(['true', 'false']).default('false'),
});

export type GatewayConfig = {
  port: number;
  identityIssuer: string;
  identityJwksUrl: string;
  mailAudience: string;
  mailDomain: string;
  requiredScopes: readonly string[];
  stalwartBaseUrl: string;
  stalwartPublicUrl: string;
  stalwartAdminUsername: string;
  stalwartAdminPassword: string;
  stalwartServerHostname: string;
  stalwartAutoBootstrap: boolean;
  stalwartConfigureOpenAgentOidc: boolean;
};

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const parsed = environmentSchema.parse(environment);
  const requiredScopes = parsed.OPENAGENT_REQUIRED_SCOPES.split(/[ ,]+/u).filter(Boolean);
  if (requiredScopes.length === 0) {
    throw new Error('OPENAGENT_REQUIRED_SCOPES must contain at least one scope');
  }

  return {
    port: parsed.PORT,
    identityIssuer: parsed.OPENAGENT_IDENTITY_ISSUER,
    identityJwksUrl:
      parsed.OPENAGENT_IDENTITY_JWKS_URL ?? `${parsed.OPENAGENT_IDENTITY_ISSUER}/jwks`,
    mailAudience: parsed.OPENAGENT_MAIL_AUDIENCE,
    mailDomain: parsed.OPENAGENT_MAIL_DOMAIN.toLowerCase(),
    requiredScopes,
    stalwartBaseUrl: parsed.STALWART_BASE_URL,
    stalwartPublicUrl: parsed.STALWART_PUBLIC_URL,
    stalwartAdminUsername: parsed.STALWART_ADMIN_USERNAME,
    stalwartAdminPassword: parsed.STALWART_ADMIN_PASSWORD,
    stalwartServerHostname: parsed.STALWART_SERVER_HOSTNAME.toLowerCase(),
    stalwartAutoBootstrap: parsed.STALWART_AUTO_BOOTSTRAP === 'true',
    stalwartConfigureOpenAgentOidc: parsed.STALWART_CONFIGURE_OPENAGENT_OIDC === 'true',
  };
}

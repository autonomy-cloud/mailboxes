import { z } from 'zod';

const url = z.string().url().transform((value) => value.replace(/\/$/, ''));

const environmentSchema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(6402),
  OPENAGENT_IDENTITY_ISSUER: url.optional(),
  OPENAGENT_IDENTITY_JWKS_URL: url.optional(),
  OPENAGENT_MAIL_AUDIENCE: url.default('https://mail.openagent.md'),
  OPENAGENT_MAIL_DOMAIN: z.string().trim().min(3).default('agents.openagent.md'),
  LEGACY_AGENT_MAIL_DOMAINS: z.string().default(''),
  OPENAGENT_REQUIRED_SCOPES: z.string().default('mail:read'),
  CAST_MAILBOX_GATEWAY_TOKEN: z.string().min(32).optional(),
  CAST_DKIM_SELECTOR: z.string().trim().regex(/^[a-z0-9][a-z0-9._-]{0,62}$/iu).default('cast1'),
  MAIL_PUBLIC_DELIVERY_CONFIGURED: z.enum(['true', 'false']).default('false'),
  CAST_AGENT_MAIL_WEBHOOK_URL: url.optional(),
  CAST_MAILBOX_WEBHOOK_SECRET: z.string().min(32).optional(),
  MAIL_TELEMETRY_WEBHOOK_SECRET: z.string().min(32).optional(),
  MAIL_TELEMETRY_WEBHOOK_CONFIGURED: z.enum(['true', 'false']).default('false'),
  STALWART_BASE_URL: url,
  STALWART_PUBLIC_URL: url,
  STALWART_MAIL_HOST: z.string().trim().min(3),
  STALWART_SMTP_SUBMISSION_PORT: z.coerce.number().int().min(1).max(65535).default(465),
  STALWART_IMAP_PORT: z.coerce.number().int().min(1).max(65535).default(993),
  STALWART_ADMIN_USERNAME: z.string().min(1),
  STALWART_ADMIN_PASSWORD: z.string().min(12),
  STALWART_SERVER_HOSTNAME: z.string().trim().min(3).default('mail.openagent.md'),
  STALWART_REQUEST_TLS_CERTIFICATE: z.enum(['true', 'false']).default('false'),
  STALWART_AUTO_BOOTSTRAP: z.enum(['true', 'false']).default('false'),
  STALWART_CONFIGURE_OPENAGENT_OIDC: z.enum(['true', 'false']).default('false'),
  STALWART_CONFIGURE_CAST_MAIL: z.enum(['true', 'false']).default('false'),
  OPENAGENT_BOOTSTRAP_ONLY: z.enum(['true', 'false']).default('false'),
});

export type GatewayConfig = {
  port: number;
  identityIssuer: string | undefined;
  identityJwksUrl: string | undefined;
  mailAudience: string;
  mailDomain: string;
  legacyAgentMailDomains: readonly string[];
  requiredScopes: readonly string[];
  castMailboxGatewayToken?: string;
  castDkimSelector: string;
  mailPublicDeliveryConfigured: boolean;
  castAgentMailWebhookUrl?: string;
  castMailboxWebhookSecret?: string;
  mailTelemetryWebhookSecret?: string;
  mailTelemetryWebhookConfigured: boolean;
  stalwartBaseUrl: string;
  stalwartPublicUrl: string;
  stalwartMailHost: string;
  stalwartSmtpSubmissionPort: number;
  stalwartImapPort: number;
  stalwartAdminUsername: string;
  stalwartAdminPassword: string;
  stalwartServerHostname: string;
  stalwartRequestTlsCertificate: boolean;
  stalwartAutoBootstrap: boolean;
  stalwartConfigureOpenAgentOidc: boolean;
  stalwartConfigureCastMail: boolean;
  bootstrapOnly: boolean;
};

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const parsed = environmentSchema.parse(environment);
  const requiredScopes = parsed.OPENAGENT_REQUIRED_SCOPES.split(/[ ,]+/u).filter(Boolean);
  const mailDomain = validMailDomain(parsed.OPENAGENT_MAIL_DOMAIN, 'OPENAGENT_MAIL_DOMAIN');
  const legacyAgentMailDomains = [...new Set(
    parsed.LEGACY_AGENT_MAIL_DOMAINS.split(/[ ,]+/u)
      .filter(Boolean)
      .map((domain) => validMailDomain(domain, 'LEGACY_AGENT_MAIL_DOMAINS')),
  )];
  if (legacyAgentMailDomains.includes(mailDomain)) {
    throw new Error('LEGACY_AGENT_MAIL_DOMAINS must not include OPENAGENT_MAIL_DOMAIN');
  }
  if (requiredScopes.length === 0) {
    throw new Error('OPENAGENT_REQUIRED_SCOPES must contain at least one scope');
  }
  if (!parsed.OPENAGENT_IDENTITY_ISSUER && parsed.OPENAGENT_IDENTITY_JWKS_URL) {
    throw new Error('OPENAGENT_IDENTITY_JWKS_URL requires OPENAGENT_IDENTITY_ISSUER');
  }
  if (parsed.STALWART_CONFIGURE_OPENAGENT_OIDC === 'true' && !parsed.OPENAGENT_IDENTITY_ISSUER) {
    throw new Error(
      'OPENAGENT_IDENTITY_ISSUER is required when STALWART_CONFIGURE_OPENAGENT_OIDC=true',
    );
  }

  return {
    port: parsed.PORT,
    identityIssuer: parsed.OPENAGENT_IDENTITY_ISSUER,
    identityJwksUrl: parsed.OPENAGENT_IDENTITY_ISSUER
      ? parsed.OPENAGENT_IDENTITY_JWKS_URL ?? `${parsed.OPENAGENT_IDENTITY_ISSUER}/jwks`
      : undefined,
    mailAudience: parsed.OPENAGENT_MAIL_AUDIENCE,
    mailDomain,
    legacyAgentMailDomains,
    requiredScopes,
    ...(parsed.CAST_MAILBOX_GATEWAY_TOKEN
      ? { castMailboxGatewayToken: parsed.CAST_MAILBOX_GATEWAY_TOKEN }
      : {}),
    castDkimSelector: parsed.CAST_DKIM_SELECTOR.toLowerCase(),
    mailPublicDeliveryConfigured: parsed.MAIL_PUBLIC_DELIVERY_CONFIGURED === 'true',
    ...(parsed.CAST_AGENT_MAIL_WEBHOOK_URL
      ? { castAgentMailWebhookUrl: parsed.CAST_AGENT_MAIL_WEBHOOK_URL }
      : {}),
    ...(parsed.CAST_MAILBOX_WEBHOOK_SECRET
      ? { castMailboxWebhookSecret: parsed.CAST_MAILBOX_WEBHOOK_SECRET }
      : {}),
    ...(parsed.MAIL_TELEMETRY_WEBHOOK_SECRET
      ? { mailTelemetryWebhookSecret: parsed.MAIL_TELEMETRY_WEBHOOK_SECRET }
      : {}),
    mailTelemetryWebhookConfigured: parsed.MAIL_TELEMETRY_WEBHOOK_CONFIGURED === 'true',
    stalwartBaseUrl: parsed.STALWART_BASE_URL,
    stalwartPublicUrl: parsed.STALWART_PUBLIC_URL,
    stalwartMailHost: parsed.STALWART_MAIL_HOST.toLowerCase(),
    stalwartSmtpSubmissionPort: parsed.STALWART_SMTP_SUBMISSION_PORT,
    stalwartImapPort: parsed.STALWART_IMAP_PORT,
    stalwartAdminUsername: parsed.STALWART_ADMIN_USERNAME,
    stalwartAdminPassword: parsed.STALWART_ADMIN_PASSWORD,
    stalwartServerHostname: parsed.STALWART_SERVER_HOSTNAME.toLowerCase(),
    stalwartRequestTlsCertificate: parsed.STALWART_REQUEST_TLS_CERTIFICATE === 'true',
    stalwartAutoBootstrap: parsed.STALWART_AUTO_BOOTSTRAP === 'true',
    stalwartConfigureOpenAgentOidc: parsed.STALWART_CONFIGURE_OPENAGENT_OIDC === 'true',
    stalwartConfigureCastMail: parsed.STALWART_CONFIGURE_CAST_MAIL === 'true',
    bootstrapOnly: parsed.OPENAGENT_BOOTSTRAP_ONLY === 'true',
  };
}

function validMailDomain(value: string, environmentName: string): string {
  const domain = value.trim().toLowerCase();
  if (
    domain.length > 253 ||
    !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(domain)
  ) {
    throw new Error(`${environmentName} contains an invalid mail domain: ${value}`);
  }
  return domain;
}

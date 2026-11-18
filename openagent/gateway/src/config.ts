import { z } from 'zod';

const url = z.string().url().transform((value) => value.replace(/\/$/, ''));

const environmentSchema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(6402),
  OPENAGENT_MAIL_DOMAIN: z.string().trim().min(3).default('agents.visca.ai'),
  LEGACY_AGENT_MAIL_DOMAINS: z.string().default(''),
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
  // The server's own name, written only by the one-time bootstrap. It is the
  // mail host unless a deployment says otherwise.
  STALWART_SERVER_HOSTNAME: z.string().trim().min(3).optional(),
  STALWART_REQUEST_TLS_CERTIFICATE: z.enum(['true', 'false']).default('false'),
  STALWART_AUTO_BOOTSTRAP: z.enum(['true', 'false']).default('false'),
  STALWART_CONFIGURE_CAST_MAIL: z.enum(['true', 'false']).default('false'),
});

export type GatewayConfig = {
  port: number;
  mailDomain: string;
  legacyAgentMailDomains: readonly string[];
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
  stalwartConfigureCastMail: boolean;
};

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const parsed = environmentSchema.parse(environment);
  const mailDomain = validMailDomain(parsed.OPENAGENT_MAIL_DOMAIN, 'OPENAGENT_MAIL_DOMAIN');
  const legacyAgentMailDomains = [...new Set(
    parsed.LEGACY_AGENT_MAIL_DOMAINS.split(/[ ,]+/u)
      .filter(Boolean)
      .map((domain) => validMailDomain(domain, 'LEGACY_AGENT_MAIL_DOMAINS')),
  )];
  if (legacyAgentMailDomains.includes(mailDomain)) {
    throw new Error('LEGACY_AGENT_MAIL_DOMAINS must not include OPENAGENT_MAIL_DOMAIN');
  }

  return {
    port: parsed.PORT,
    mailDomain,
    legacyAgentMailDomains,
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
    stalwartServerHostname: (parsed.STALWART_SERVER_HOSTNAME ?? parsed.STALWART_MAIL_HOST).toLowerCase(),
    stalwartRequestTlsCertificate: parsed.STALWART_REQUEST_TLS_CERTIFICATE === 'true',
    stalwartAutoBootstrap: parsed.STALWART_AUTO_BOOTSTRAP === 'true',
    stalwartConfigureCastMail: parsed.STALWART_CONFIGURE_CAST_MAIL === 'true',
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

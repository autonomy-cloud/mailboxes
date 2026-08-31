import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHmac } from 'node:crypto';
import { ZodError } from 'zod';

import {
  castCalendarEventCreateSchema,
  castCalendarEventDeleteSchema,
  castCalendarEventUpdateSchema,
  castMailboxEnsureSchema,
  castMailboxRetireSchema,
  castMailboxSendSchema,
  isValidCastServiceToken,
} from './cast-mailbox-api.js';
import { loadConfig } from './config.js';
import { OpenAgentTokenVerifier } from './openagent-token-verifier.js';
import { initializeStalwart } from './startup.js';
import { StalwartClient } from './stalwart-client.js';
import { telemetryAccountId } from './telemetry.js';

const config = loadConfig();
const verifier = config.identityIssuer && config.identityJwksUrl
  ? new OpenAgentTokenVerifier(config)
  : undefined;
const stalwart = new StalwartClient(config);

const server = createServer(async (request, response) => {
  try {
    await route(request, response);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    const status = error instanceof ClientRequestError ? error.status : 500;
    console.error(JSON.stringify({ level: status >= 500 ? 'error' : 'warn', message, path: request.url }));
    json(response, status, {
      error: status >= 500 ? 'internal_error' : 'invalid_request',
      message: status >= 500 ? 'Mailbox operation failed' : message,
    });
  }
});

async function route(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const url = new URL(request.url ?? '/', 'http://gateway.local');
  if (request.method === 'GET' && url.pathname === '/health/live') {
    json(response, 200, { status: 'ok' });
    return;
  }
  if (request.method === 'GET' && url.pathname === '/health/ready') {
    const ready = await stalwart.isReady();
    const backendCapabilities = ready
      ? await stalwart.serviceCapabilities()
      : {
          mailboxProvisioning: false,
          inboundReceiving: false,
          outboundDelivery: false,
          calendarSync: false,
        };
    const serviceProvisioningConfigured = Boolean(config.castMailboxGatewayToken);
    const inboundConfigured = Boolean(
      config.mailTelemetryWebhookConfigured &&
      config.mailTelemetryWebhookSecret &&
      config.castAgentMailWebhookUrl &&
      config.castMailboxWebhookSecret,
    );
    json(response, ready ? 200 : 503, {
      status: ready ? 'ready' : 'not_ready',
      capabilities: {
        mailboxProvisioning: ready && serviceProvisioningConfigured &&
          backendCapabilities.mailboxProvisioning,
        inboundReceiving: ready && inboundConfigured && backendCapabilities.inboundReceiving,
        outboundDelivery: ready && serviceProvisioningConfigured &&
          backendCapabilities.outboundDelivery,
        calendarSync: ready && serviceProvisioningConfigured && backendCapabilities.calendarSync,
      },
    });
    return;
  }
  if (request.method === 'POST' && url.pathname === '/v1/cast/mailboxes/ensure') {
    if (!authorizeCastRequest(request, response)) return;
    const input = await parseBody(request, castMailboxEnsureSchema);
    const mailbox = await stalwart.ensureCastMailbox(input);
    console.info(JSON.stringify({
      level: 'info',
      event: 'cast.mailbox.ensure',
      workspaceId: input.workspaceId,
      agentId: input.agentId,
      address: mailbox.address,
      created: mailbox.created,
      tenantCreated: mailbox.tenantCreated,
      domainCreated: mailbox.domainCreated,
    }));
    json(response, mailbox.created ? 201 : 200, {
      ...mailbox,
      jmapSessionUrl: `${config.stalwartPublicUrl}/.well-known/jmap`,
      smtpSubmission: {
        host: config.stalwartMailHost,
        port: config.stalwartSmtpSubmissionPort,
        tls: 'implicit',
      },
      imap: {
        host: config.stalwartMailHost,
        port: config.stalwartImapPort,
        tls: 'implicit',
      },
    });
    return;
  }
  if (request.method === 'GET' && url.pathname === '/v1/cast/mail/dkim') {
    if (!authorizeCastRequest(request, response)) return;
    const record = await stalwart.castDkimRecord();
    if (!record) {
      json(response, 503, {
        error: 'service_not_configured',
        message: 'Outbound mail signing is not ready',
      });
      return;
    }
    json(response, 200, record);
    return;
  }
  if (request.method === 'POST' && url.pathname === '/v1/cast/mailboxes/retire') {
    if (!authorizeCastRequest(request, response)) return;
    const input = await parseBody(request, castMailboxRetireSchema);
    const mailbox = await stalwart.retireCastMailbox(input);
    console.info(JSON.stringify({
      level: 'info',
      event: 'cast.mailbox.retire',
      workspaceId: input.workspaceId,
      agentId: input.agentId,
      address: mailbox.address,
      retired: mailbox.retired,
    }));
    json(response, 200, mailbox);
    return;
  }
  if (request.method === 'POST' && url.pathname === '/v1/cast/mailboxes/send') {
    if (!authorizeCastRequest(request, response)) return;
    const input = await parseBody(request, castMailboxSendSchema, 16 * 1024 * 1024);
    const sent = await stalwart.sendCastMailbox(input);
    console.info(JSON.stringify({
      level: 'info',
      event: 'cast.mailbox.send',
      workspaceId: input.workspaceId,
      agentId: input.agentId,
      accountId: sent.accountId,
      emailId: sent.emailId,
      submissionId: sent.submissionId,
      messageId: sent.messageId,
    }));
    json(response, 202, sent);
    return;
  }
  if (request.method === 'POST' && url.pathname === '/v1/cast/calendars/events') {
    if (!authorizeCastRequest(request, response)) return;
    const input = await parseBody(request, castCalendarEventCreateSchema);
    const event = await stalwart.createCastCalendarEvent(input);
    json(response, 201, event);
    return;
  }
  if (request.method === 'POST' && url.pathname === '/v1/mail-events/ingest') {
    if (
      !config.mailTelemetryWebhookConfigured ||
      !config.mailTelemetryWebhookSecret ||
      !config.castAgentMailWebhookUrl ||
      !config.castMailboxWebhookSecret
    ) {
      json(response, 503, {
        error: 'service_not_configured',
        message: 'Inbound mail forwarding is not configured',
      });
      return;
    }
    const raw = await readBody(request, 2 * 1024 * 1024);
    const suppliedSignature = request.headers['x-signature'];
    const expectedSignature = createHmac('sha256', config.mailTelemetryWebhookSecret)
      .update(raw)
      .digest('base64');
    if (
      typeof suppliedSignature !== 'string' ||
      !isValidCastServiceToken(suppliedSignature, expectedSignature)
    ) {
      json(response, 401, { error: 'invalid_signature' });
      return;
    }
    const payload = parseJson(raw);
    const events = telemetryEvents(payload);
    let accepted = 0;
    let forwarded = 0;
    let ignored = 0;
    let duplicates = 0;
    for (const event of events) {
      if (event.type !== 'message-ingest.ham' && event.type !== 'message-ingest.spam') continue;
      const data = event.data;
      let accountId: string;
      try {
        accountId = telemetryAccountId(data.accountId);
      } catch (error) {
        throw new ClientRequestError(
          error instanceof Error ? error.message : 'Telemetry event has an invalid accountId',
          400,
        );
      }
      const emailId = scalarId(data.id, 'id');
      const result = await stalwart.forwardInboundMailEvent({
        sourceId: `mail:${accountId}:${emailId}`,
        accountId,
        emailId,
        ...(typeof data.messageId === 'string' ? { messageId: data.messageId } : {}),
      });
      accepted += 1;
      if (result === 'forwarded') forwarded += 1;
      if (result === 'ignored') ignored += 1;
      if (result === 'duplicate') duplicates += 1;
    }
    json(response, 202, { accepted, forwarded, ignored, duplicates });
    return;
  }
  const calendarEventMatch = url.pathname.match(/^\/v1\/cast\/calendars\/events\/([^/]+)$/u);
  if (request.method === 'PUT' && calendarEventMatch) {
    if (!authorizeCastRequest(request, response)) return;
    const externalId = calendarExternalId(calendarEventMatch[1]);
    const input = await parseBody(request, castCalendarEventUpdateSchema);
    const event = await stalwart.updateCastCalendarEvent(externalId, input);
    json(response, 200, event);
    return;
  }
  if (request.method === 'DELETE' && calendarEventMatch) {
    if (!authorizeCastRequest(request, response)) return;
    const externalId = calendarExternalId(calendarEventMatch[1]);
    const input = await parseBody(request, castCalendarEventDeleteSchema);
    await stalwart.deleteCastCalendarEvent(externalId, input);
    json(response, 200, { externalId });
    return;
  }
  if (request.method === 'POST' && url.pathname === '/v1/mailboxes/ensure') {
    if (!verifier) {
      json(response, 503, {
        error: 'service_not_configured',
        message: 'Legacy identity-backed mailbox provisioning is not configured',
      });
      return;
    }
    const token = bearerToken(request);
    if (!token) {
      json(response, 401, { error: 'invalid_token', message: 'Bearer token required' });
      return;
    }

    let identity;
    try {
      identity = await verifier.verify(token);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Invalid token';
      json(response, 401, { error: 'invalid_token', message });
      return;
    }

    const mailbox = await stalwart.ensureMailbox(identity.agentEmail, identity.agentName);
    await stalwart.ensureBearerAccess(token);
    console.info(JSON.stringify({
      level: 'info',
      event: 'mailbox.ensure',
      agentId: identity.agentId,
      address: identity.agentEmail,
      created: mailbox.created,
      tokenId: identity.tokenId,
    }));
    json(response, mailbox.created ? 201 : 200, {
      ...mailbox,
      jmapSessionUrl: `${config.stalwartPublicUrl}/.well-known/jmap`,
      smtpSubmission: {
        host: config.stalwartMailHost,
        port: config.stalwartSmtpSubmissionPort,
        tls: 'implicit',
      },
      imap: {
        host: config.stalwartMailHost,
        port: config.stalwartImapPort,
        tls: 'implicit',
      },
    });
    return;
  }

  json(response, 404, { error: 'not_found' });
}

function authorizeCastRequest(
  request: IncomingMessage,
  response: ServerResponse,
): boolean {
  if (!config.castMailboxGatewayToken) {
    json(response, 503, {
      error: 'service_not_configured',
      message: 'Cast mailbox service authentication is not configured',
    });
    return false;
  }
  if (!isValidCastServiceToken(bearerToken(request), config.castMailboxGatewayToken)) {
    json(response, 401, { error: 'invalid_token', message: 'Valid bearer token required' });
    return false;
  }
  return true;
}

async function parseBody<T>(
  request: IncomingMessage,
  schema: { parse(input: unknown): T },
  maxBytes = 256 * 1024,
): Promise<T> {
  const raw = await readBody(request, maxBytes);
  const parsed = parseJson(raw);
  try {
    return schema.parse(parsed);
  } catch (error) {
    if (error instanceof ZodError) {
      throw new ClientRequestError('Request body does not match the mailbox API contract', 400);
    }
    throw error;
  }
}

async function readBody(request: IncomingMessage, maxBytes: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += buffer.byteLength;
    if (totalBytes > maxBytes) throw new ClientRequestError('Request body is too large', 413);
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

function parseJson(raw: Buffer): unknown {
  try {
    return JSON.parse(raw.toString('utf8'));
  } catch {
    throw new ClientRequestError('Request body must be valid JSON', 400);
  }
}

class ClientRequestError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

function calendarExternalId(encoded: string | undefined): string {
  let externalId: string;
  try {
    externalId = decodeURIComponent(encoded ?? '');
  } catch {
    throw new ClientRequestError('Invalid calendar event id', 400);
  }
  if (!/^[a-z0-9_-]{1,128}$/iu.test(externalId)) {
    throw new ClientRequestError('Invalid calendar event id', 400);
  }
  return externalId;
}

function telemetryEvents(payload: unknown): Array<{
  type: string;
  data: Record<string, unknown>;
}> {
  if (!isRecord(payload) || !Array.isArray(payload.events)) {
    throw new ClientRequestError('Telemetry payload must contain an events array', 400);
  }
  return payload.events.map((value) => {
    if (!isRecord(value) || typeof value.type !== 'string' || !isRecord(value.data)) {
      throw new ClientRequestError('Telemetry event is invalid', 400);
    }
    return { type: value.type, data: value.data };
  });
}

function scalarId(value: unknown, name: string): string {
  if (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 256 &&
    !/[\u0000-\u001f\u007f]/u.test(value)
  ) return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  throw new ClientRequestError(`Telemetry event is missing ${name}`, 400);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function bearerToken(request: IncomingMessage): string | undefined {
  const authorization = request.headers.authorization;
  const match = authorization?.match(/^Bearer\s+(.+)$/iu);
  return match?.[1];
}

function json(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  response.end(JSON.stringify(body));
}

if (
  config.stalwartAutoBootstrap ||
  config.stalwartConfigureOpenAgentOidc ||
  config.stalwartConfigureCastMail
) {
  const startup = await initializeStalwart({
    bootstrapIfNeeded: () => config.stalwartAutoBootstrap
      ? stalwart.bootstrapIfNeeded()
      : Promise.resolve(false),
    ensureOpenAgentOidc: async () => {
      if (config.stalwartConfigureOpenAgentOidc) await stalwart.ensureOpenAgentOidc();
      if (config.stalwartConfigureCastMail) await stalwart.ensureCastMailConfiguration();
    },
  }, {
    onRetry: (error, attempt) => {
      const message = error instanceof Error ? error.message : 'Unknown error';
      console.warn(JSON.stringify({
        level: 'warn',
        event: 'stalwart.initialization_retry',
        attempt,
        message,
      }));
    },
  });
  if (startup.bootstrapped) {
    console.info(JSON.stringify({
      level: 'info',
      event: 'stalwart.bootstrapped',
      hostname: config.stalwartServerHostname,
      domain: config.mailDomain,
    }));
  }
  if (config.stalwartConfigureOpenAgentOidc) {
    console.info(JSON.stringify({
      level: 'info',
      event: 'stalwart.oidc_configured',
      issuer: config.identityIssuer,
      audience: config.mailAudience,
    }));
  }
  if (config.stalwartConfigureCastMail) {
    console.info(JSON.stringify({
      level: 'info',
      event: 'cast_mail.signing_configured',
      domain: config.mailDomain,
      selector: config.castDkimSelector,
    }));
  }
}

if (config.bootstrapOnly) {
  console.info(JSON.stringify({ level: 'info', event: 'bootstrap.completed' }));
  process.exit(0);
}

server.listen(config.port, '0.0.0.0', () => {
  console.info(JSON.stringify({
    level: 'info',
    event: 'gateway.started',
    port: config.port,
    legacyIdentityConfigured: Boolean(verifier),
  }));
});

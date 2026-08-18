import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

import { loadConfig } from './config.js';
import { OpenAgentTokenVerifier } from './openagent-token-verifier.js';
import { initializeStalwart } from './startup.js';
import { StalwartClient } from './stalwart-client.js';

const config = loadConfig();
const verifier = new OpenAgentTokenVerifier(config);
const stalwart = new StalwartClient(config);

const server = createServer(async (request, response) => {
  try {
    await route(request, response);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    console.error(JSON.stringify({ level: 'error', message, path: request.url }));
    json(response, 500, { error: 'internal_error', message: 'Mailbox operation failed' });
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
    json(response, ready ? 200 : 503, { status: ready ? 'ready' : 'not_ready' });
    return;
  }
  if (request.method === 'POST' && url.pathname === '/v1/mailboxes/ensure') {
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

if (config.stalwartAutoBootstrap || config.stalwartConfigureOpenAgentOidc) {
  const startup = await initializeStalwart({
    bootstrapIfNeeded: () => config.stalwartAutoBootstrap
      ? stalwart.bootstrapIfNeeded()
      : Promise.resolve(false),
    ensureOpenAgentOidc: () => config.stalwartConfigureOpenAgentOidc
      ? stalwart.ensureOpenAgentOidc()
      : Promise.resolve(),
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
    issuer: config.identityIssuer,
    audience: config.mailAudience,
  }));
});

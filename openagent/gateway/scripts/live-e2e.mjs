import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import tls from 'node:tls';

const identityOrigin = process.env.OPENAGENT_LIVE_IDENTITY_ORIGIN ?? 'http://127.0.0.1:6201';
const managementOrigin = process.env.OPENAGENT_LIVE_MANAGEMENT_ORIGIN ?? 'http://127.0.0.1:6201';
const gatewayOrigin = process.env.OPENAGENT_LIVE_GATEWAY_ORIGIN ?? 'http://localhost:6402';
const stalwartOrigin = process.env.OPENAGENT_LIVE_STALWART_ORIGIN ?? 'http://localhost:6401';
const managementToken = process.env.OPENAGENT_LIVE_MANAGEMENT_TOKEN;
const managementApi = `${managementOrigin}/api`;
const mailAudience = 'https://mail.openagent.md';
const mailScopes = [
  'mail:read', 'mail:send', 'calendar:read', 'calendar:write',
  'contacts:read', 'contacts:write', 'files:read', 'files:write',
];
const jmapCapabilities = [
  'urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:blob', 'urn:ietf:params:jmap:mail',
  'urn:ietf:params:jmap:submission', 'urn:ietf:params:jmap:contacts',
  'urn:ietf:params:jmap:calendars', 'urn:ietf:params:jmap:filenode',
];

async function main() {
  if (!managementToken) throw new Error('OPENAGENT_LIVE_MANAGEMENT_TOKEN is required');

  try {
  checkpoint('services', await serviceHealth());
  const suffix = `${Date.now().toString(36)}-${randomUUID().slice(0, 6)}`;
  const sender = await enrollAgent(`mail-e2e-sender-${suffix}`);
  checkpoint('sender.enrolled', publicAgent(sender));
  const recipient = await enrollAgent(`mail-e2e-recipient-${suffix}`);
  checkpoint('recipient.enrolled', publicAgent(recipient));

  const senderMailbox = await ensureMailbox(sender.token);
  const recipientMailbox = await ensureMailbox(recipient.token);
  checkpoint('mailboxes.provisioned', { sender: senderMailbox.address, recipient: recipientMailbox.address });

  const senderSession = await discoverJmap(sender.token);
  const recipientSession = await discoverJmap(recipient.token);
  const senderAccountId = primaryAccountId(senderSession);
  const recipientAccountId = primaryAccountId(recipientSession);
  assert(senderAccountId === senderMailbox.accountId, 'sender account binding mismatch');
  assert(recipientAccountId === recipientMailbox.accountId, 'recipient account binding mismatch');

  const calendarId = await createObject(senderSession, sender.token, 'Calendar', {
    name: 'Agent work', description: 'OpenAgent live E2E calendar', sortOrder: 10, isSubscribed: true,
  });
  const addressBookId = await createObject(senderSession, sender.token, 'AddressBook', {
    name: 'Agent contacts', description: 'OpenAgent live E2E contacts', sortOrder: 10, isSubscribed: true,
  });
  const fileNodeId = await createObject(senderSession, sender.token, 'FileNode', {
    name: 'Agent files', parentId: null,
  });
  checkpoint('collaboration.created', { addressBookId, calendarId, fileNodeId });

  const artifacts = await createCollaborationArtifacts(senderSession, sender.token, {
    addressBookId,
    calendarId,
    fileNodeId,
    suffix,
  });
  checkpoint('collaboration.content.created', artifacts);

  await assertAccountIsolation(recipientSession, recipient.token, senderAccountId, calendarId);
  checkpoint('accounts.isolated', { recipientCannotReadSenderCalendar: true });

  const messageId = `<openagent-${suffix}@agents.openagent.md>`;
  await smtpSend({ from: sender.email, messageId, recipient: recipient.email, token: sender.token });
  await waitForMessage(recipientSession, recipient.token, messageId);
  checkpoint('mail.delivered', { from: sender.email, messageId, to: recipient.email });

  console.log(JSON.stringify({
    agents: [publicAgent(sender), publicAgent(recipient)], result: 'pass',
    verified: [
      'identity', 'mailbox', 'jmap', 'calendar', 'calendar-event', 'contacts',
      'contact-card', 'files', 'file-content', 'isolation', 'smtp',
    ],
  }));
  } catch (error) {
    console.error(JSON.stringify({ result: 'fail', message: compactError(error) }));
    process.exitCode = 1;
  }
}

async function serviceHealth() {
  const paths = [
    `${identityOrigin}/oidc/.well-known/openid-configuration`,
    `${gatewayOrigin}/health/ready`, `${stalwartOrigin}/healthz/ready`,
  ];
  const statuses = await Promise.all(paths.map(async (url) => (await fetch(url)).status));
  assert(statuses.every((status) => status >= 200 && status < 300), `unhealthy services: ${statuses}`);
  return { identity: statuses[0], gateway: statuses[1], stalwart: statuses[2] };
}

async function enrollAgent(localPart) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicJwk = { ...publicKey.export({ format: 'jwk' }), alg: 'EdDSA', use: 'sig' };
  const email = `${localPart}@agents.openagent.md`;
  const identity = await managementRequest('/agent-identities', {
    body: {
      controller: { entityId: 'mail-live-e2e', type: 'user' },
      customData: { purpose: 'OpenAgent mail live E2E verification' },
      description: 'OpenAgent mail live E2E verification', email, name: localPart,
    }, method: 'POST',
  });
  const agentId = identity.principal.id;
  const challenge = await managementRequest(`/agent-identities/${agentId}/key-challenges`, {
    body: {
      algorithm: 'EdDSA', publicJwk,
      runtimeInstance: {
        displayName: localPart, externalInstanceId: `mail-live-${localPart}`,
        integrationVersion: 'mailboxes-live-e2e/1', runtime: 'workers',
      },
    }, method: 'POST',
  });
  const proof = sign(null,
    Buffer.from(`openagent-challenge:${challenge.challengeId}:${challenge.nonce}`),
    privateKey).toString('base64url');
  await managementRequest(`/agent-identities/${agentId}/key-challenges/${challenge.challengeId}/verify`, {
    body: { nonce: challenge.nonce, signature: proof }, method: 'POST',
  });
  await managementRequest(`/agent-identities/${agentId}/approve`, { method: 'POST' });
  await managementRequest(`/agent-identities/${agentId}/service-grants`, {
    body: { scopes: mailScopes, service: 'mail' }, method: 'POST',
  });
  await managementRequest(`/agent-identities/${agentId}/service-grants/mail/approve`, { method: 'POST' });
  const token = await issueAgentToken(agentId, privateKey);
  const tokenHeader = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
  const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  assert(claims.email === email, 'agent token is missing its standard email claim');
  return {
    agentId,
    email,
    token,
    tokenAlgorithm: tokenHeader.alg,
    tokenKeyId: tokenHeader.kid,
  };
}

async function managementRequest(path, options) {
  const response = await fetch(`${managementApi}${path}`, {
    body: options.body ? JSON.stringify(options.body) : undefined,
    headers: { Authorization: `Bearer ${managementToken}`, ...(options.body ? { 'Content-Type': 'application/json' } : {}) },
    method: options.method,
  });
  const body = await readJson(response);
  if (!response.ok) throw new Error(`${options.method} ${path}: HTTP ${response.status} ${errorSummary(body)}`);
  return body;
}

async function issueAgentToken(agentId, privateKey) {
  const tokenEndpoint = `${identityOrigin}/oidc/token`;
  const now = Math.floor(Date.now() / 1000);
  const assertion = createJwt({
    aud: tokenEndpoint, exp: now + 120, iat: now, iss: agentId, jti: randomUUID(), sub: agentId,
  }, privateKey);
  const response = await fetch(tokenEndpoint, {
    body: new URLSearchParams({
      client_assertion: assertion,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_id: agentId, grant_type: 'client_credentials', resource: mailAudience,
      scope: mailScopes.join(' '),
    }),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, method: 'POST',
  });
  const body = await readJson(response);
  if (!response.ok || typeof body.access_token !== 'string') {
    throw new Error(`agent token: HTTP ${response.status} ${errorSummary(body)}`);
  }
  return body.access_token;
}

function createJwt(payload, privateKey) {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const unsigned = `${header}.${body}`;
  return `${unsigned}.${sign(null, Buffer.from(unsigned), privateKey).toString('base64url')}`;
}

async function ensureMailbox(token) {
  const response = await fetch(`${gatewayOrigin}/v1/mailboxes/ensure`, {
    headers: { Authorization: `Bearer ${token}` }, method: 'POST',
  });
  const body = await readJson(response);
  if (!response.ok) throw new Error(`mailbox ensure: HTTP ${response.status} ${errorSummary(body)}`);
  return body;
}

async function discoverJmap(token) {
  const response = await fetch(`${stalwartOrigin}/.well-known/jmap`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const body = await readJson(response);
  if (!response.ok) throw new Error(`JMAP discovery: HTTP ${response.status} ${errorSummary(body)}`);
  assert(typeof body.apiUrl === 'string', 'JMAP session missing apiUrl');
  return body;
}

async function createObject(session, token, type, object) {
  const result = await jmapCall(session, token, [
    `${type}/set`, { accountId: primaryAccountId(session), create: { live: object } }, `create-${type}`,
  ]);
  const created = result.created?.live;
  if (!created?.id) throw new Error(`${type}/set did not create object: ${errorSummary(result.notCreated)}`);
  return created.id;
}

async function createCollaborationArtifacts(session, token, ids) {
  const eventId = await createObject(session, token, 'CalendarEvent', {
    '@type': 'Event',
    calendarIds: { [ids.calendarId]: true },
    duration: 'PT30M',
    start: '2030-01-02T10:00:00',
    timeZone: 'UTC',
    title: 'OpenAgent live E2E event',
    uid: `openagent-${ids.suffix}@agents.openagent.md`,
    updated: new Date().toISOString().replace(/\.\d{3}Z$/u, 'Z'),
  });
  const contactId = await createObject(session, token, 'ContactCard', {
    '@type': 'Card',
    addressBookIds: { [ids.addressBookId]: true },
    emails: {
      work: { address: 'service@openagent.md', contexts: { work: true } },
    },
    name: { full: 'OpenAgent Service' },
    uid: `urn:uuid:${randomUUID()}`,
  });
  const file = await createFile(session, token, ids.fileNodeId);

  await assertObjectExists(session, token, 'CalendarEvent', eventId);
  await assertObjectExists(session, token, 'ContactCard', contactId);
  await assertObjectExists(session, token, 'FileNode', file.fileId);
  const blob = await jmapCall(session, token, [
    'Blob/get',
    { accountId: primaryAccountId(session), ids: [file.blobId], properties: ['data:asText'] },
    'verify-file-content',
  ]);
  assert(blob.list?.[0]?.['data:asText'] === 'OpenAgent file content', 'uploaded file content mismatch');
  return { contactId, eventId, fileId: file.fileId };
}

async function createFile(session, token, parentId) {
  const accountId = primaryAccountId(session);
  const response = await jmapRaw(session, token, [
    [
      'Blob/upload',
      { accountId, create: { content: { data: [{ 'data:asText': 'OpenAgent file content' }] } } },
      'upload-file-content',
    ],
    [
      'FileNode/set',
      {
        accountId,
        create: {
          file: {
            blobId: '#content',
            name: 'openagent-e2e.txt',
            parentId,
            type: 'text/plain',
          },
        },
      },
      'create-file-node',
    ],
  ]);
  const uploaded = response.methodResponses?.[0]?.[1]?.created?.content;
  const created = response.methodResponses?.[1]?.[1]?.created?.file;
  if (!uploaded?.id || !created?.id) {
    throw new Error(`file creation failed: ${JSON.stringify(response.methodResponses).slice(0, 800)}`);
  }
  return { blobId: uploaded.id, fileId: created.id };
}

async function assertObjectExists(session, token, type, id) {
  const result = await jmapCall(session, token, [
    `${type}/get`, { accountId: primaryAccountId(session), ids: [id] }, `verify-${type}`,
  ]);
  assert(result.list?.some((entry) => entry.id === id), `${type} ${id} was not persisted`);
}

async function assertAccountIsolation(session, token, foreignAccountId, calendarId) {
  const response = await jmapRaw(session, token, [
    ['Calendar/get', { accountId: foreignAccountId, ids: [calendarId] }, 'isolation'],
  ]);
  const [name, body] = response.methodResponses?.[0] ?? [];
  assert(name === 'error' || (Array.isArray(body?.notFound) && body.notFound.includes(calendarId)),
    'recipient unexpectedly read sender calendar');
}

async function jmapCall(session, token, methodCall) {
  const response = await jmapRaw(session, token, [methodCall]);
  const [name, body] = response.methodResponses?.[0] ?? [];
  if (name === 'error') throw new Error(`${methodCall[0]}: ${errorSummary(body)}`);
  return body;
}

async function jmapRaw(session, token, methodCalls) {
  const apiUrl = new URL(session.apiUrl, stalwartOrigin);
  const publicOrigin = new URL(stalwartOrigin);
  apiUrl.protocol = publicOrigin.protocol;
  apiUrl.host = publicOrigin.host;
  const response = await fetch(apiUrl, {
    body: JSON.stringify({ methodCalls, using: jmapCapabilities }),
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, method: 'POST',
  });
  const body = await readJson(response);
  if (!response.ok) throw new Error(`JMAP API: HTTP ${response.status} ${errorSummary(body)}`);
  return body;
}

async function smtpSend({ from, messageId, recipient, token }) {
  const channel = new SmtpChannel(tls.connect({
    host: '127.0.0.1',
    port: 6487,
    rejectUnauthorized: false,
  }));
  await channel.ready();
  await channel.expect(220);
  await channel.command('EHLO openagent.local', 250);
  const oauth = Buffer.from(`n,a=${from},\x01auth=Bearer ${token}\x01\x01`).toString('base64');
  await channel.command(`AUTH OAUTHBEARER ${oauth}`, 235);
  await channel.command(`MAIL FROM:<${from}>`, 250);
  await channel.command(`RCPT TO:<${recipient}>`, 250);
  await channel.command('DATA', 354);
  const message = [
    `From: ${from}`, `To: ${recipient}`, 'Subject: OpenAgent live E2E',
    `Message-ID: ${messageId}`, 'Date: ' + new Date().toUTCString(),
    'Content-Type: text/plain; charset=utf-8', '',
    'Authenticated OpenAgent delivery verification.', '.',
  ].join('\r\n');
  await channel.command(message, 250, true);
  await channel.command('QUIT', 221);
  channel.close();
}

class SmtpChannel {
  constructor(socket) {
    this.socket = socket;
    this.buffer = '';
    this.waiters = [];
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => { this.buffer += chunk; this.flush(); });
    socket.on('error', (error) => this.rejectAll(error));
    socket.on('close', () => this.rejectAll(new Error('SMTP connection closed')));
  }
  ready() {
    if (this.socket.encrypted && !this.socket.secureConnecting) return Promise.resolve();
    return new Promise((resolve, reject) => {
      this.socket.once('secureConnect', resolve);
      this.socket.once('error', reject);
    });
  }
  async command(command, code, sensitive = false) {
    this.socket.write(`${command}\r\n`);
    const response = await this.expect(code);
    if (response.code !== code) {
      throw new Error(`SMTP ${sensitive ? 'DATA' : command.split(' ', 1)[0]}: ${response.text}`);
    }
    return response;
  }
  expect(code) {
    return new Promise((resolve, reject) => { this.waiters.push({ code, resolve, reject }); this.flush(); });
  }
  flush() {
    if (this.waiters.length === 0) return;
    const lines = this.buffer.split(/\r?\n/);
    if (lines.length < 2) return;
    const firstCode = lines[0]?.slice(0, 3);
    let end = -1;
    for (let index = 0; index < lines.length - 1; index += 1) {
      if (lines[index]?.startsWith(`${firstCode} `)) { end = index; break; }
    }
    if (end < 0) return;
    const consumed = lines.slice(0, end + 1).join('\r\n') + '\r\n';
    this.buffer = lines.slice(end + 1).join('\r\n');
    const waiter = this.waiters.shift();
    waiter.resolve({ code: Number(firstCode), text: consumed.trim() });
  }
  rejectAll(error) { for (const waiter of this.waiters.splice(0)) waiter.reject(error); }
  detach() {
    this.socket.removeAllListeners('data'); this.socket.removeAllListeners('error');
    this.socket.removeAllListeners('close'); return this.socket;
  }
  close() { this.socket.end(); }
}

async function waitForMessage(session, token, messageId) {
  const accountId = primaryAccountId(session);
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const query = await jmapCall(session, token, [
      'Email/query', { accountId, limit: 50, sort: [{ isAscending: false, property: 'receivedAt' }] }, 'email-query',
    ]);
    if (query.ids?.length) {
      const get = await jmapCall(session, token, [
        'Email/get', { accountId, ids: query.ids, properties: ['messageId', 'subject'] }, 'email-get',
      ]);
      if (get.list?.some((email) => email.messageId?.includes(messageId.slice(1, -1)))) return;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`message ${messageId} was not delivered within 15 seconds`);
}

function primaryAccountId(session) {
  const primary = session.primaryAccounts ?? {};
  return primary['urn:ietf:params:jmap:mail'] ?? Object.values(primary)[0] ?? Object.keys(session.accounts ?? {})[0];
}
function publicAgent(agent) {
  return {
    agentId: agent.agentId,
    email: agent.email,
    tokenAlgorithm: agent.tokenAlgorithm,
    tokenKeyId: agent.tokenKeyId,
  };
}
function checkpoint(name, detail) { console.log(JSON.stringify({ checkpoint: name, ...detail })); }
function assert(condition, message) { if (!condition) throw new Error(message); }
async function readJson(response) {
  const text = await response.text();
  try { return text ? JSON.parse(text) : {}; } catch { return { message: text.slice(0, 300) }; }
}
function errorSummary(body) {
  if (!body || typeof body !== 'object') return String(body ?? '');
  return [body.error, body.error_description, body.message, body.type]
    .filter((value) => typeof value === 'string').join(' ').slice(0, 500);
}
function compactError(error) { return (error instanceof Error ? error.message : String(error)).slice(0, 1_000); }

await main();

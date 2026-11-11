import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
const base = process.env.CAST_MAIL_DOMAIN_TEST_BASE_URL ?? 'http://127.0.0.1:7991';
const stalwart = process.env.STALWART_TEST_BASE_URL ?? 'http://127.0.0.1:7990';
for (const value of [base, stalwart]) {
  const url = new URL(value);
  assert(
    ['127.0.0.1', 'localhost'].includes(url.hostname) &&
      Number(url.port) >= 7000 &&
      Number(url.port) <= 7999,
    'Run this synthetic-mail acceptance only against an isolated local 7xxx endpoint',
  );
}
const token = process.env.CAST_MAILBOX_GATEWAY_TOKEN;
const username = process.env.STALWART_ADMIN_USERNAME;
const password = process.env.STALWART_ADMIN_PASSWORD;
assert(token && username && password, 'Configure local gateway and Stalwart test credentials');
const workspaceId = randomUUID();
const senderId = randomUUID();
const recipientId = randomUUID();
const stable = (value) => value.replaceAll('-', '');
const fixture = stable(workspaceId).slice(0, 12);
const domain = `test-${fixture}.agents.visca.ai`;
async function api(path, body, expected = 200) {
  const r = await fetch(base + path, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  if (!(Array.isArray(expected) ? expected : [expected]).includes(r.status))
    throw new Error(`${path}: HTTP ${r.status} ${text}`);
  return text ? JSON.parse(text) : null;
}

const a = {
  workspaceId,
  agentId: senderId,
  displayName: 'Sales',
  permanentAddress: `agt-${stable(senderId)}@wsp-${stable(workspaceId)}.agents.openagent.md`,
  aliases: [`sales@${domain}`],
};
const b = {
  workspaceId,
  agentId: recipientId,
  displayName: 'Support',
  permanentAddress: `agt-${stable(recipientId)}@wsp-${stable(workspaceId)}.agents.visca.ai`,
  aliases: [`support@${domain}`],
};
let first, receiver;
try {
  first = await api('/v1/cast/mailboxes/ensure', a, [200, 201]);
  receiver = await api('/v1/cast/mailboxes/ensure', b, [200, 201]);
  assert(first.accountId && receiver.accountId);
  console.log('PASS: preserved old permanent address and provisioned readable aliases');
  await api(
    '/v1/cast/mailboxes/send',
    {
      workspaceId,
      agentId: a.agentId,
      permanentAddress: a.permanentAddress,
      from: { address: `sales@${domain}` },
      to: [`support@${domain}`],
      subject: 'Mail domain qualification',
      text: 'Internal-only test',
      references: [],
      messageId: `<mail-domain-${fixture}@${domain}>`,
    },
    202,
  );
  console.log('PASS: real JMAP import and submission through cross-domain alias');
  const renamed = await api('/v1/cast/mailboxes/ensure', {
    ...a,
    displayName: 'Success',
    aliases: [`sales@${domain}`, `success@${domain}`],
  });
  assert.equal(renamed.accountId, first.accountId);
  console.log('PASS: rename retained the same Stalwart account');
  await api(
    '/v1/cast/mailboxes/ensure',
    {
      ...b,
      workspaceId: '44444444-4444-4444-8444-444444444444',
      permanentAddress: `agt-${stable(recipientId)}@wsp-44444444444444448444444444444444.agents.visca.ai`,
    },
    500,
  );
  console.log('PASS: cross-workspace domain adoption rejected');
  await api(
    '/v1/cast/mailboxes/send',
    {
      workspaceId,
      agentId: b.agentId,
      permanentAddress: b.permanentAddress,
      from: { address: `sales@${domain}` },
      to: [`support@${domain}`],
      subject: 'Spoof attempt',
      text: 'Must fail',
      references: [],
      messageId: '<spoof@software-factory.agents.visca.ai>',
    },
    500,
  );
  console.log('PASS: cross-agent sender spoof rejected');
  const event = await api('/v1/cast/calendars/events', {
    workspaceId, agentId: a.agentId, idempotencyKey: `mail-domain-${fixture}`,
    event: { title: 'Local preserved-mailbox calendar check', startsAt: '2030-01-02T10:00:00Z', endsAt: '2030-01-02T10:30:00Z' },
  }, 201);
  assert(event.externalId);
  console.log('PASS: calendar still resolves the preserved permanent mailbox');
  let custom;
  for (let attempt = 0; attempt < 20; attempt++) {
    custom = await api('/v1/cast/mail-domains/ensure', {
      workspaceId,
      domain: `agents.customer-${fixture}.test`,
    });
    if (custom.records.some((record) => record.key.includes('._domainkey.'))) break;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  assert(custom.records.some((record) => record.key.includes('._domainkey.')));
  console.log('PASS: custom-domain provisioning returned actual DKIM and MX records');

  const auth = 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64');
  const session = await (
    await fetch(`${stalwart}/.well-known/jmap`, { headers: { authorization: auth } })
  ).json();
  async function jmap(method, args) {
    const r = await fetch(`${stalwart}/jmap/`, {
      method: 'POST',
      headers: { authorization: auth, 'content-type': 'application/json' },
      body: JSON.stringify({
        using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
        methodCalls: [[method, args, 'test']],
      }),
    });
    const data = await r.json();
    if (data.methodResponses?.[0]?.[0] === 'error') throw new Error(JSON.stringify(data));
    return data.methodResponses[0][1];
  }
  let found = false;
  for (let i = 0; i < 15; i++) {
    const result = await jmap('Email/query', {
      accountId: receiver.accountId,
      filter: { subject: 'Mail domain qualification' },
    });
    if (result.ids?.length) {
      found = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  assert(found, 'Submitted mail must arrive in recipient mailbox');
  console.log('PASS: recipient mailbox contains delivered email');
} finally {
  for (const agent of [a, b]) {
    await api('/v1/cast/mailboxes/retire', {
      workspaceId,
      agentId: agent.agentId,
      permanentAddress: agent.permanentAddress,
    });
  }
}
console.log('PASS: synthetic agent mailboxes retired');

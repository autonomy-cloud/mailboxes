import { describe, expect, it, vi } from 'vitest';

import type { GatewayConfig } from './config.js';
import { StalwartClient } from './stalwart-client.js';

const config: GatewayConfig = {
  port: 6402,
  identityIssuer: 'https://id.openagent.md/oidc',
  identityJwksUrl: 'https://id.openagent.md/oidc/jwks',
  mailAudience: 'https://mail.openagent.md',
  mailDomain: 'agents.openagent.md',
  legacyAgentMailDomains: [],
  castDkimSelector: 'cast1',
  mailPublicDeliveryConfigured: false,
  mailTelemetryWebhookConfigured: false,
  requiredScopes: ['mail:read'],
  stalwartBaseUrl: 'http://stalwart:8080',
  stalwartPublicUrl: 'https://inbox.openagent.md',
  stalwartMailHost: 'mail.openagent.md',
  stalwartSmtpSubmissionPort: 465,
  stalwartImapPort: 993,
  stalwartAdminUsername: 'admin',
  stalwartAdminPassword: 'a-long-test-password',
  stalwartServerHostname: 'mail.openagent.md',
  stalwartRequestTlsCertificate: false,
  stalwartAutoBootstrap: false,
  stalwartConfigureOpenAgentOidc: false,
  stalwartConfigureCastMail: false,
  bootstrapOnly: false,
  castAgentMailWebhookUrl: 'http://cast:3000/webhooks/messaging/agent-mail',
  castMailboxWebhookSecret: 'a-long-cast-mailbox-webhook-secret',
};

const session = {
  apiUrl: 'https://mail.openagent.md/jmap/',
  uploadUrl: 'https://mail.openagent.md/jmap/upload/{accountId}',
  downloadUrl: 'https://mail.openagent.md/jmap/download/{accountId}/{blobId}/{name}?type={type}',
  capabilities: {
    'urn:ietf:params:jmap:mail': {},
    'urn:ietf:params:jmap:submission': {},
    'urn:ietf:params:jmap:calendars': {},
  },
  accounts: {
    admin: {
      accountCapabilities: {
        'urn:stalwart:jmap': {},
      },
    },
  },
  primaryAccounts: { 'urn:ietf:params:jmap:mail': 'admin' },
};

function methodResponse() {
  return new Response(JSON.stringify({
    methodResponses: [['x:Action/set', { accountId: 'admin', created: {} }, 'openagent']],
  }), { headers: { 'Content-Type': 'application/json' } });
}

function registryResponse(method: string, payload: Record<string, unknown>) {
  return new Response(JSON.stringify({
    methodResponses: [[method, { accountId: 'admin', ...payload }, 'openagent']],
  }), { headers: { 'Content-Type': 'application/json' } });
}

function requestBody(fetchMock: ReturnType<typeof vi.fn>, callIndex: number) {
  const init = fetchMock.mock.calls[callIndex]?.[1] as RequestInit | undefined;
  return JSON.parse(String(init?.body)) as {
    methodCalls: Array<[string, Record<string, unknown>, string]>;
  };
}

describe('StalwartClient.ensureBearerAccess', () => {
  it('accepts an agent token that Stalwart already authorizes', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    const client = new StalwartClient(config, fetchMock as unknown as typeof fetch);

    await expect(client.ensureBearerAccess('agent-token')).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('reloads OIDC settings and caches after a transient rejection', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(methodResponse())
      .mockResolvedValueOnce(methodResponse())
      .mockResolvedValueOnce(new Response(null, { status: 200 }));
    const client = new StalwartClient(config, fetchMock as unknown as typeof fetch);

    await expect(client.ensureBearerAccess('agent-token')).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });
});

describe('StalwartClient Cast-native provisioning', () => {
  const input = {
    workspaceId: 'A1B2-C3D4',
    agentId: 'E5F6-7890',
    displayName: 'Sales agent',
    permanentAddress: 'agt-e5f67890@wsp-a1b2c3d4.agents.openagent.md',
    aliases: [
      'sales@wsp-a1b2c3d4.agents.openagent.md',
      'agt-e5f67890@wsp-a1b2c3d4.agents.openagent.md',
    ],
  };

  it('reports only backend capabilities present in the authenticated JMAP session', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify(session)));
    const client = new StalwartClient(config, fetchMock as unknown as typeof fetch);

    await expect(client.serviceCapabilities()).resolves.toEqual({
      mailboxProvisioning: true,
      inboundReceiving: true,
      outboundDelivery: false,
      calendarSync: true,
    });
  });

  it('does not accept a registry capability owned only by an unrelated account', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({
      ...session,
      accounts: {
        admin: { accountCapabilities: {} },
        unrelated: { accountCapabilities: { 'urn:stalwart:jmap': {} } },
      },
    })));
    const client = new StalwartClient(config, fetchMock as unknown as typeof fetch);

    await expect(client.serviceCapabilities()).resolves.toEqual({
      mailboxProvisioning: false,
      inboundReceiving: true,
      outboundDelivery: false,
      calendarSync: true,
    });
  });

  it('reports outbound delivery only after signing configuration and DNS proof match', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(registryResponse('x:Domain/query', { ids: ['base-domain'] }))
      .mockResolvedValueOnce(registryResponse('x:DkimSignature/query', { ids: ['dkim-1'] }))
      .mockResolvedValueOnce(registryResponse('x:DkimSignature/get', {
        list: [{
          id: 'dkim-1',
          '@type': 'Dkim1RsaSha256',
          selector: 'cast1',
          domainId: 'base-domain',
          stage: 'active',
          publicKey: 'PUBLICKEY',
        }],
      }))
      .mockResolvedValueOnce(registryResponse('x:SenderAuth/get', {
        list: [{
          id: 'singleton',
          dkimStrict: true,
          dkimSignDomain: { match: {}, else: "'agents.openagent.md'" },
        }],
      }));
    const dns = vi.fn().mockResolvedValue([
      ['v=DKIM1; k=rsa; h=sha256; p=PUBLICKEY'],
    ]);
    const client = new StalwartClient({
      ...config,
      mailPublicDeliveryConfigured: true,
    }, fetchMock as unknown as typeof fetch, dns);

    await expect(client.serviceCapabilities()).resolves.toMatchObject({
      outboundDelivery: true,
    });
    await expect(new StalwartClient({
      ...config,
      mailPublicDeliveryConfigured: true,
    }, fetchMock as unknown as typeof fetch, vi.fn().mockRejectedValue(new Error('NXDOMAIN')))
      .serviceCapabilities()).resolves.toMatchObject({ outboundDelivery: false });
  });

  it('reuses the active parent-domain RSA signer under cast1 without private-key export', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(registryResponse('x:Domain/query', { ids: ['base-domain'] }))
      .mockResolvedValueOnce(registryResponse('x:SenderAuth/set', { updated: { singleton: null } }))
      .mockResolvedValueOnce(registryResponse('x:DkimSignature/query', { ids: ['dkim-1'] }))
      .mockResolvedValueOnce(registryResponse('x:DkimSignature/get', {
        list: [{
          id: 'dkim-1',
          '@type': 'Dkim1RsaSha256',
          selector: 'v1-rsa-20260810',
          domainId: 'base-domain',
          stage: 'active',
          publicKey: 'PUBLICKEY',
        }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Domain/get', {
        list: [{ id: 'base-domain', dkimManagement: { '@type': 'Automatic' } }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Domain/set', { updated: { 'base-domain': null } }))
      .mockResolvedValueOnce(registryResponse('x:DkimSignature/set', { updated: { 'dkim-1': null } }))
      .mockResolvedValueOnce(methodResponse())
      .mockResolvedValueOnce(methodResponse());
    const client = new StalwartClient({
      ...config,
      stalwartConfigureCastMail: true,
    }, fetchMock as unknown as typeof fetch);

    await expect(client.ensureCastMailConfiguration()).resolves.toBeUndefined();
    expect(requestBody(fetchMock, 2).methodCalls[0]).toEqual([
      'x:SenderAuth/set',
      expect.objectContaining({
        update: {
          singleton: {
            dkimSignDomain: { match: {}, else: "'agents.openagent.md'" },
            dkimStrict: true,
          },
        },
      }),
      'openagent',
    ]);
    expect(requestBody(fetchMock, 7).methodCalls[0]).toEqual([
      'x:DkimSignature/set',
      expect.objectContaining({
        update: {
          'dkim-1': { selector: 'cast1' },
        },
      }),
      'openagent',
    ]);
    expect(JSON.stringify(requestBody(fetchMock, 7))).not.toContain('privateKey');
  });

  it('creates a tenant-bound workspace domain and tenant-bound mailbox', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(registryResponse('x:Tenant/query', { ids: [] }))
      .mockResolvedValueOnce(registryResponse('x:Tenant/set', {
        created: { workspace: { id: 'tenant-1' } },
      }))
      .mockResolvedValueOnce(registryResponse('x:Domain/query', { ids: [] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/set', {
        created: { workspace: { id: 'domain-1' } },
      }))
      .mockResolvedValueOnce(registryResponse('x:Account/query', { ids: [] }))
      .mockResolvedValueOnce(registryResponse('x:Account/set', {
        created: { mailbox: { id: 'account-1' } },
      }))
      .mockResolvedValueOnce(methodResponse());
    const client = new StalwartClient(config, fetchMock as unknown as typeof fetch);

    await expect(client.ensureCastMailbox(input)).resolves.toEqual({
      accountId: 'account-1',
      address: input.permanentAddress,
      aliases: ['sales@wsp-a1b2c3d4.agents.openagent.md'],
      created: true,
      tenantId: 'tenant-1',
      domainId: 'domain-1',
      domain: 'wsp-a1b2c3d4.agents.openagent.md',
      tenantCreated: true,
      domainCreated: true,
      legacyCleanup: [],
    });

    expect(requestBody(fetchMock, 2).methodCalls[0]).toEqual([
      'x:Tenant/set',
      expect.objectContaining({
        accountId: 'admin',
        create: {
          workspace: {
            name: 'cast-workspace:a1b2-c3d4',
            roles: { '@type': 'Default' },
            permissions: { '@type': 'Inherit' },
            quotas: {},
          },
        },
      }),
      'openagent',
    ]);
    expect(requestBody(fetchMock, 4).methodCalls[0]).toEqual([
      'x:Domain/set',
      expect.objectContaining({
        accountId: 'admin',
        create: {
          workspace: expect.objectContaining({
            name: 'wsp-a1b2c3d4.agents.openagent.md',
            memberTenantId: 'tenant-1',
            isEnabled: true,
            certificateManagement: { '@type': 'Manual' },
            dkimManagement: { '@type': 'Manual' },
            dnsManagement: { '@type': 'Manual' },
          }),
        },
      }),
      'openagent',
    ]);
    expect(requestBody(fetchMock, 6).methodCalls[0]).toEqual([
      'x:Account/set',
      expect.objectContaining({
        accountId: 'admin',
        create: {
          mailbox: expect.objectContaining({
            '@type': 'User',
            name: 'agt-e5f67890',
            domainId: 'domain-1',
            memberTenantId: 'tenant-1',
            aliases: {
              '0': {
                enabled: true,
                name: 'sales',
                domainId: 'domain-1',
                description: 'Cast agent alias',
              },
            },
          }),
        },
      }),
      'openagent',
    ]);
  });

  it('removes only the exact tenant-owned legacy mailbox and an empty legacy domain', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(registryResponse('x:Tenant/query', { ids: ['tenant-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/query', { ids: ['domain-new'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/get', {
        list: [{ id: 'domain-new', memberTenantId: 'tenant-1' }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Account/query', { ids: ['account-new'] }))
      .mockResolvedValueOnce(registryResponse('x:Account/get', {
        list: [{ id: 'account-new', memberTenantId: 'tenant-1' }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Account/set', { updated: { 'account-new': null } }))
      .mockResolvedValueOnce(registryResponse('x:Domain/query', { ids: ['domain-old'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/get', {
        list: [{ id: 'domain-old', memberTenantId: 'tenant-1' }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Account/query', { ids: ['account-old'] }))
      .mockResolvedValueOnce(registryResponse('x:Account/get', {
        list: [{ id: 'account-old', memberTenantId: 'tenant-1' }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Account/set', { destroyed: ['account-old'] }))
      .mockResolvedValueOnce(registryResponse('x:Account/query', { ids: [] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/set', { destroyed: ['domain-old'] }))
      .mockResolvedValueOnce(methodResponse());
    const client = new StalwartClient({
      ...config,
      legacyAgentMailDomains: ['agents.visca.ai'],
    }, fetchMock as unknown as typeof fetch);

    await expect(client.ensureCastMailbox(input)).resolves.toMatchObject({
      address: input.permanentAddress,
      legacyCleanup: [{
        baseDomain: 'agents.visca.ai',
        domain: 'wsp-a1b2c3d4.agents.visca.ai',
        address: 'agt-e5f67890@wsp-a1b2c3d4.agents.visca.ai',
        accountRemoved: true,
        domainRemoved: true,
      }],
    });
    expect(requestBody(fetchMock, 11).methodCalls[0]).toEqual([
      'x:Account/set',
      expect.objectContaining({ accountId: 'admin', destroy: ['account-old'] }),
      'openagent',
    ]);
    expect(requestBody(fetchMock, 13).methodCalls[0]).toEqual([
      'x:Domain/set',
      expect.objectContaining({ accountId: 'admin', destroy: ['domain-old'] }),
      'openagent',
    ]);
  });

  it('refuses legacy cleanup when the old domain is owned by another tenant', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(registryResponse('x:Tenant/query', { ids: ['tenant-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/query', { ids: ['domain-new'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/get', {
        list: [{ id: 'domain-new', memberTenantId: 'tenant-1' }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Account/query', { ids: ['account-new'] }))
      .mockResolvedValueOnce(registryResponse('x:Account/get', {
        list: [{ id: 'account-new', memberTenantId: 'tenant-1' }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Account/set', { updated: { 'account-new': null } }))
      .mockResolvedValueOnce(registryResponse('x:Domain/query', { ids: ['domain-old'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/get', {
        list: [{ id: 'domain-old', memberTenantId: 'tenant-other' }],
      }));
    const client = new StalwartClient({
      ...config,
      legacyAgentMailDomains: ['agents.visca.ai'],
    }, fetchMock as unknown as typeof fetch);

    await expect(client.ensureCastMailbox(input)).rejects.toThrow(
      'belongs to tenant tenant-other, expected tenant-1',
    );
    expect(fetchMock).toHaveBeenCalledTimes(9);
  });

  it('updates aliases and reactivates quotas without duplicating existing objects', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(registryResponse('x:Tenant/query', { ids: ['tenant-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/query', { ids: ['domain-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/get', {
        list: [{ id: 'domain-1', memberTenantId: 'tenant-1' }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Account/query', { ids: ['account-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Account/get', {
        list: [{ id: 'account-1', memberTenantId: 'tenant-1' }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Account/set', { updated: { 'account-1': null } }))
      .mockResolvedValueOnce(methodResponse());
    const client = new StalwartClient(config, fetchMock as unknown as typeof fetch);

    const result = await client.ensureCastMailbox(input);
    expect(result.created).toBe(false);
    expect(result.tenantCreated).toBe(false);
    expect(result.domainCreated).toBe(false);
    expect(requestBody(fetchMock, 6).methodCalls[0]?.[1]).toEqual(expect.objectContaining({
      update: {
        'account-1': expect.objectContaining({
          description: 'Sales agent',
          quotas: {},
        }),
      },
    }));
  });

  it('refuses to adopt a workspace domain owned by another tenant', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(registryResponse('x:Tenant/query', { ids: ['tenant-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/query', { ids: ['domain-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/get', {
        list: [{ id: 'domain-1', memberTenantId: 'tenant-2' }],
      }));
    const client = new StalwartClient(config, fetchMock as unknown as typeof fetch);

    await expect(client.ensureCastMailbox(input)).rejects.toThrow(
      'belongs to tenant tenant-2, expected tenant-1',
    );
  });

  it('retires reversibly by blocking new data and disabling aliases', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(registryResponse('x:Tenant/query', { ids: ['tenant-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/query', { ids: ['domain-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/get', {
        list: [{ id: 'domain-1', memberTenantId: 'tenant-1' }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Account/query', { ids: ['account-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Account/get', {
        list: [{
          id: 'account-1',
          memberTenantId: 'tenant-1',
          aliases: {
            '0': { enabled: true, name: 'sales', domainId: 'domain-1' },
          },
        }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Account/set', { updated: { 'account-1': null } }))
      .mockResolvedValueOnce(methodResponse());
    const client = new StalwartClient(config, fetchMock as unknown as typeof fetch);

    await expect(client.retireCastMailbox({
      workspaceId: input.workspaceId,
      agentId: input.agentId,
      permanentAddress: input.permanentAddress,
    })).resolves.toEqual({
      accountId: 'account-1',
      address: input.permanentAddress,
      retired: true,
    });
    expect(requestBody(fetchMock, 6).methodCalls[0]?.[1]).toEqual(expect.objectContaining({
      update: {
        'account-1': expect.objectContaining({
          aliases: {
            '0': { enabled: false, name: 'sales', domainId: 'domain-1' },
          },
          quotas: {
            maxDiskQuota: 1,
            maxEmails: 0,
            maxEmailSubmissions: 0,
            maxCalendarEvents: 0,
            maxContactCards: 0,
            maxFiles: 0,
          },
        }),
      },
    }));
  });

  it('uploads, imports and submits outbound mail as the tenant-bound account', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(registryResponse('x:Tenant/query', { ids: ['tenant-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/query', { ids: ['domain-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/get', {
        list: [{ id: 'domain-1', memberTenantId: 'tenant-1' }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Account/query', { ids: ['account-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Account/get', {
        list: [{
          id: 'account-1',
          memberTenantId: 'tenant-1',
          aliases: {
            '0': { enabled: true, name: 'sales', domainId: 'domain-1' },
          },
        }],
      }))
      .mockResolvedValueOnce(registryResponse('Identity/get', {
        list: [{ id: 'identity-1', email: 'sales@wsp-a1b2c3d4.agents.openagent.md' }],
      }))
      .mockResolvedValueOnce(registryResponse('Mailbox/query', { ids: ['drafts-1'] }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ blobId: 'blob-1' })))
      .mockResolvedValueOnce(registryResponse('Email/import', {
        created: { outbound: { id: 'email-1' } },
      }))
      .mockResolvedValueOnce(registryResponse('EmailSubmission/set', {
        created: { outbound: { id: 'submission-1' } },
      }));
    const client = new StalwartClient(config, fetchMock as unknown as typeof fetch);

    await expect(client.sendCastMailbox({
      workspaceId: input.workspaceId,
      agentId: input.agentId,
      from: { address: 'sales@wsp-a1b2c3d4.agents.openagent.md', name: 'Sales Agent' },
      to: ['buyer@example.com'],
      cc: [],
      bcc: ['audit@example.com'],
      subject: 'Hello',
      messageId: '<cast-test@wsp-a1b2c3d4.agents.openagent.md>',
      text: 'Plain body',
      references: [],
      attachments: [{
        filename: 'note.txt',
        contentType: 'text/plain',
        contentBase64: Buffer.from('attachment').toString('base64'),
      }],
    })).resolves.toEqual({
      accountId: 'account-1',
      emailId: 'email-1',
      submissionId: 'submission-1',
      messageId: expect.stringMatching(/^<.+@wsp-a1b2c3d4\.agents\.openagent\.md>$/u),
    });

    expect(fetchMock.mock.calls[8]?.[0]).toBe(
      'http://stalwart:8080/jmap/upload/account-1',
    );
    const upload = fetchMock.mock.calls[8]?.[1] as RequestInit;
    expect(upload.headers).toEqual(expect.objectContaining({
      'Content-Type': 'message/rfc5322',
    }));
    const raw = Buffer.from(upload.body as Uint8Array).toString('utf8');
    expect(raw).toContain('From: "Sales Agent" <sales@wsp-a1b2c3d4.agents.openagent.md>');
    expect(raw).toContain('To: buyer@example.com');
    expect(raw).not.toContain('Bcc:');
    expect(raw).toContain("filename*=UTF-8''note.txt");

    expect(requestBody(fetchMock, 9).methodCalls[0]).toEqual([
      'Email/import',
      expect.objectContaining({
        accountId: 'account-1',
        emails: {
          outbound: expect.objectContaining({
            blobId: 'blob-1',
            mailboxIds: { 'drafts-1': true },
            keywords: { '$draft': true },
          }),
        },
      }),
      'openagent',
    ]);
    expect(requestBody(fetchMock, 10).methodCalls[0]).toEqual([
      'EmailSubmission/set',
      expect.objectContaining({
        accountId: 'account-1',
        create: {
          outbound: {
            emailId: 'email-1',
            identityId: 'identity-1',
            envelope: {
              mailFrom: { email: 'sales@wsp-a1b2c3d4.agents.openagent.md' },
              rcptTo: [{ email: 'buyer@example.com' }, { email: 'audit@example.com' }],
            },
          },
        },
      }),
      'openagent',
    ]);
  });

  it('creates an idempotent UTC calendar event in the agent default calendar', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(registryResponse('x:Tenant/query', { ids: ['tenant-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/query', { ids: ['domain-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Domain/get', {
        list: [{ id: 'domain-1', memberTenantId: 'tenant-1' }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Account/query', { ids: ['account-1'] }))
      .mockResolvedValueOnce(registryResponse('x:Account/get', {
        list: [{ id: 'account-1', memberTenantId: 'tenant-1' }],
      }))
      .mockResolvedValueOnce(registryResponse('CalendarEvent/query', { ids: [] }))
      .mockResolvedValueOnce(registryResponse('Calendar/get', {
        list: [{ id: 'calendar-1', isDefault: true }],
      }))
      .mockResolvedValueOnce(registryResponse('CalendarEvent/set', {
        created: { event: { id: 'event-1' } },
      }));
    const client = new StalwartClient(config, fetchMock as unknown as typeof fetch);

    await expect(client.createCastCalendarEvent({
      workspaceId: input.workspaceId,
      agentId: input.agentId,
      idempotencyKey: 'cast-event-123',
      event: {
        title: 'Customer call',
        startsAt: '2030-01-02T10:00:00+00:00',
        endsAt: '2030-01-02T10:30:00+00:00',
        description: 'Discuss renewal',
        location: 'Video room',
      },
    })).resolves.toEqual({ externalId: 'event-1' });

    expect(requestBody(fetchMock, 8).methodCalls[0]).toEqual([
      'CalendarEvent/set',
      expect.objectContaining({
        accountId: 'account-1',
        create: {
          event: expect.objectContaining({
            '@type': 'Event',
            title: 'Customer call',
            start: '2030-01-02T10:00:00',
            timeZone: 'Etc/UTC',
            duration: 'PT1800S',
            calendarIds: { 'calendar-1': true },
            description: 'Discuss renewal',
            locations: {
              'cast-location': { '@type': 'Location', name: 'Video room' },
            },
          }),
        },
      }),
      'openagent',
    ]);
  });

  it('downloads an inbound raw message and forwards it with a stable source id', async () => {
    const rawMessage = Buffer.from(
      'From: buyer@example.com\r\nTo: sales@example.com\r\nMessage-ID: <incoming@example.com>\r\n\r\nHello',
    );
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(registryResponse('x:Account/get', {
        list: [{
          id: 'account-1',
          name: 'agt-e5f67890',
          domainId: 'domain-1',
          memberTenantId: 'tenant-1',
        }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Domain/get', {
        list: [{
          id: 'domain-1',
          name: 'wsp-a1b2c3d4.agents.openagent.md',
          memberTenantId: 'tenant-1',
        }],
      }))
      .mockResolvedValueOnce(registryResponse('Email/get', {
        list: [{ id: 'email-1', blobId: 'blob-1' }],
      }))
      .mockResolvedValueOnce(new Response(rawMessage))
      .mockResolvedValueOnce(new Response(null, { status: 202 }));
    const client = new StalwartClient(config, fetchMock as unknown as typeof fetch);

    await expect(client.forwardInboundMailEvent({
      sourceId: 'mail:account-1:email-1',
      accountId: 'account-1',
      emailId: 'email-1',
      messageId: '<incoming@example.com>',
    })).resolves.toBe('forwarded');

    expect(fetchMock.mock.calls[4]?.[0]).toBe(
      'http://stalwart:8080/jmap/download/account-1/blob-1/message.eml?type=message%2Frfc822',
    );
    expect(fetchMock.mock.calls[5]?.[0]).toBe(
      'http://cast:3000/webhooks/messaging/agent-mail',
    );
    const webhook = fetchMock.mock.calls[5]?.[1] as RequestInit;
    expect(webhook.headers).toEqual(expect.objectContaining({
      'Content-Type': 'message/rfc822',
      'agent-mail-webhook-auth': 'a-long-cast-mailbox-webhook-secret',
      'agent-mail-recipient': 'agt-e5f67890@wsp-a1b2c3d4.agents.openagent.md',
      'agent-mail-source-id': 'mail:account-1:email-1',
      'agent-mail-message-id': '<incoming@example.com>',
    }));
    expect(Buffer.from(webhook.body as Uint8Array)).toEqual(rawMessage);

    await expect(client.forwardInboundMailEvent({
      sourceId: 'mail:account-1:email-1',
      accountId: 'account-1',
      emailId: 'email-1',
    })).resolves.toBe('duplicate');
    expect(fetchMock).toHaveBeenCalledTimes(6);
  });

  it('ignores non-Cast and cross-tenant inbound accounts without downloading mail', async () => {
    const outsideFetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(registryResponse('x:Account/get', {
        list: [{
          id: 'account-1',
          name: 'someone',
          domainId: 'domain-1',
          memberTenantId: 'tenant-1',
        }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Domain/get', {
        list: [{ id: 'domain-1', name: 'example.com', memberTenantId: 'tenant-1' }],
      }));
    const outsideClient = new StalwartClient(config, outsideFetch as unknown as typeof fetch);
    await expect(outsideClient.forwardInboundMailEvent({
      sourceId: 'mail:account-1:email-1',
      accountId: 'account-1',
      emailId: 'email-1',
    })).resolves.toBe('ignored');
    expect(outsideFetch).toHaveBeenCalledTimes(3);

    const crossTenantFetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(registryResponse('x:Account/get', {
        list: [{
          id: 'account-2',
          name: 'agt-e5f67890',
          domainId: 'domain-2',
          memberTenantId: 'tenant-1',
        }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Domain/get', {
        list: [{
          id: 'domain-2',
          name: 'wsp-a1b2c3d4.agents.openagent.md',
          memberTenantId: 'tenant-2',
        }],
      }));
    const crossTenantClient = new StalwartClient(
      config,
      crossTenantFetch as unknown as typeof fetch,
    );
    await expect(crossTenantClient.forwardInboundMailEvent({
      sourceId: 'mail:account-2:email-2',
      accountId: 'account-2',
      emailId: 'email-2',
    })).resolves.toBe('ignored');
    expect(crossTenantFetch).toHaveBeenCalledTimes(3);
  });

  it('treats an oversized raw message as a terminal ignored event', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(session)))
      .mockResolvedValueOnce(registryResponse('x:Account/get', {
        list: [{
          id: 'account-1',
          name: 'agt-e5f67890',
          domainId: 'domain-1',
          memberTenantId: 'tenant-1',
        }],
      }))
      .mockResolvedValueOnce(registryResponse('x:Domain/get', {
        list: [{
          id: 'domain-1',
          name: 'wsp-a1b2c3d4.agents.openagent.md',
          memberTenantId: 'tenant-1',
        }],
      }))
      .mockResolvedValueOnce(registryResponse('Email/get', {
        list: [{ id: 'email-1', blobId: 'blob-1' }],
      }))
      .mockResolvedValueOnce(new Response('too large', {
        headers: { 'Content-Length': String(25 * 1024 * 1024 + 1) },
      }));
    const client = new StalwartClient(config, fetchMock as unknown as typeof fetch);

    await expect(client.forwardInboundMailEvent({
      sourceId: 'mail:account-1:email-1',
      accountId: 'account-1',
      emailId: 'email-1',
    })).resolves.toBe('ignored');
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });
});

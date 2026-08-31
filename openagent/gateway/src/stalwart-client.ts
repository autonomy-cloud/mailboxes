import type { GatewayConfig } from './config.js';
import { createHash, randomUUID } from 'node:crypto';
import { resolveTxt } from 'node:dns/promises';
import {
  permanentMailboxAddress,
  workspaceDomain,
  type CastMailboxEnsureInput,
  type CastMailboxRetireInput,
  type CastMailboxSendInput,
  type CastCalendarEvent,
  type CastCalendarEventCreateInput,
  type CastCalendarEventDeleteInput,
  type CastCalendarEventUpdateInput,
} from './cast-mailbox-api.js';

const CORE_CAPABILITY = 'urn:ietf:params:jmap:core';
const STALWART_CAPABILITY = 'urn:stalwart:jmap';
const MAIL_CAPABILITY = 'urn:ietf:params:jmap:mail';
const SUBMISSION_CAPABILITY = 'urn:ietf:params:jmap:submission';
const CALENDAR_CAPABILITY = 'urn:ietf:params:jmap:calendars';
const MAX_INBOUND_MESSAGE_BYTES = 25 * 1024 * 1024;
const INBOUND_REPLAY_TTL_MS = 60 * 60 * 1_000;
const MAX_INBOUND_REPLAY_ENTRIES = 10_000;

type JmapMethodCall = [name: string, arguments: Record<string, unknown>, callId: string];
type JmapMethodResponse = [name: string, response: Record<string, unknown>, callId: string];

type JmapSession = {
  apiUrl: string;
  uploadUrl?: string;
  downloadUrl?: string;
  capabilities?: Record<string, unknown>;
  accounts: Record<string, {
    accountCapabilities?: Record<string, unknown>;
  }>;
  primaryAccounts?: Record<string, string>;
};

export type ProvisionedMailbox = {
  accountId: string;
  address: string;
  created: boolean;
};

export type ProvisionedCastMailbox = ProvisionedMailbox & {
  tenantId: string;
  domainId: string;
  domain: string;
  aliases: string[];
  tenantCreated: boolean;
  domainCreated: boolean;
  legacyCleanup: LegacyMailboxCleanupResult[];
};

export type LegacyMailboxCleanupResult = {
  baseDomain: string;
  domain: string;
  address: string;
  accountRemoved: boolean;
  domainRemoved: boolean;
};

export type RetiredCastMailbox = {
  accountId?: string;
  address: string;
  retired: boolean;
};

export type SentCastMailboxMessage = {
  accountId: string;
  emailId: string;
  submissionId: string;
  messageId: string;
};

export type InboundMailTelemetryEvent = {
  sourceId: string;
  accountId: string;
  emailId: string;
  messageId?: string;
};

export type InboundMailForwardResult = 'forwarded' | 'ignored' | 'duplicate';

export type MailServiceCapabilities = {
  mailboxProvisioning: boolean;
  inboundReceiving: boolean;
  outboundDelivery: boolean;
  calendarSync: boolean;
};

export type CastDkimRecord = {
  domain: string;
  selector: string;
  dnsName: string;
  txtValue: string;
  algorithm: 'rsa-sha256';
  dnsPublished: boolean;
};

export class StalwartClient {
  readonly #config: GatewayConfig;
  readonly #fetch: typeof fetch;
  readonly #resolveTxt: typeof resolveTxt;
  readonly #inboundReplayCache = new Map<string, number>();
  readonly #inboundInFlight = new Map<string, Promise<InboundMailForwardResult>>();

  constructor(
    config: GatewayConfig,
    fetchImplementation: typeof fetch = fetch,
    resolveTxtImplementation: typeof resolveTxt = resolveTxt,
  ) {
    this.#config = config;
    this.#fetch = fetchImplementation;
    this.#resolveTxt = resolveTxtImplementation;
  }

  async isReady(): Promise<boolean> {
    try {
      const response = await this.#fetch(`${this.#config.stalwartBaseUrl}/healthz/ready`, {
        headers: { 'X-Forwarded-For': '127.0.0.1' },
        signal: AbortSignal.timeout(3_000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  async serviceCapabilities(): Promise<MailServiceCapabilities> {
    try {
      const session = await this.#session();
      const capabilities = asRecord(session.capabilities);
      const adminAccountId = primaryAccountId(session);
      const adminCapabilities = asRecord(
        session.accounts[adminAccountId]?.accountCapabilities,
      );
      // The registry extension is account-scoped. Fail closed unless the
      // administrator account selected for registry calls owns it; a grant on
      // an unrelated account must never advertise provisioning readiness.
      const hasRegistry = Object.hasOwn(adminCapabilities, STALWART_CAPABILITY);
      const hasMail = Object.hasOwn(capabilities, MAIL_CAPABILITY);
      const hasSubmission = Object.hasOwn(capabilities, SUBMISSION_CAPABILITY);
      const hasCalendar = Object.hasOwn(capabilities, CALENDAR_CAPABILITY);
      const signing = this.#config.mailPublicDeliveryConfigured && hasSubmission
        ? await this.#castDkimRecord(session)
        : undefined;
      return {
        mailboxProvisioning: hasRegistry,
        inboundReceiving: hasMail && Boolean(session.downloadUrl),
        outboundDelivery: hasMail && hasSubmission && Boolean(session.uploadUrl) &&
          signing?.dnsPublished === true,
        calendarSync: hasCalendar,
      };
    } catch {
      return unavailableMailServiceCapabilities();
    }
  }

  async castDkimRecord(): Promise<CastDkimRecord | undefined> {
    return this.#castDkimRecord(await this.#session());
  }

  async ensureCastMailConfiguration(): Promise<void> {
    const session = await this.#session();
    const adminAccountId = primaryAccountId(session);
    const domainId = await this.#findDomain(
      session.apiUrl,
      adminAccountId,
      this.#config.mailDomain,
    );
    if (!domainId) {
      throw new Error(`Base mail domain ${this.#config.mailDomain} is not configured`);
    }

    const senderAuth = await this.#call(session.apiUrl, adminAccountId, 'x:SenderAuth/set', {
      update: {
        singleton: {
          dkimSignDomain: {
            match: {},
            else: `'${this.#config.mailDomain}'`,
          },
          dkimStrict: true,
        },
      },
    });
    assertNoSetFailures(senderAuth, 'Parent-domain sender authentication configuration');

    const activeRsaSignatures = await this.#activeParentRsaSignatures(
      session.apiUrl,
      adminAccountId,
      domainId,
    );
    if (activeRsaSignatures.length !== 1) {
      throw new Error(
        `Expected exactly one active RSA signer for ${this.#config.mailDomain}, found ${activeRsaSignatures.length}`,
      );
    }
    const domain = await this.#registryObject(
      session.apiUrl,
      adminAccountId,
      'Domain',
      domainId,
    );
    if (asRecord(domain.dkimManagement)['@type'] === 'Automatic') {
      const manual = await this.#call(session.apiUrl, adminAccountId, 'x:Domain/set', {
        update: { [domainId]: { dkimManagement: { '@type': 'Manual' } } },
      });
      assertNoSetFailures(manual, 'Stable parent-domain DKIM freeze');
    }
    const signature = activeRsaSignatures[0];
    if (!signature) {
      throw new Error('Active parent-domain RSA signer disappeared during configuration');
    }
    if (signature.selector !== this.#config.castDkimSelector) {
      const signatureId = requiredString(signature.id, 'Active RSA signer id');
      const renamed = await this.#call(session.apiUrl, adminAccountId, 'x:DkimSignature/set', {
        update: { [signatureId]: { selector: this.#config.castDkimSelector } },
      });
      assertNoSetFailures(renamed, 'Stable parent-domain DKIM selector');
    }
    await this.#reloadSettings(session.apiUrl, adminAccountId);
    await this.#invalidateCaches(session.apiUrl, adminAccountId);
  }

  async ensureBearerAccess(token: string): Promise<void> {
    if (await this.#hasBearerAccess(token)) return;

    const session = await this.#session();
    const adminAccountId = primaryAccountId(session);
    await this.#reloadSettings(session.apiUrl, adminAccountId);
    await this.#invalidateCaches(session.apiUrl, adminAccountId);

    if (!(await this.#hasBearerAccess(token))) {
      throw new Error('Stalwart rejected the provisioned agent bearer token');
    }
  }

  async bootstrapIfNeeded(): Promise<boolean> {
    const session = await this.#session();
    const adminAccountId = primaryAccountId(session);
    const response = await this.#call(session.apiUrl, adminAccountId, 'x:Bootstrap/get', {});
    const bootstrap = Array.isArray(response.list) ? response.list[0] : undefined;
    if (!isRecord(bootstrap)) {
      return false;
    }

    const update = {
      serverHostname: this.#config.stalwartServerHostname,
      defaultDomain: this.#config.mailDomain,
      requestTlsCertificate: this.#config.stalwartRequestTlsCertificate,
      generateDkimKeys: true,
      dataStore: bootstrap.dataStore,
      blobStore: bootstrap.blobStore,
      searchStore: bootstrap.searchStore,
      inMemoryStore: bootstrap.inMemoryStore,
      directory: { '@type': 'Internal' },
      tracer: bootstrap.tracer,
      dnsServer: bootstrap.dnsServer,
    };
    const setResponse = await this.#call(session.apiUrl, adminAccountId, 'x:Bootstrap/set', {
      update: { singleton: update },
    });
    const notUpdated = asRecord(setResponse.notUpdated);
    if (Object.keys(notUpdated).length > 0) {
      throw new Error(`Stalwart bootstrap failed: ${JSON.stringify(notUpdated)}`);
    }
    return true;
  }

  async ensureOpenAgentOidc(): Promise<void> {
    const session = await this.#session();
    const adminAccountId = primaryAccountId(session);
    const domainId = await this.#findDomain(
      session.apiUrl,
      adminAccountId,
      this.#config.mailDomain,
    );
    if (!domainId) {
      throw new Error(`Stalwart domain ${this.#config.mailDomain} is not configured`);
    }

    const query = await this.#call(session.apiUrl, adminAccountId, 'x:Directory/query', {});
    const directoryIds = stringIds(query.ids);
    let directoryId: string | undefined;
    let directories: Record<string, unknown>[] = [];
    if (directoryIds.length > 0) {
      const get = await this.#call(session.apiUrl, adminAccountId, 'x:Directory/get', {
        ids: directoryIds,
      });
      directories = Array.isArray(get.list)
        ? get.list.filter(isRecord)
        : [];
      const existing = directories.find(
        (entry) =>
          entry['@type'] === 'Oidc' &&
          entry.issuerUrl === this.#config.identityIssuer,
      );
      if (isRecord(existing) && typeof existing.id === 'string') {
        directoryId = existing.id;
      }
    }

    if (!directoryId) {
      const created = await this.#call(session.apiUrl, adminAccountId, 'x:Directory/set', {
        create: {
          openagent: {
            '@type': 'Oidc',
            description: 'OpenAgent Identity',
            issuerUrl: this.#config.identityIssuer,
            requireAudience: this.#config.mailAudience,
            requireScopes: Object.fromEntries(
              this.#config.requiredScopes.map((scope) => [scope, true]),
            ),
            claimUsername: 'agent_email',
            claimName: 'agent_name',
          },
        },
      });
      const notCreated = asRecord(created.notCreated);
      if (Object.keys(notCreated).length > 0) {
        throw new Error(`Stalwart OIDC directory creation failed: ${JSON.stringify(notCreated)}`);
      }
      directoryId = requiredString(
        asRecord(asRecord(created.created).openagent).id,
        'created directory id',
      );
    }

    const canonicalOidc = {
      description: 'OpenAgent Identity',
      issuerUrl: this.#config.identityIssuer,
      requireAudience: this.#config.mailAudience,
      requireScopes: Object.fromEntries(
        this.#config.requiredScopes.map((scope) => [scope, true]),
      ),
      claimUsername: 'agent_email',
      claimName: 'agent_name',
    };

    const legacyUpdates = Object.fromEntries(
      directories
        .filter(
          (entry) =>
            entry.id !== directoryId &&
            entry['@type'] === 'Oidc' &&
            entry.description === 'OpenAgent Identity',
        )
        .map((entry) => [requiredString(entry.id, 'legacy directory id'), canonicalOidc]),
    );
    if (Object.keys(legacyUpdates).length > 0) {
      const normalized = await this.#call(session.apiUrl, adminAccountId, 'x:Directory/set', {
        update: legacyUpdates,
      });
      const notUpdated = asRecord(normalized.notUpdated);
      if (Object.keys(notUpdated).length > 0) {
        throw new Error(`Stalwart legacy OIDC normalization failed: ${JSON.stringify(notUpdated)}`);
      }
    }

    const updated = await this.#call(session.apiUrl, adminAccountId, 'x:Domain/set', {
      update: { [domainId]: { directoryId } },
    });
    const notUpdated = asRecord(updated.notUpdated);
    if (Object.keys(notUpdated).length > 0) {
      throw new Error(`Stalwart domain OIDC binding failed: ${JSON.stringify(notUpdated)}`);
    }
    await this.#ensureDefaultDirectory(session.apiUrl, adminAccountId, directoryId);
    await this.#reloadSettings(session.apiUrl, adminAccountId);
    await this.#invalidateCaches(session.apiUrl, adminAccountId);
  }

  async #ensureDefaultDirectory(
    apiUrl: string,
    accountId: string,
    directoryId: string,
  ): Promise<void> {
    const current = await this.#call(apiUrl, accountId, 'x:Authentication/get', {});
    const list = Array.isArray(current.list) ? current.list : [];
    const userRoleId = await this.#findUserRole(apiUrl, accountId);
    const authentication = {
      directoryId,
      defaultUserRoleIds: { [userRoleId]: true },
    };
    const response = await this.#call(apiUrl, accountId, 'x:Authentication/set',
      list.length > 0
        ? { update: { singleton: authentication } }
        : { create: { singleton: authentication } },
    );
    const failed = {
      ...asRecord(response.notCreated),
      ...asRecord(response.notUpdated),
    };
    if (Object.keys(failed).length > 0) {
      throw new Error(`Stalwart default OIDC binding failed: ${JSON.stringify(failed)}`);
    }
  }

  async #findUserRole(apiUrl: string, accountId: string): Promise<string> {
    const query = await this.#call(apiUrl, accountId, 'x:Role/query', {});
    const ids = stringIds(query.ids);
    const response = await this.#call(apiUrl, accountId, 'x:Role/get', { ids });
    const roles = Array.isArray(response.list) ? response.list.filter(isRecord) : [];
    const userRole = roles.find((role) => role.description === 'User');
    return requiredString(userRole?.id, 'Stalwart User role id');
  }

  async ensureMailbox(address: string, displayName: string): Promise<ProvisionedMailbox> {
    const [localPart, domain] = splitAddress(address);
    const session = await this.#session();
    const adminAccountId = primaryAccountId(session);
    const domainId = await this.#findDomain(session.apiUrl, adminAccountId, domain);
    if (!domainId) {
      throw new Error(
        `Stalwart domain ${domain} is not configured; bootstrap or create it before provisioning agents`,
      );
    }

    const existingAccountId = await this.#findAccount(
      session.apiUrl,
      adminAccountId,
      localPart,
      domainId,
    );
    if (existingAccountId) {
      return { accountId: existingAccountId, address, created: false };
    }

    const response = await this.#call(session.apiUrl, adminAccountId, 'x:Account/set', {
      create: {
        mailbox: {
          '@type': 'User',
          name: localPart,
          domainId,
          credentials: {},
          encryptionAtRest: { '@type': 'Disabled' },
          permissions: { '@type': 'Inherit' },
          roles: { '@type': 'User' },
          locale: 'en_US',
          description: displayName,
        },
      },
    });
    const notCreated = asRecord(response.notCreated);
    if (Object.keys(notCreated).length > 0) {
      throw new Error(`Stalwart account creation failed: ${JSON.stringify(notCreated)}`);
    }
    const created = asRecord(asRecord(response.created).mailbox);
    const accountId = requiredString(created.id, 'created account id');
    await this.#invalidateCaches(session.apiUrl, adminAccountId);
    return { accountId, address, created: true };
  }

  async ensureCastMailbox(input: CastMailboxEnsureInput): Promise<ProvisionedCastMailbox> {
    const address = permanentMailboxAddress(
      input.agentId,
      input.workspaceId,
      this.#config.mailDomain,
    );
    if (input.permanentAddress.toLowerCase() !== address) {
      throw new Error(`permanentAddress must be ${address}`);
    }

    const domain = workspaceDomain(input.workspaceId, this.#config.mailDomain);
    const aliases = normalizeWorkspaceAliases(input.aliases, address, domain);
    const [localPart] = splitAddress(address);
    const session = await this.#session();
    const adminAccountId = primaryAccountId(session);
    const tenant = await this.#ensureCastTenant(
      session.apiUrl,
      adminAccountId,
      input.workspaceId,
    );
    const workspaceMailDomain = await this.#ensureCastDomain(
      session.apiUrl,
      adminAccountId,
      domain,
      tenant.id,
      input.workspaceId,
    );
    const mailbox = await this.#ensureCastAccount(
      session.apiUrl,
      adminAccountId,
      localPart,
      workspaceMailDomain.id,
      tenant.id,
      input.displayName,
      aliases,
    );
    const legacyCleanup: LegacyMailboxCleanupResult[] = [];
    for (const legacyBaseDomain of this.#config.legacyAgentMailDomains) {
      legacyCleanup.push(await this.#removeLegacyCastMailbox({
        apiUrl: session.apiUrl,
        adminAccountId,
        tenantId: tenant.id,
        workspaceId: input.workspaceId,
        agentId: input.agentId,
        legacyBaseDomain,
      }));
    }
    await this.#invalidateCaches(session.apiUrl, adminAccountId);
    return {
      accountId: mailbox.id,
      address,
      aliases,
      created: mailbox.created,
      tenantId: tenant.id,
      domainId: workspaceMailDomain.id,
      domain,
      tenantCreated: tenant.created,
      domainCreated: workspaceMailDomain.created,
      legacyCleanup,
    };
  }

  async retireCastMailbox(input: CastMailboxRetireInput): Promise<RetiredCastMailbox> {
    const address = permanentMailboxAddress(
      input.agentId,
      input.workspaceId,
      this.#config.mailDomain,
    );
    if (input.permanentAddress.toLowerCase() !== address) {
      throw new Error(`permanentAddress must be ${address}`);
    }

    const session = await this.#session();
    const adminAccountId = primaryAccountId(session);
    const tenantId = await this.#findTenant(
      session.apiUrl,
      adminAccountId,
      castTenantName(input.workspaceId),
    );
    if (!tenantId) return { address, retired: false };

    const domain = workspaceDomain(input.workspaceId, this.#config.mailDomain);
    const domainId = await this.#findDomain(session.apiUrl, adminAccountId, domain);
    if (!domainId) return { address, retired: false };
    await this.#assertObjectTenant(
      session.apiUrl,
      adminAccountId,
      'Domain',
      domainId,
      tenantId,
    );

    const [localPart] = splitAddress(address);
    const accountId = await this.#findAccount(
      session.apiUrl,
      adminAccountId,
      localPart,
      domainId,
    );
    if (!accountId) return { address, retired: false };
    const account = await this.#registryObject(
      session.apiUrl,
      adminAccountId,
      'Account',
      accountId,
    );
    assertMemberTenant(account, tenantId, 'account');
    const aliases = disableAliases(account.aliases);
    const response = await this.#call(session.apiUrl, adminAccountId, 'x:Account/set', {
      update: {
        [accountId]: {
          aliases,
          description: `Retired Cast agent ${input.agentId}`,
          quotas: {
            maxDiskQuota: 1,
            maxEmails: 0,
            maxEmailSubmissions: 0,
            maxCalendarEvents: 0,
            maxContactCards: 0,
            maxFiles: 0,
          },
        },
      },
    });
    assertNoSetFailures(response, 'Stalwart account retirement');
    await this.#invalidateCaches(session.apiUrl, adminAccountId);
    return { accountId, address, retired: true };
  }

  async sendCastMailbox(input: CastMailboxSendInput): Promise<SentCastMailboxMessage> {
    const canonicalAddress = permanentMailboxAddress(
      input.agentId,
      input.workspaceId,
      this.#config.mailDomain,
    );
    const from = input.from.address.toLowerCase();
    const domain = workspaceDomain(input.workspaceId, this.#config.mailDomain);
    const session = await this.#session();
    const adminAccountId = primaryAccountId(session);
    const tenantId = await this.#findTenant(
      session.apiUrl,
      adminAccountId,
      castTenantName(input.workspaceId),
    );
    if (!tenantId) throw new Error('Cast workspace mailbox tenant is not provisioned');
    const domainId = await this.#findDomain(session.apiUrl, adminAccountId, domain);
    if (!domainId) throw new Error('Cast workspace mail domain is not provisioned');
    await this.#assertObjectTenant(
      session.apiUrl,
      adminAccountId,
      'Domain',
      domainId,
      tenantId,
    );
    const [localPart] = splitAddress(canonicalAddress);
    const accountId = await this.#findAccount(
      session.apiUrl,
      adminAccountId,
      localPart,
      domainId,
    );
    if (!accountId) throw new Error('Cast agent mailbox is not provisioned');
    const account = await this.#registryObject(
      session.apiUrl,
      adminAccountId,
      'Account',
      accountId,
    );
    assertMemberTenant(account, tenantId, 'account');
    const allowedSenders = accountAddresses(account, canonicalAddress, domain);
    if (!allowedSenders.has(from)) {
      throw new Error(`Sender ${input.from.address} is not an enabled alias of this Cast agent`);
    }

    const identities = await this.#standardCall(
      session.apiUrl,
      adminAccountId,
      accountId,
      'Identity/get',
      {},
      [MAIL_CAPABILITY, SUBMISSION_CAPABILITY],
    );
    const identity = (Array.isArray(identities.list) ? identities.list : [])
      .filter(isRecord)
      .find((entry) => typeof entry.email === 'string' && entry.email.toLowerCase() === from);
    if (!identity) throw new Error(`Stalwart has no enabled sending identity for ${from}`);
    const identityId = requiredId(identity.id, 'sending identity id');

    const draftsMailboxId = await this.#draftsMailboxId(
      session.apiUrl,
      adminAccountId,
      accountId,
    );
    const rawMessage = buildRfc5322Message(input, domain);
    const blobId = await this.#uploadMessage(session, accountId, rawMessage.bytes);
    const imported = await this.#standardCall(
      session.apiUrl,
      adminAccountId,
      accountId,
      'Email/import',
      {
        emails: {
          outbound: {
            blobId,
            mailboxIds: { [draftsMailboxId]: true },
            keywords: { '$draft': true },
            receivedAt: new Date().toISOString(),
          },
        },
      },
      [MAIL_CAPABILITY],
    );
    assertNoSetFailures(imported, 'Stalwart email import');
    const emailId = createdObjectId(imported, 'outbound', 'imported email id');
    const recipients = [...new Set([...input.to, ...input.cc, ...input.bcc].map((email) => (
      email.toLowerCase()
    )))];
    const submitted = await this.#standardCall(
      session.apiUrl,
      adminAccountId,
      accountId,
      'EmailSubmission/set',
      {
        create: {
          outbound: {
            emailId,
            identityId,
            envelope: {
              mailFrom: { email: from },
              rcptTo: recipients.map((email) => ({ email })),
            },
          },
        },
      },
      [MAIL_CAPABILITY, SUBMISSION_CAPABILITY],
    );
    assertNoSetFailures(submitted, 'Stalwart email submission');
    return {
      accountId,
      emailId,
      submissionId: createdObjectId(submitted, 'outbound', 'email submission id'),
      messageId: rawMessage.messageId,
    };
  }

  async createCastCalendarEvent(
    input: CastCalendarEventCreateInput,
  ): Promise<{ externalId: string }> {
    const context = await this.#castAccountContext(input.workspaceId, input.agentId);
    const uid = `cast-${createHash('sha256')
      .update(`${input.workspaceId}:${input.agentId}:${input.idempotencyKey}`, 'utf8')
      .digest('hex')}`;
    const existing = await this.#standardCall(
      context.session.apiUrl,
      context.adminAccountId,
      context.accountId,
      'CalendarEvent/query',
      { filter: { uid }, limit: 2 },
      [CALENDAR_CAPABILITY],
    );
    const existingId = onlyId(existing.ids, `calendar event UID ${uid}`);
    if (existingId) return { externalId: existingId };

    const calendarId = await this.#defaultCalendarId(context);
    const response = await this.#standardCall(
      context.session.apiUrl,
      context.adminAccountId,
      context.accountId,
      'CalendarEvent/set',
      {
        create: {
          event: {
            ...calendarEventObject(input.event),
            '@type': 'Event',
            uid,
            calendarIds: { [calendarId]: true },
          },
        },
      },
      [CALENDAR_CAPABILITY],
    );
    assertNoSetFailures(response, 'Calendar event creation');
    return { externalId: createdObjectId(response, 'event', 'created calendar event id') };
  }

  async updateCastCalendarEvent(
    externalId: string,
    input: CastCalendarEventUpdateInput,
  ): Promise<{ externalId: string }> {
    const context = await this.#castAccountContext(input.workspaceId, input.agentId);
    const response = await this.#standardCall(
      context.session.apiUrl,
      context.adminAccountId,
      context.accountId,
      'CalendarEvent/set',
      { update: { [externalId]: calendarEventObject(input.event) } },
      [CALENDAR_CAPABILITY],
    );
    assertNoSetFailures(response, 'Calendar event update');
    return { externalId };
  }

  async deleteCastCalendarEvent(
    externalId: string,
    input: CastCalendarEventDeleteInput,
  ): Promise<void> {
    const context = await this.#castAccountContext(input.workspaceId, input.agentId);
    const response = await this.#standardCall(
      context.session.apiUrl,
      context.adminAccountId,
      context.accountId,
      'CalendarEvent/set',
      { destroy: [externalId] },
      [CALENDAR_CAPABILITY],
    );
    const failures = asRecord(response.notDestroyed);
    const failure = asRecord(failures[externalId]);
    if (Object.keys(failures).length > 0 && failure.type !== 'notFound') {
      throw new Error(`Calendar event deletion failed: ${JSON.stringify(failures)}`);
    }
  }

  async forwardInboundMailEvent(
    input: InboundMailTelemetryEvent,
  ): Promise<InboundMailForwardResult> {
    this.#pruneInboundReplayCache();
    if (this.#inboundReplayCache.has(input.sourceId)) return 'duplicate';
    const inFlight = this.#inboundInFlight.get(input.sourceId);
    if (inFlight) return inFlight;

    const operation = this.#forwardInboundMailEventOnce(input)
      .catch((error: unknown) => {
        if (error instanceof PermanentInboundMailError) return 'ignored' as const;
        throw error;
      })
      .then((result) => {
        this.#inboundReplayCache.set(input.sourceId, Date.now());
        this.#pruneInboundReplayCache();
        return result;
      })
      .finally(() => {
        this.#inboundInFlight.delete(input.sourceId);
      });
    this.#inboundInFlight.set(input.sourceId, operation);
    return operation;
  }

  async #forwardInboundMailEventOnce(
    input: InboundMailTelemetryEvent,
  ): Promise<Exclude<InboundMailForwardResult, 'duplicate'>> {
    const targetUrl = this.#config.castAgentMailWebhookUrl;
    const targetSecret = this.#config.castMailboxWebhookSecret;
    if (!targetUrl || !targetSecret) {
      throw new Error('Cast inbound mail webhook is not configured');
    }

    const session = await this.#session();
    const adminAccountId = primaryAccountId(session);
    const account = await this.#registryObject(
      session.apiUrl,
      adminAccountId,
      'Account',
      input.accountId,
    );
    const domainId = requiredId(account.domainId, 'inbound mailbox domain id');
    const domain = await this.#registryObject(
      session.apiUrl,
      adminAccountId,
      'Domain',
      domainId,
    );
    const localPart = requiredString(account.name, 'inbound mailbox local part');
    const domainName = requiredString(domain.name, 'inbound mailbox domain name');
    if (
      !isCastAgentLocalPart(localPart) ||
      !isCastWorkspaceDomain(domainName, this.#config.mailDomain)
    ) {
      return 'ignored';
    }
    const accountTenantId = optionalId(account.memberTenantId);
    const domainTenantId = optionalId(domain.memberTenantId);
    if (!accountTenantId || !domainTenantId || accountTenantId !== domainTenantId) {
      return 'ignored';
    }
    const email = await this.#standardCall(
      session.apiUrl,
      adminAccountId,
      input.accountId,
      'Email/get',
      { ids: [input.emailId], properties: ['blobId', 'messageId'] },
      [MAIL_CAPABILITY],
    );
    const emailObject = Array.isArray(email.list) ? email.list.find(isRecord) : undefined;
    if (!emailObject) throw new Error(`Inbound email ${input.emailId} was not found`);
    const blobId = requiredString(emailObject.blobId, 'inbound email blob id');
    const raw = await this.#downloadRawMessage(session, input.accountId, blobId);
    const recipient = `${localPart.toLowerCase()}@${domainName.toLowerCase()}`;
    const response = await this.#fetch(targetUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'message/rfc822',
        'agent-mail-webhook-auth': targetSecret,
        'agent-mail-recipient': recipient,
        'agent-mail-source-id': input.sourceId,
        ...(isSafeHeaderValue(input.messageId)
          ? { 'agent-mail-message-id': input.messageId }
          : {}),
      },
      body: raw,
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) {
      throw new Error(`Cast inbound mail webhook failed with HTTP ${response.status}`);
    }
    return 'forwarded';
  }

  async #downloadRawMessage(
    session: JmapSession,
    accountId: string,
    blobId: string,
  ): Promise<Uint8Array> {
    if (!session.downloadUrl) throw new Error('Stalwart JMAP session has no download URL');
    const downloadUrl = session.downloadUrl
      .replace('{accountId}', encodeURIComponent(accountId))
      .replace('{blobId}', encodeURIComponent(blobId))
      .replace('{name}', 'message.eml')
      .replace('{type}', encodeURIComponent('message/rfc822'));
    const response = await this.#fetch(resolveApiUrl(downloadUrl, this.#config.stalwartBaseUrl), {
      headers: { Authorization: this.#authorization() },
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) throw new Error(`Inbound message download failed with HTTP ${response.status}`);
    return readResponseBody(response, MAX_INBOUND_MESSAGE_BYTES);
  }

  #pruneInboundReplayCache(): void {
    const expiredBefore = Date.now() - INBOUND_REPLAY_TTL_MS;
    for (const [sourceId, forwardedAt] of this.#inboundReplayCache) {
      if (
        forwardedAt >= expiredBefore &&
        this.#inboundReplayCache.size <= MAX_INBOUND_REPLAY_ENTRIES
      ) break;
      this.#inboundReplayCache.delete(sourceId);
    }
  }

  async #castAccountContext(
    workspaceId: string,
    agentId: string,
  ): Promise<{ session: JmapSession; adminAccountId: string; accountId: string }> {
    const session = await this.#session();
    const adminAccountId = primaryAccountId(session);
    const tenantId = await this.#findTenant(
      session.apiUrl,
      adminAccountId,
      castTenantName(workspaceId),
    );
    if (!tenantId) throw new Error('Cast workspace mailbox tenant is not provisioned');
    const domain = workspaceDomain(workspaceId, this.#config.mailDomain);
    const domainId = await this.#findDomain(session.apiUrl, adminAccountId, domain);
    if (!domainId) throw new Error('Cast workspace mail domain is not provisioned');
    await this.#assertObjectTenant(
      session.apiUrl,
      adminAccountId,
      'Domain',
      domainId,
      tenantId,
    );
    const [localPart] = splitAddress(permanentMailboxAddress(
      agentId,
      workspaceId,
      this.#config.mailDomain,
    ));
    const accountId = await this.#findAccount(
      session.apiUrl,
      adminAccountId,
      localPart,
      domainId,
    );
    if (!accountId) throw new Error('Cast agent mailbox is not provisioned');
    await this.#assertObjectTenant(
      session.apiUrl,
      adminAccountId,
      'Account',
      accountId,
      tenantId,
    );
    return { session, adminAccountId, accountId };
  }

  async #defaultCalendarId(context: {
    session: JmapSession;
    adminAccountId: string;
    accountId: string;
  }): Promise<string> {
    const response = await this.#standardCall(
      context.session.apiUrl,
      context.adminAccountId,
      context.accountId,
      'Calendar/get',
      {},
      [CALENDAR_CAPABILITY],
    );
    const calendars = Array.isArray(response.list) ? response.list.filter(isRecord) : [];
    const calendar = calendars.find((entry) => entry.isDefault === true) ?? calendars[0];
    if (!calendar) throw new Error('Stalwart did not initialize a calendar for the mailbox');
    return requiredId(calendar.id, 'default calendar id');
  }

  async #draftsMailboxId(
    apiUrl: string,
    adminAccountId: string,
    mailboxAccountId: string,
  ): Promise<string> {
    const query = await this.#standardCall(
      apiUrl,
      adminAccountId,
      mailboxAccountId,
      'Mailbox/query',
      { filter: { role: 'drafts' }, limit: 2 },
      [MAIL_CAPABILITY],
    );
    const existingId = onlyId(query.ids, 'drafts mailbox');
    if (existingId) return existingId;
    const created = await this.#standardCall(
      apiUrl,
      adminAccountId,
      mailboxAccountId,
      'Mailbox/set',
      {
        create: {
          drafts: { name: 'Drafts', role: 'drafts', isSubscribed: true },
        },
      },
      [MAIL_CAPABILITY],
    );
    assertNoSetFailures(created, 'Stalwart drafts mailbox creation');
    return createdObjectId(created, 'drafts', 'created drafts mailbox id');
  }

  async #uploadMessage(
    session: JmapSession,
    accountId: string,
    bytes: Uint8Array,
  ): Promise<string> {
    if (!session.uploadUrl) throw new Error('Stalwart JMAP session has no upload URL');
    const uploadUrl = session.uploadUrl.replace('{accountId}', encodeURIComponent(accountId));
    const response = await this.#fetch(resolveApiUrl(uploadUrl, this.#config.stalwartBaseUrl), {
      method: 'POST',
      headers: {
        Authorization: this.#authorization(),
        'Content-Type': 'message/rfc5322',
      },
      body: bytes,
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) throw new Error(`Stalwart message upload failed with HTTP ${response.status}`);
    const body = await response.json();
    if (!isRecord(body)) throw new Error('Stalwart message upload returned an invalid response');
    return requiredString(body.blobId, 'uploaded message blob id');
  }

  async #removeLegacyCastMailbox(input: {
    apiUrl: string;
    adminAccountId: string;
    tenantId: string;
    workspaceId: string;
    agentId: string;
    legacyBaseDomain: string;
  }): Promise<LegacyMailboxCleanupResult> {
    const domain = workspaceDomain(input.workspaceId, input.legacyBaseDomain);
    const address = permanentMailboxAddress(
      input.agentId,
      input.workspaceId,
      input.legacyBaseDomain,
    );
    const domainId = await this.#findDomain(input.apiUrl, input.adminAccountId, domain);
    if (!domainId) {
      return {
        baseDomain: input.legacyBaseDomain,
        domain,
        address,
        accountRemoved: false,
        domainRemoved: false,
      };
    }
    await this.#assertObjectTenant(
      input.apiUrl,
      input.adminAccountId,
      'Domain',
      domainId,
      input.tenantId,
    );

    const [localPart] = splitAddress(address);
    const accountId = await this.#findAccount(
      input.apiUrl,
      input.adminAccountId,
      localPart,
      domainId,
    );
    let accountRemoved = false;
    if (accountId) {
      await this.#assertObjectTenant(
        input.apiUrl,
        input.adminAccountId,
        'Account',
        accountId,
        input.tenantId,
      );
      const accountResponse = await this.#call(
        input.apiUrl,
        input.adminAccountId,
        'x:Account/set',
        { destroy: [accountId] },
      );
      assertNoSetFailures(accountResponse, 'Legacy mailbox account removal');
      accountRemoved = true;
    }

    const remainingAccounts = await this.#accountsInDomain(
      input.apiUrl,
      input.adminAccountId,
      domainId,
    );
    let domainRemoved = false;
    if (remainingAccounts.length === 0) {
      const domainResponse = await this.#call(
        input.apiUrl,
        input.adminAccountId,
        'x:Domain/set',
        { destroy: [domainId] },
      );
      assertNoSetFailures(domainResponse, 'Empty legacy workspace domain removal');
      domainRemoved = true;
    }

    return {
      baseDomain: input.legacyBaseDomain,
      domain,
      address,
      accountRemoved,
      domainRemoved,
    };
  }

  async #castDkimRecord(session: JmapSession): Promise<CastDkimRecord | undefined> {
    const adminAccountId = primaryAccountId(session);
    const domainId = await this.#findDomain(
      session.apiUrl,
      adminAccountId,
      this.#config.mailDomain,
    );
    if (!domainId) return undefined;
    const signature = await this.#castDkimSignature(
      session.apiUrl,
      adminAccountId,
      domainId,
    );
    if (!signature) return undefined;

    const senderAuthResponse = await this.#call(
      session.apiUrl,
      adminAccountId,
      'x:SenderAuth/get',
      { ids: ['singleton'] },
    );
    const senderAuth = Array.isArray(senderAuthResponse.list)
      ? senderAuthResponse.list.find(isRecord)
      : undefined;
    const signDomain = asRecord(senderAuth?.dkimSignDomain);
    if (
      senderAuth?.dkimStrict !== true ||
      signDomain.else !== `'${this.#config.mailDomain}'`
    ) return undefined;

    const publicKey = requiredString(signature.publicKey, 'DKIM public key');
    const dnsName = `${this.#config.castDkimSelector}._domainkey.${this.#config.mailDomain}`;
    const txtValue = `v=DKIM1; k=rsa; h=sha256; p=${publicKey}`;
    let dnsPublished = false;
    try {
      const records = await withTimeout(this.#resolveTxt(dnsName), 3_000);
      dnsPublished = records.some((parts) => parts.join('') === txtValue);
    } catch {
      dnsPublished = false;
    }
    return {
      domain: this.#config.mailDomain,
      selector: this.#config.castDkimSelector,
      dnsName,
      txtValue,
      algorithm: 'rsa-sha256',
      dnsPublished,
    };
  }

  async #castDkimSignature(
    apiUrl: string,
    adminAccountId: string,
    domainId: string,
  ): Promise<Record<string, unknown> | undefined> {
    return (await this.#activeParentRsaSignatures(apiUrl, adminAccountId, domainId))
      .find((signature) => signature.selector === this.#config.castDkimSelector);
  }

  async #activeParentRsaSignatures(
    apiUrl: string,
    adminAccountId: string,
    domainId: string,
  ): Promise<Record<string, unknown>[]> {
    const query = await this.#call(apiUrl, adminAccountId, 'x:DkimSignature/query', {
      filter: { domainId },
      limit: 100,
    });
    const ids = stringIds(query.ids);
    if (ids.length === 0) return [];
    const get = await this.#call(apiUrl, adminAccountId, 'x:DkimSignature/get', {
      ids,
      properties: ['@type', 'selector', 'domainId', 'stage', 'publicKey'],
    });
    return (Array.isArray(get.list) ? get.list : [])
      .filter(isRecord)
      .filter((signature) => (
        signature['@type'] === 'Dkim1RsaSha256' &&
        String(signature.stage).toLowerCase() === 'active' &&
        optionalId(signature.domainId) === domainId &&
        typeof signature.publicKey === 'string' &&
        signature.publicKey.length > 0
      ));
  }

  async #ensureCastTenant(
    apiUrl: string,
    accountId: string,
    workspaceId: string,
  ): Promise<{ id: string; created: boolean }> {
    const name = castTenantName(workspaceId);
    const existingId = await this.#findTenant(apiUrl, accountId, name);
    if (existingId) return { id: existingId, created: false };

    const response = await this.#call(apiUrl, accountId, 'x:Tenant/set', {
      create: {
        workspace: {
          name,
          roles: { '@type': 'Default' },
          permissions: { '@type': 'Inherit' },
          quotas: {},
        },
      },
    });
    const failure = setFailures(response);
    if (Object.keys(failure).length > 0) {
      const racedId = await this.#findTenant(apiUrl, accountId, name);
      if (racedId) return { id: racedId, created: false };
      throw new Error(`Stalwart tenant creation failed: ${JSON.stringify(failure)}`);
    }
    return {
      id: createdObjectId(response, 'workspace', 'created tenant id'),
      created: true,
    };
  }

  async #ensureCastDomain(
    apiUrl: string,
    accountId: string,
    domain: string,
    tenantId: string,
    workspaceId: string,
  ): Promise<{ id: string; created: boolean }> {
    const existingId = await this.#findDomain(apiUrl, accountId, domain);
    if (existingId) {
      await this.#assertObjectTenant(apiUrl, accountId, 'Domain', existingId, tenantId);
      return { id: existingId, created: false };
    }

    const response = await this.#call(apiUrl, accountId, 'x:Domain/set', {
      create: {
        workspace: {
          name: domain,
          isEnabled: true,
          description: `Cast workspace ${workspaceId}`,
          memberTenantId: tenantId,
          certificateManagement: { '@type': 'Manual' },
          dkimManagement: { '@type': 'Manual' },
          dnsManagement: { '@type': 'Manual' },
        },
      },
    });
    const failure = setFailures(response);
    if (Object.keys(failure).length > 0) {
      const racedId = await this.#findDomain(apiUrl, accountId, domain);
      if (racedId) {
        await this.#assertObjectTenant(apiUrl, accountId, 'Domain', racedId, tenantId);
        return { id: racedId, created: false };
      }
      throw new Error(`Stalwart domain creation failed: ${JSON.stringify(failure)}`);
    }
    return {
      id: createdObjectId(response, 'workspace', 'created workspace domain id'),
      created: true,
    };
  }

  async #ensureCastAccount(
    apiUrl: string,
    accountId: string,
    localPart: string,
    domainId: string,
    tenantId: string,
    displayName: string,
    aliases: string[],
  ): Promise<{ id: string; created: boolean }> {
    const aliasObjects = emailAliasObjects(aliases, domainId);
    const existingId = await this.#findAccount(apiUrl, accountId, localPart, domainId);
    if (existingId) {
      const existing = await this.#registryObject(
        apiUrl,
        accountId,
        'Account',
        existingId,
      );
      assertMemberTenant(existing, tenantId, 'account');
      const response = await this.#call(apiUrl, accountId, 'x:Account/set', {
        update: {
          [existingId]: {
            aliases: aliasObjects,
            description: displayName,
            quotas: {},
          },
        },
      });
      assertNoSetFailures(response, 'Stalwart account update');
      return { id: existingId, created: false };
    }

    const response = await this.#call(apiUrl, accountId, 'x:Account/set', {
      create: {
        mailbox: {
          '@type': 'User',
          name: localPart,
          domainId,
          memberTenantId: tenantId,
          credentials: {},
          encryptionAtRest: { '@type': 'Disabled' },
          permissions: { '@type': 'Inherit' },
          roles: { '@type': 'User' },
          aliases: aliasObjects,
          quotas: {},
          locale: 'en_US',
          description: displayName,
        },
      },
    });
    const failure = setFailures(response);
    if (Object.keys(failure).length > 0) {
      const racedId = await this.#findAccount(apiUrl, accountId, localPart, domainId);
      if (racedId) return this.#ensureCastAccount(
        apiUrl,
        accountId,
        localPart,
        domainId,
        tenantId,
        displayName,
        aliases,
      );
      throw new Error(`Stalwart account creation failed: ${JSON.stringify(failure)}`);
    }
    return {
      id: createdObjectId(response, 'mailbox', 'created account id'),
      created: true,
    };
  }

  async #findTenant(apiUrl: string, accountId: string, name: string): Promise<string | undefined> {
    const response = await this.#call(apiUrl, accountId, 'x:Tenant/query', {
      filter: { name },
      limit: 2,
    });
    return onlyId(response.ids, `tenant ${name}`);
  }

  async #registryObject(
    apiUrl: string,
    accountId: string,
    objectType: 'Account' | 'Domain',
    id: string,
  ): Promise<Record<string, unknown>> {
    const response = await this.#call(apiUrl, accountId, `x:${objectType}/get`, { ids: [id] });
    const object = Array.isArray(response.list) ? response.list.find(isRecord) : undefined;
    if (!object) throw new Error(`Stalwart ${objectType.toLowerCase()} ${id} was not found`);
    return object;
  }

  async #assertObjectTenant(
    apiUrl: string,
    accountId: string,
    objectType: 'Account' | 'Domain',
    id: string,
    tenantId: string,
  ): Promise<void> {
    assertMemberTenant(
      await this.#registryObject(apiUrl, accountId, objectType, id),
      tenantId,
      objectType.toLowerCase(),
    );
  }

  async #findDomain(apiUrl: string, accountId: string, name: string): Promise<string | undefined> {
    const response = await this.#call(apiUrl, accountId, 'x:Domain/query', {
      filter: { name },
      limit: 2,
    });
    return firstId(response.ids);
  }

  async #findAccount(
    apiUrl: string,
    accountId: string,
    name: string,
    domainId: string,
  ): Promise<string | undefined> {
    const response = await this.#call(apiUrl, accountId, 'x:Account/query', {
      filter: {
        operator: 'AND',
        conditions: [{ name }, { domainId }],
      },
      limit: 2,
    });
    return firstId(response.ids);
  }

  async #accountsInDomain(
    apiUrl: string,
    accountId: string,
    domainId: string,
  ): Promise<string[]> {
    const response = await this.#call(apiUrl, accountId, 'x:Account/query', {
      filter: { domainId },
      limit: 2,
    });
    return stringIds(response.ids);
  }

  async #invalidateCaches(apiUrl: string, accountId: string): Promise<void> {
    await this.#call(apiUrl, accountId, 'x:Action/set', {
      create: { cache: { '@type': 'InvalidateCaches' } },
    });
  }

  async #reloadSettings(apiUrl: string, accountId: string): Promise<void> {
    await this.#call(apiUrl, accountId, 'x:Action/set', {
      create: { settings: { '@type': 'ReloadSettings' } },
    });
  }

  async #session(): Promise<JmapSession> {
    const response = await this.#fetch(`${this.#config.stalwartBaseUrl}/.well-known/jmap`, {
      headers: { Authorization: this.#authorization() },
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) {
      throw new Error(`Stalwart session discovery failed with HTTP ${response.status}`);
    }
    const body = await response.json();
    if (!isRecord(body) || typeof body.apiUrl !== 'string' || !isRecord(body.accounts)) {
      throw new Error('Stalwart returned an invalid JMAP session');
    }
    return body as JmapSession;
  }

  async #hasBearerAccess(token: string): Promise<boolean> {
    try {
      const response = await this.#fetch(
        `${this.#config.stalwartBaseUrl}/.well-known/jmap`,
        {
          headers: { Authorization: `Bearer ${token}` },
          signal: AbortSignal.timeout(10_000),
        },
      );
      return response.ok;
    } catch {
      return false;
    }
  }

  async #call(
    apiUrl: string,
    accountId: string,
    method: string,
    arguments_: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.#callWithCapabilities(
      apiUrl,
      accountId,
      method,
      arguments_,
      [STALWART_CAPABILITY],
    );
  }

  async #standardCall(
    apiUrl: string,
    adminAccountId: string,
    targetAccountId: string,
    method: string,
    arguments_: Record<string, unknown>,
    capabilities: string[],
  ): Promise<Record<string, unknown>> {
    return this.#callWithCapabilities(
      apiUrl,
      targetAccountId,
      method,
      arguments_,
      capabilities,
      adminAccountId,
    );
  }

  async #callWithCapabilities(
    apiUrl: string,
    accountId: string,
    method: string,
    arguments_: Record<string, unknown>,
    capabilities: string[],
    _authenticatedAccountId?: string,
  ): Promise<Record<string, unknown>> {
    const methodCall: JmapMethodCall = [method, { ...arguments_, accountId }, 'openagent'];
    const response = await this.#fetch(resolveApiUrl(apiUrl, this.#config.stalwartBaseUrl), {
      method: 'POST',
      headers: {
        Authorization: this.#authorization(),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        using: [CORE_CAPABILITY, ...capabilities],
        methodCalls: [methodCall],
      }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) {
      throw new Error(`${method} failed with HTTP ${response.status}`);
    }
    const body = await response.json();
    if (!isRecord(body) || !Array.isArray(body.methodResponses)) {
      throw new Error(`${method} returned an invalid JMAP response`);
    }
    const methodResponse = body.methodResponses[0] as JmapMethodResponse | undefined;
    if (!methodResponse || !isRecord(methodResponse[1])) {
      throw new Error(`${method} returned no method response`);
    }
    if (methodResponse[0] === 'error') {
      throw new Error(`${method} failed: ${JSON.stringify(methodResponse[1])}`);
    }
    return methodResponse[1];
  }

  #authorization(): string {
    return `Basic ${Buffer.from(
      `${this.#config.stalwartAdminUsername}:${this.#config.stalwartAdminPassword}`,
      'utf8',
    ).toString('base64')}`;
  }
}

function resolveApiUrl(apiUrl: string, baseUrl: string): string {
  const parsedBaseUrl = new URL(baseUrl);
  const parsedApiUrl = new URL(apiUrl, parsedBaseUrl);
  parsedApiUrl.protocol = parsedBaseUrl.protocol;
  parsedApiUrl.host = parsedBaseUrl.host;
  return parsedApiUrl.toString();
}

function primaryAccountId(session: JmapSession): string {
  const primary = session.primaryAccounts;
  if (primary) {
    const mail = primary['urn:ietf:params:jmap:mail'];
    if (mail) return mail;
    const first = Object.values(primary)[0];
    if (first) return first;
  }
  const first = Object.keys(session.accounts)[0];
  if (!first) throw new Error('Stalwart session contains no administrator account');
  return first;
}

function splitAddress(address: string): [string, string] {
  const parts = address.toLowerCase().split('@');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error('Invalid mailbox address');
  }
  return [parts[0], parts[1]];
}

function firstId(value: unknown): string | undefined {
  return Array.isArray(value) && typeof value[0] === 'string' ? value[0] : undefined;
}

function onlyId(value: unknown, description: string): string | undefined {
  const ids = stringIds(value);
  if (ids.length > 1) throw new Error(`Stalwart returned multiple records for ${description}`);
  return ids[0];
}

function stringIds(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string') : [];
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`Missing ${name}`);
  return value;
}

function asRecord(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

function setFailures(response: Record<string, unknown>): Record<string, unknown> {
  return {
    ...asRecord(response.notCreated),
    ...asRecord(response.notUpdated),
    ...asRecord(response.notDestroyed),
  };
}

function assertNoSetFailures(response: Record<string, unknown>, operation: string): void {
  const failures = setFailures(response);
  if (Object.keys(failures).length > 0) {
    throw new Error(`${operation} failed: ${JSON.stringify(failures)}`);
  }
}

function createdObjectId(
  response: Record<string, unknown>,
  clientId: string,
  description: string,
): string {
  return requiredId(asRecord(asRecord(response.created)[clientId]).id, description);
}

function requiredId(value: unknown, description: string): string {
  if (typeof value === 'string' && value.length > 0) return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  throw new Error(`Missing ${description}`);
}

function optionalId(value: unknown): string | undefined {
  if (typeof value === 'string' && value.length > 0) return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  return undefined;
}

function isCastAgentLocalPart(value: string): boolean {
  return /^agt-[a-z0-9]+$/u.test(value.toLowerCase());
}

function isCastWorkspaceDomain(value: string, mailDomain: string): boolean {
  const normalized = value.toLowerCase();
  const suffix = `.${mailDomain.toLowerCase()}`;
  if (!normalized.startsWith('wsp-') || !normalized.endsWith(suffix)) return false;
  return /^[a-z0-9]+$/u.test(normalized.slice(4, -suffix.length));
}

function isSafeHeaderValue(value: string | undefined): value is string {
  return Boolean(value && value.length <= 998 && !/[\r\n]/u.test(value));
}

function unavailableMailServiceCapabilities(): MailServiceCapabilities {
  return {
    mailboxProvisioning: false,
    inboundReceiving: false,
    outboundDelivery: false,
    calendarSync: false,
  };
}

async function readResponseBody(response: Response, maxBytes: number): Promise<Uint8Array> {
  const contentLength = response.headers.get('content-length');
  if (contentLength) {
    const declaredBytes = Number(contentLength);
    if (Number.isFinite(declaredBytes) && declaredBytes > maxBytes) {
      await response.body?.cancel();
      throw new PermanentInboundMailError(`Inbound message exceeds the ${maxBytes}-byte limit`);
    }
  }

  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        throw new PermanentInboundMailError(`Inbound message exceeds the ${maxBytes}-byte limit`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

class PermanentInboundMailError extends Error {}

async function withTimeout<T>(operation: Promise<T>, milliseconds: number): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<T>((_resolve, reject) => {
        timeout = setTimeout(() => reject(new Error('Operation timed out')), milliseconds);
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

function castTenantName(workspaceId: string): string {
  return `cast-workspace:${workspaceId.toLowerCase()}`;
}

function assertMemberTenant(
  object: Record<string, unknown>,
  expectedTenantId: string,
  description: string,
): void {
  const actualTenantId = requiredId(object.memberTenantId, `${description} memberTenantId`);
  if (actualTenantId !== expectedTenantId) {
    throw new Error(
      `Stalwart ${description} belongs to tenant ${actualTenantId}, expected ${expectedTenantId}`,
    );
  }
}

function normalizeWorkspaceAliases(
  values: readonly string[],
  permanentAddress: string,
  workspaceMailDomain: string,
): string[] {
  const aliases = new Set<string>();
  for (const value of values) {
    const normalized = value.toLowerCase();
    const [localPart, domain] = splitAddress(normalized);
    validateLocalPart(localPart);
    if (domain !== workspaceMailDomain) {
      throw new Error(`Alias ${value} must use workspace domain ${workspaceMailDomain}`);
    }
    if (normalized !== permanentAddress) aliases.add(normalized);
  }
  return [...aliases].sort();
}

function validateLocalPart(localPart: string): void {
  if (
    localPart.length > 64 ||
    !/^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?$/u.test(localPart)
  ) {
    throw new Error(`Invalid mailbox local part: ${localPart}`);
  }
}

function emailAliasObjects(
  aliases: readonly string[],
  domainId: string,
): Record<string, unknown> {
  return Object.fromEntries(aliases.map((address, index) => {
    const [name] = splitAddress(address);
    return [String(index), {
      enabled: true,
      name,
      domainId,
      description: 'Cast agent alias',
    }];
  }));
}

function disableAliases(value: unknown): Record<string, unknown> {
  const aliases = asRecord(value);
  return Object.fromEntries(Object.entries(aliases).map(([key, alias]) => {
    const aliasObject = asRecord(alias);
    return [key, { ...aliasObject, enabled: false }];
  }));
}

function accountAddresses(
  account: Record<string, unknown>,
  canonicalAddress: string,
  domain: string,
): Set<string> {
  const addresses = new Set([canonicalAddress]);
  for (const alias of Object.values(asRecord(account.aliases))) {
    const object = asRecord(alias);
    if (object.enabled !== true || typeof object.name !== 'string') continue;
    addresses.add(`${object.name.toLowerCase()}@${domain}`);
  }
  return addresses;
}

function buildRfc5322Message(
  input: CastMailboxSendInput,
  senderDomain: string,
): { bytes: Uint8Array; messageId: string } {
  const messageId = input.messageId || `<${randomUUID()}@${senderDomain}>`;
  const headers = [
    `From: ${formattedSender(input.from)}`,
    `To: ${input.to.map((address) => address.toLowerCase()).join(', ')}`,
    ...(input.cc.length > 0
      ? [`Cc: ${input.cc.map((address) => address.toLowerCase()).join(', ')}`]
      : []),
    `Subject: ${encodedHeader(input.subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: ${messageId}`,
    ...(input.inReplyTo ? [`In-Reply-To: ${input.inReplyTo}`] : []),
    ...(input.references.length > 0 ? [`References: ${input.references.join(' ')}`] : []),
    'MIME-Version: 1.0',
  ];
  const body = mimeBody(input);
  return {
    messageId,
    bytes: Buffer.from(`${headers.join('\r\n')}\r\n${body}\r\n`, 'utf8'),
  };
}

function mimeBody(input: CastMailboxSendInput): string {
  const content = messageContentPart(input);
  if (input.attachments.length === 0) return content;

  const boundary = `cast-mixed-${randomUUID()}`;
  const parts = [
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    content,
  ];
  for (const attachment of input.attachments) {
    parts.push(
      `--${boundary}`,
      `Content-Type: ${attachment.contentType}`,
      'Content-Transfer-Encoding: base64',
      `Content-Disposition: attachment; filename*=UTF-8''${encodeURIComponent(attachment.filename)}`,
      '',
      foldBase64(attachment.contentBase64),
    );
  }
  parts.push(`--${boundary}--`);
  return parts.join('\r\n');
}

function messageContentPart(input: CastMailboxSendInput): string {
  if (input.text !== undefined && input.html !== undefined) {
    const boundary = `cast-alt-${randomUUID()}`;
    return [
      `Content-Type: multipart/alternative; boundary="${boundary}"`,
      '',
      `--${boundary}`,
      textPart('text/plain', input.text),
      `--${boundary}`,
      textPart('text/html', input.html),
      `--${boundary}--`,
    ].join('\r\n');
  }
  return textPart(input.html !== undefined ? 'text/html' : 'text/plain', input.html ?? input.text ?? '');
}

function textPart(contentType: string, value: string): string {
  return [
    `Content-Type: ${contentType}; charset=UTF-8`,
    'Content-Transfer-Encoding: base64',
    '',
    foldBase64(Buffer.from(value, 'utf8').toString('base64')),
  ].join('\r\n');
}

function encodedHeader(value: string): string {
  if (/^[\x20-\x7e]*$/u.test(value)) return value;
  return `=?UTF-8?B?${Buffer.from(value, 'utf8').toString('base64')}?=`;
}

function formattedSender(sender: { address: string; name?: string | undefined }): string {
  if (!sender.name) return sender.address.toLowerCase();
  const name = /^[\x20-\x7e]*$/u.test(sender.name)
    ? `"${sender.name.replace(/["\\]/gu, '\\$&')}"`
    : encodedHeader(sender.name);
  return `${name} <${sender.address.toLowerCase()}>`;
}

function foldBase64(value: string): string {
  return value.match(/.{1,76}/gu)?.join('\r\n') ?? '';
}

function calendarEventObject(event: CastCalendarEvent): Record<string, unknown> {
  const startsAt = new Date(event.startsAt);
  const endsAt = new Date(event.endsAt);
  const durationSeconds = Math.floor((endsAt.getTime() - startsAt.getTime()) / 1_000);
  if (!Number.isFinite(durationSeconds) || durationSeconds <= 0) {
    throw new Error('Calendar event endsAt must be after startsAt');
  }
  return {
    title: event.title,
    start: startsAt.toISOString().replace(/\.\d{3}Z$/u, ''),
    timeZone: 'Etc/UTC',
    duration: `PT${durationSeconds}S`,
    updated: new Date().toISOString().replace(/\.\d{3}Z$/u, 'Z'),
    description: event.description ?? null,
    locations: event.location
      ? {
          'cast-location': {
            '@type': 'Location',
            name: event.location,
          },
        }
      : {},
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

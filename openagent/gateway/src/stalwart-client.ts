import type { GatewayConfig } from './config.js';

const CORE_CAPABILITY = 'urn:ietf:params:jmap:core';
const STALWART_CAPABILITY = 'urn:stalwart:jmap';

type JmapMethodCall = [name: string, arguments: Record<string, unknown>, callId: string];
type JmapMethodResponse = [name: string, response: Record<string, unknown>, callId: string];

type JmapSession = {
  apiUrl: string;
  accounts: Record<string, unknown>;
  primaryAccounts?: Record<string, string>;
};

export type ProvisionedMailbox = {
  accountId: string;
  address: string;
  created: boolean;
};

export class StalwartClient {
  readonly #config: GatewayConfig;
  readonly #fetch: typeof fetch;

  constructor(config: GatewayConfig, fetchImplementation: typeof fetch = fetch) {
    this.#config = config;
    this.#fetch = fetchImplementation;
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
      requestTlsCertificate: false,
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

  async #call(
    apiUrl: string,
    accountId: string,
    method: string,
    arguments_: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const methodCall: JmapMethodCall = [method, { ...arguments_, accountId }, 'openagent'];
    const response = await this.#fetch(resolveApiUrl(apiUrl, this.#config.stalwartBaseUrl), {
      method: 'POST',
      headers: {
        Authorization: this.#authorization(),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        using: [CORE_CAPABILITY, STALWART_CAPABILITY],
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';

import type { GatewayConfig } from './config.js';

const MAX_TOKEN_LIFETIME_SECONDS = 10 * 60;
const CLOCK_TOLERANCE_SECONDS = 15;

export type AgentMailIdentity = {
  agentId: string;
  agentName: string;
  agentEmail: string;
  controllerType: 'user' | 'organization';
  controllerId: string;
  runtime: string;
  runtimeInstance: string;
  scopes: readonly string[];
  tokenId: string;
};

type VerifyJwt = typeof jwtVerify;

export class OpenAgentTokenVerifier {
  readonly #config: GatewayConfig;
  readonly #verifyJwt: VerifyJwt;
  readonly #jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(config: GatewayConfig, verifyJwt: VerifyJwt = jwtVerify) {
    this.#config = config;
    this.#verifyJwt = verifyJwt;
    this.#jwks = createRemoteJWKSet(
      new URL(config.identityJwksUrl),
      { cooldownDuration: 10_000, timeoutDuration: 5_000 },
    );
  }

  async verify(token: string): Promise<AgentMailIdentity> {
    const { payload } = await this.#verifyJwt(token, this.#jwks, {
      issuer: this.#config.identityIssuer,
      audience: this.#config.mailAudience,
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      algorithms: ['RS256', 'PS256', 'ES256', 'ES384'],
      requiredClaims: ['sub', 'aud', 'exp', 'iat', 'jti'],
    });

    return validateAgentClaims(payload, this.#config);
  }
}

export function validateAgentClaims(payload: JWTPayload, config: GatewayConfig): AgentMailIdentity {
  const subject = requiredString(payload.sub, 'sub');
  const agentId = requiredString(payload.agent_id, 'agent_id');
  const clientId = requiredString(payload.client_id, 'client_id');
  if (payload.agent !== true || subject !== agentId || clientId !== agentId) {
    throw new Error('Token is not bound to exactly one OpenAgent identity');
  }

  if (typeof payload.iat !== 'number' || typeof payload.exp !== 'number') {
    throw new Error('Token must include numeric iat and exp claims');
  }
  if (payload.exp <= payload.iat || payload.exp - payload.iat > MAX_TOKEN_LIFETIME_SECONDS) {
    throw new Error('Token lifetime exceeds the OpenAgent service-token limit');
  }

  const amr = stringArray(payload.amr, 'amr');
  if (!amr.includes('agent_key')) {
    throw new Error('Token was not authenticated with an agent key');
  }

  const agentEmail = requiredString(payload.agent_email, 'agent_email').toLowerCase();
  if (!agentEmail.endsWith(`@${config.mailDomain}`) || agentEmail.split('@').length !== 2) {
    throw new Error(`Agent email must belong to ${config.mailDomain}`);
  }

  const controller = payload.agent_controller;
  if (!isRecord(controller)) {
    throw new Error('Missing agent_controller claim');
  }
  const rawControllerType = requiredString(controller.type, 'agent_controller.type');
  const controllerType = rawControllerType === 'org' ? 'organization' : rawControllerType;
  if (controllerType !== 'user' && controllerType !== 'organization') {
    throw new Error('Invalid agent controller type');
  }

  const scopes = new Set(scopeList(payload.scope));
  for (const requiredScope of config.requiredScopes) {
    if (!scopes.has(requiredScope)) {
      throw new Error(`Missing required scope: ${requiredScope}`);
    }
  }

  return {
    agentId,
    agentName: requiredString(payload.agent_name, 'agent_name'),
    agentEmail,
    controllerType,
    controllerId: requiredString(controller.id, 'agent_controller.id'),
    runtime: requiredString(payload.agent_runtime, 'agent_runtime'),
    runtimeInstance: requiredString(payload.agent_runtime_instance, 'agent_runtime_instance'),
    scopes: [...scopes],
    tokenId: requiredString(payload.jti, 'jti'),
  };
}

function scopeList(value: unknown): string[] {
  if (typeof value === 'string') {
    return value.split(' ').filter(Boolean);
  }
  return stringArray(value, 'scope');
}

function stringArray(value: unknown, claim: string): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new Error(`${claim} must be a string array`);
  }
  return value as string[];
}

function requiredString(value: unknown, claim: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Missing ${claim} claim`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

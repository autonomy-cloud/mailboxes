import { describe, expect, it } from 'vitest';

import {
  castMailboxEnsureSchema,
  castMailboxSendSchema,
  isValidCastServiceToken,
  permanentMailboxAddress,
  workspaceDomain,
} from './cast-mailbox-api.js';

describe('Cast mailbox service authentication', () => {
  it('accepts only the configured shared bearer token', () => {
    const configured = 'cast-service-token-that-is-long-enough';
    expect(isValidCastServiceToken(configured, configured)).toBe(true);
    expect(isValidCastServiceToken('wrong', configured)).toBe(false);
    expect(isValidCastServiceToken(undefined, configured)).toBe(false);
    expect(isValidCastServiceToken(configured, undefined)).toBe(false);
  });
});

describe('Cast mailbox address contract', () => {
  it('uses the same stable workspace and agent normalization as Cast', () => {
    expect(workspaceDomain('2B5E-1234', 'agents.openagent.md')).toBe(
      'wsp-2b5e1234.agents.openagent.md',
    );
    expect(permanentMailboxAddress('A0B1-C2D3', '2B5E-1234', 'agents.openagent.md')).toBe(
      'agt-a0b1c2d3@wsp-2b5e1234.agents.openagent.md',
    );
  });

  it('rejects malformed or unexpectedly expanded requests', () => {
    expect(() => castMailboxEnsureSchema.parse({
      workspaceId: 'workspace',
      agentId: 'agent',
      displayName: 'Sales',
      permanentAddress: 'agt-agent@wsp-workspace.agents.openagent.md',
      aliases: [],
      tenantId: 'caller-controlled',
    })).toThrow();
  });

  it('normalizes Cast sender objects and scalar recipients', () => {
    expect(castMailboxSendSchema.parse({
      workspaceId: 'workspace',
      agentId: 'agent',
      from: { address: 'sales@example.com', name: 'Sales' },
      to: 'buyer@example.com',
      subject: 'Hello',
      messageId: '<message@example.com>',
      text: 'Body',
    })).toMatchObject({
      from: { address: 'sales@example.com', name: 'Sales' },
      to: ['buyer@example.com'],
      cc: [],
      bcc: [],
    });
  });
});

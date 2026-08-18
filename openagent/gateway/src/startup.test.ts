import { describe, expect, it, vi } from 'vitest';

import { initializeStalwart } from './startup.js';

describe('initializeStalwart', () => {
  it('survives the bootstrap restart window and preserves the bootstrap result', async () => {
    const bootstrapIfNeeded = vi.fn()
      .mockResolvedValueOnce(true)
      .mockRejectedValueOnce(new Error('primaryKeyViolation'))
      .mockResolvedValueOnce(false);
    const ensureOpenAgentOidc = vi.fn()
      .mockRejectedValueOnce(new Error('bootstrap mode'))
      .mockResolvedValueOnce(undefined);
    const sleep = vi.fn().mockResolvedValue(undefined);

    await expect(initializeStalwart(
      { bootstrapIfNeeded, ensureOpenAgentOidc },
      { attempts: 4, delayMs: 1, sleep },
    )).resolves.toEqual({ bootstrapped: true, attempts: 3 });
    expect(sleep).toHaveBeenCalledTimes(2);
  });

  it('fails loudly after the bounded retry budget', async () => {
    const error = new Error('unavailable');
    const client = {
      bootstrapIfNeeded: vi.fn().mockRejectedValue(error),
      ensureOpenAgentOidc: vi.fn(),
    };

    await expect(initializeStalwart(client, {
      attempts: 2,
      delayMs: 1,
      sleep: vi.fn().mockResolvedValue(undefined),
    })).rejects.toBe(error);
    expect(client.bootstrapIfNeeded).toHaveBeenCalledTimes(2);
    expect(client.ensureOpenAgentOidc).not.toHaveBeenCalled();
  });
});

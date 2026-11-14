import { describe, expect, it } from 'vitest';

import { telemetryAccountId } from './telemetry.js';

describe('telemetryAccountId', () => {
  it('converts numeric telemetry account ids to Stalwart JMAP ids', () => {
    expect(telemetryAccountId(0)).toBe('a');
    expect(telemetryAccountId(1)).toBe('b');
    expect(telemetryAccountId(2)).toBe('c');
    expect(telemetryAccountId(3)).toBe('d');
    expect(telemetryAccountId(31)).toBe('3');
    expect(telemetryAccountId(32)).toBe('ba');
  });

  it('preserves an already encoded JMAP account id', () => {
    expect(telemetryAccountId('d333333')).toBe('d333333');
  });

  it.each([-1, 1.5, Number.MAX_SAFE_INTEGER, '4', '', null])(
    'rejects an ambiguous or invalid telemetry account id: %j',
    (value) => {
      expect(() => telemetryAccountId(value)).toThrow();
    },
  );
});

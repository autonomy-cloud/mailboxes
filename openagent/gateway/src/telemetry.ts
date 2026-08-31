const STALWART_ID_ALPHABET = 'abcdefghijklmnopqrstuvwxyz792013';

export function telemetryAccountId(value: unknown): string {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
      throw new Error('Telemetry event has an invalid accountId');
    }
    return encodeStalwartId(value);
  }
  if (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 256 &&
    /^[a-z792013]+$/u.test(value)
  ) {
    return value;
  }
  throw new Error('Telemetry event is missing accountId');
}

function encodeStalwartId(value: number): string {
  if (value === 0) return STALWART_ID_ALPHABET[0]!;
  let id = value;
  let encoded = '';
  while (id > 0) {
    encoded = STALWART_ID_ALPHABET[id % 32]! + encoded;
    id = Math.floor(id / 32);
  }
  return encoded;
}

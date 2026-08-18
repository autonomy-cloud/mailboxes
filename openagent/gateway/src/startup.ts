export type StalwartStartupClient = {
  bootstrapIfNeeded(): Promise<boolean>;
  ensureOpenAgentOidc(): Promise<void>;
};

export type StalwartStartupResult = {
  bootstrapped: boolean;
  attempts: number;
};

type StartupOptions = {
  attempts?: number;
  delayMs?: number;
  sleep?: (milliseconds: number) => Promise<void>;
  onRetry?: (error: unknown, attempt: number) => void;
};

export async function initializeStalwart(
  client: StalwartStartupClient,
  options: StartupOptions = {},
): Promise<StalwartStartupResult> {
  const attempts = options.attempts ?? 60;
  const delayMs = options.delayMs ?? 1_000;
  const sleep = options.sleep ?? ((milliseconds) =>
    new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  let bootstrapped = false;
  let lastError: unknown;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      bootstrapped = (await client.bootstrapIfNeeded()) || bootstrapped;
      await client.ensureOpenAgentOidc();
      return { bootstrapped, attempts: attempt };
    } catch (error) {
      lastError = error;
      if (attempt === attempts) break;
      options.onRetry?.(error, attempt);
      await sleep(delayMs);
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error('Stalwart initialization failed');
}

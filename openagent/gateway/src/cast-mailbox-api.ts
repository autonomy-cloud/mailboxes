import { createHash, timingSafeEqual } from 'node:crypto';

import { z } from 'zod';

const immutableId = z.string().trim().min(1).max(128);
const emailAddress = z.string().trim().min(3).max(254).refine(
  (value) => /^[^\s@]+@[^\s@]+$/u.test(value) && !/[\r\n]/u.test(value),
  'Invalid email address',
);

export const castMailboxEnsureSchema = z.object({
  workspaceId: immutableId,
  agentId: immutableId,
  displayName: z.string().trim().min(1).max(256),
  permanentAddress: emailAddress,
  aliases: z.array(emailAddress).max(64).default([]),
}).strict();

export const castMailboxRetireSchema = z.object({
  workspaceId: immutableId,
  agentId: immutableId,
  permanentAddress: emailAddress,
}).strict();

const recipientList = z.union([emailAddress, z.array(emailAddress).max(100)])
  .default([])
  .transform((value) => typeof value === 'string' ? [value] : value);
const sender = z.union([
  emailAddress.transform((address) => ({ address })),
  z.object({
    address: emailAddress,
    name: z.string().trim().min(1).max(256).refine(
      (value) => !/[\r\n]/u.test(value),
      'Display name must not contain line breaks',
    ).optional(),
  }).strict(),
]);
const attachmentSchema = z.object({
  filename: z.string().trim().min(1).max(255),
  contentType: z.string().trim().regex(/^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/iu),
  contentBase64: z.string().max(10 * 1024 * 1024).regex(/^[a-z0-9+/]*={0,2}$/iu),
}).strict();

export const castMailboxSendSchema = z.object({
  workspaceId: immutableId,
  agentId: immutableId,
  from: sender,
  to: recipientList,
  cc: recipientList,
  bcc: recipientList,
  subject: z.string().max(998),
  text: z.string().max(5 * 1024 * 1024).optional(),
  html: z.string().max(5 * 1024 * 1024).optional(),
  messageId: z.string().trim().min(3).max(998),
  inReplyTo: z.string().trim().max(998).optional(),
  references: z.array(z.string().trim().min(1).max(998)).max(100).default([]),
  attachments: z.array(attachmentSchema).max(32).default([]),
}).strict().superRefine((value, context) => {
  if (value.to.length + value.cc.length + value.bcc.length === 0) {
    context.addIssue({ code: 'custom', message: 'At least one recipient is required' });
  }
  if (value.text === undefined && value.html === undefined) {
    context.addIssue({ code: 'custom', message: 'text or html content is required' });
  }
  for (const [name, header] of [
    ['subject', value.subject],
    ['messageId', value.messageId],
    ['inReplyTo', value.inReplyTo],
    ...value.references.map((reference) => ['references', reference] as const),
  ] as const) {
    if (header?.match(/[\r\n]/u)) {
      context.addIssue({ code: 'custom', message: `${name} must not contain line breaks` });
    }
  }
});

export const castCalendarEventSchema = z.object({
  title: z.string().trim().min(1).max(512),
  startsAt: z.string().datetime({ offset: true }),
  endsAt: z.string().datetime({ offset: true }),
  description: z.string().max(100_000).optional(),
  location: z.string().trim().max(2_048).optional(),
}).strict().refine(
  (event) => Date.parse(event.endsAt) > Date.parse(event.startsAt),
  { message: 'endsAt must be after startsAt' },
);

export const castCalendarEventCreateSchema = z.object({
  workspaceId: immutableId,
  agentId: immutableId,
  idempotencyKey: z.string().trim().min(1).max(256),
  event: castCalendarEventSchema,
}).strict();

export const castCalendarEventUpdateSchema = z.object({
  workspaceId: immutableId,
  agentId: immutableId,
  event: castCalendarEventSchema,
}).strict();

export const castCalendarEventDeleteSchema = z.object({
  workspaceId: immutableId,
  agentId: immutableId,
}).strict();

export type CastMailboxEnsureInput = z.infer<typeof castMailboxEnsureSchema>;
export type CastMailboxRetireInput = z.infer<typeof castMailboxRetireSchema>;
export type CastMailboxSendInput = z.infer<typeof castMailboxSendSchema>;
export type CastCalendarEvent = z.infer<typeof castCalendarEventSchema>;
export type CastCalendarEventCreateInput = z.infer<typeof castCalendarEventCreateSchema>;
export type CastCalendarEventUpdateInput = z.infer<typeof castCalendarEventUpdateSchema>;
export type CastCalendarEventDeleteInput = z.infer<typeof castCalendarEventDeleteSchema>;

/**
 * Compare fixed-size digests so a wrong token never takes a length-dependent
 * early return through timingSafeEqual.
 */
export function isValidCastServiceToken(
  suppliedToken: string | undefined,
  configuredToken: string | undefined,
): boolean {
  if (!suppliedToken || !configuredToken) return false;
  const suppliedDigest = createHash('sha256').update(suppliedToken, 'utf8').digest();
  const configuredDigest = createHash('sha256').update(configuredToken, 'utf8').digest();
  return timingSafeEqual(suppliedDigest, configuredDigest);
}

export function normalizedImmutableId(value: string, label: string): string {
  const normalized = value.toLowerCase().replace(/[^a-z0-9]/gu, '');
  if (!normalized) throw new Error(`${label} has no DNS-safe characters`);
  return normalized;
}

export function workspaceDomain(workspaceId: string, mailDomain: string): string {
  const normalized = normalizedImmutableId(workspaceId, 'workspaceId');
  if (normalized.length > 59) {
    throw new Error('workspaceId is too long for a workspace mail domain');
  }
  return `wsp-${normalized}.${mailDomain.toLowerCase()}`;
}

export function permanentMailboxAddress(
  agentId: string,
  workspaceId: string,
  mailDomain: string,
): string {
  const normalizedAgentId = normalizedImmutableId(agentId, 'agentId');
  if (normalizedAgentId.length > 60) {
    throw new Error('agentId is too long for a mailbox local part');
  }
  return `agt-${normalizedAgentId}@${workspaceDomain(workspaceId, mailDomain)}`;
}

// a2a-caller — sender-side counterpart to a2a-acl.
//
// See README.md for usage. The core idea:
//
//   import express from 'express';
//   import { publicChatMiddleware, loadSigningKey, IpRateLimiter } from 'a2a-caller';
//
//   const signingKey = { key: loadSigningKey(process.env.PORTAL_SIGNING_SEED) };
//
//   app.post('/v1/chat/:slug', express.json(), publicChatMiddleware({
//     resolveReceiver: async (slug) => ({ did, url }),
//     callerDid: 'did:moltrust:my-portal-...',
//     signingKey,
//     callerSigKeyId: 'my-portal-v1',
//     requestsPerMinute: 30,
//     sink: (row) => db.audit.insert(row),
//     logger: pino(),
//   }));

export { signEnvelope, loadSigningKey, signablePayload, SIGNED_FIELDS } from './envelope.js';
export { IpRateLimiter } from './ip-rate-limit.js';
export { captureCallerId, parseClaimedDid, hashVisitor } from './caller-id.js';
export { buildAuditRow, emitAudit } from './audit.js';
export { publicChatMiddleware } from './middleware.js';

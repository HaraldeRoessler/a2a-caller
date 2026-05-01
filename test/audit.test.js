// Verifies emitAudit's resilience to misbehaving sinks/loggers.
// A bad logger should NEVER crash the request handler — the value
// of the audit trail isn't worth taking down the service over.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emitAudit, buildAuditRow } from '../src/audit.js';

const row = buildAuditRow({ receiverSlug: 's', callerDid: 'did:x:1' });

test('emitAudit: throwing logger.info does not propagate', () => {
  const logger = {
    info: () => { throw new Error('logger.info exploded'); },
  };
  // Must not throw out of emitAudit.
  emitAudit({ sink: null, logger, row });
});

test('emitAudit: logger access proxy that throws does not propagate', () => {
  const logger = new Proxy({}, {
    get() { throw new Error('proxy access throws'); },
  });
  emitAudit({ sink: null, logger, row });
});

test('emitAudit: throwing sink (sync) does not propagate', () => {
  const sink = () => { throw new Error('sink exploded'); };
  emitAudit({ sink, logger: null, row });
});

test('emitAudit: rejecting sink (async) does not propagate', async () => {
  const sink = async () => { throw new Error('async sink exploded'); };
  emitAudit({ sink, logger: null, row });
  // Give the unhandled-promise machinery a tick to run.
  await new Promise((r) => setTimeout(r, 20));
});

test('emitAudit: throwing logger.error during sink-failure handling does not propagate', async () => {
  const sink = async () => { throw new Error('boom'); };
  const logger = {
    error: () => { throw new Error('logger.error explodes too'); },
    info: () => { /* fine */ },
  };
  emitAudit({ sink, logger, row });
  await new Promise((r) => setTimeout(r, 20));
});

test('emitAudit: well-behaved sink + logger produces no errors', async () => {
  const calls = [];
  const sink = (r) => { calls.push(r); };
  const logger = {
    info: (r, msg) => { calls.push({ logged: true, msg }); },
    error: () => { calls.push({ error: true }); },
  };
  emitAudit({ sink, logger, row });
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(calls.length, 2);   // sink + logger.info
});

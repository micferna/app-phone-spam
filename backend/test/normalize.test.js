import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeNumber, isArcepDemarchage } from '../src/normalize.js';

test('accepte les formats FR courants et renvoie E.164', () => {
  assert.equal(normalizeNumber('06 12 34 56 78'), '+33612345678');
  assert.equal(normalizeNumber('0612345678'), '+33612345678');
  assert.equal(normalizeNumber('+33 6 12 34 56 78'), '+33612345678');
  assert.equal(normalizeNumber('0033612345678'), '+33612345678');
});

test('rejette tout ce qui n’est pas un numéro (anti-injection)', () => {
  for (const bad of [
    "'; DROP TABLE users;--",
    '<img src=x onerror=alert(1)>',
    '$(rm -rf /)',
    'not_a_number',
    '',
    '   ',
    '06123', // trop court
    null,
    undefined,
    42,
  ]) {
    assert.equal(normalizeNumber(bad), null, `devrait rejeter: ${String(bad)}`);
  }
});

test('détecte les préfixes ARCEP de démarchage', () => {
  assert.equal(isArcepDemarchage('+33948123456'), true);
  assert.equal(isArcepDemarchage('+33162000000'), true);
  assert.equal(isArcepDemarchage('+33612345678'), false);
});

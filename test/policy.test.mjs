import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateCondition } from '../src/policy.mjs';

const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Synthetic fixtures for local boundary tests, not observed platform tasks.
export const valid = () => ({
  registered_vk: '0x' + 'a'.repeat(64), proof_vk: '0x' + 'a'.repeat(64),
  minimum: '1000', public_balance: '1460',
  expiry_block: 8430000, current_block: 8420000,
  recipient: '0x' + '1'.repeat(40), condition_recipient: '0x' + '1'.repeat(40),
  amount: '500', max_transfer: '1000', proof_tx: '0x' + 'b'.repeat(64),
});

test('approves a condition only when all documented fields pass', () => {
  assert.deepEqual(evaluateCondition(valid(), new Set()), {
    decision: 'APPROVE', reason_code: 'VALID_CONDITION',
  });
});

test('rejects a proof verified by a different verification key', () => {
  const input = { ...valid(), proof_vk: '0x' + 'c'.repeat(64) };
  assert.deepEqual(evaluateCondition(input, new Set()), {
    decision: 'REJECT', reason_code: 'VK_SUBSTITUTION',
  });
});

test('rejects a proof transaction already present in the seen set', () => {
  const input = valid();
  const seen = new Set([input.proof_tx]);
  assert.deepEqual(evaluateCondition(input, seen), {
    decision: 'REJECT', reason_code: 'PROOF_REUSED',
  });
});

test('rejects at the expiry block as required by the circuit strict inequality', () => {
  for (const [expiry_block, current_block, decision, reason_code] of [
    [100, 100, 'REJECT', 'EXPIRED_CONDITION'],
    [100, 101, 'REJECT', 'EXPIRED_CONDITION'],
    [100, 99, 'APPROVE', 'VALID_CONDITION'],
    [4294967295, 4294967295, 'REJECT', 'EXPIRED_CONDITION'],
    [4294967295, 4294967294, 'APPROVE', 'VALID_CONDITION'],
    ['9', '10', 'REJECT', 'EXPIRED_CONDITION'],
    ['10', '9', 'APPROVE', 'VALID_CONDITION'],
    [0, 0, 'REJECT', 'EXPIRED_CONDITION'],
    [1, 0, 'APPROVE', 'VALID_CONDITION'],
  ]) {
    assert.deepEqual(evaluateCondition({ ...valid(), expiry_block, current_block }, new Set()), {
      decision, reason_code,
    }, `current block ${current_block}, expiry ${expiry_block}`);
  }
});

test('rejects a transfer to a recipient outside the condition', () => {
  const input = { ...valid(), recipient: '0x' + '2'.repeat(40) };
  assert.deepEqual(evaluateCondition(input, new Set()), {
    decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH',
  });
});

test('compares the transfer amount with its cap at the uint32 boundary', () => {
  const max_transfer = '4294967294';
  for (const [amount, decision, reason_code] of [
    ['4294967295', 'REJECT', 'AMOUNT_OVERFLOW'],
    [max_transfer, 'APPROVE', 'VALID_CONDITION'],
    ['4294967293', 'APPROVE', 'VALID_CONDITION'],
  ]) {
    assert.deepEqual(evaluateCondition({ ...valid(), amount, max_transfer }, new Set()), {
      decision, reason_code,
    }, `amount ${amount}`);
  }
});

test('compares verification-key hex case-insensitively', () => {
  const input = { ...valid(), proof_vk: '0x' + 'A'.repeat(64) };
  assert.deepEqual(evaluateCondition(input, new Set()), {
    decision: 'APPROVE', reason_code: 'VALID_CONDITION',
  });
});

test('compares recipient hex case-insensitively', () => {
  const input = {
    ...valid(), recipient: '0x' + 'aB'.repeat(20),
    condition_recipient: '0x' + 'Ab'.repeat(20),
  };
  assert.deepEqual(evaluateCondition(input, new Set()), {
    decision: 'APPROVE', reason_code: 'VALID_CONDITION',
  });
});

test('detects a mixed-case proof transaction in a lowercase seen set', () => {
  const input = { ...valid(), proof_tx: '0x' + 'B'.repeat(64) };
  assert.deepEqual(evaluateCondition(input, new Set([valid().proof_tx])), {
    decision: 'REJECT', reason_code: 'PROOF_REUSED',
  });
});

test('rejects a non-record input without throwing', () => {
  for (const input of [null, undefined, false, 1, 'condition', [], Object.assign([], valid())]) {
    assert.deepEqual(evaluateCondition(input, new Set()), {
      decision: 'REJECT', reason_code: 'INVALID_INPUT',
    });
  }
});

test('rejects every missing own condition field before evaluating traps', () => {
  for (const field of Object.keys(valid())) {
    const input = { ...valid(), proof_vk: '0x' + 'c'.repeat(64) };
    delete input[field];
    assert.deepEqual(evaluateCondition(input, new Set()), {
      decision: 'REJECT', reason_code: 'INVALID_INPUT',
    }, `missing ${field}`);
  }
  assert.deepEqual(evaluateCondition(Object.create(valid()), new Set()), {
    decision: 'REJECT', reason_code: 'INVALID_INPUT',
  });
});

test('fails closed when the caller has not provided a replay set', () => {
  for (const seen of [undefined, null, [], {}, { has: () => false }, false]) {
    assert.deepEqual(evaluateCondition(valid(), seen), {
      decision: 'REJECT', reason_code: 'INVALID_INPUT',
    });
  }
});

test('rejects malformed hashes or addresses before comparing identifiers', () => {
  for (const [field, width] of [
    ['registered_vk', 64], ['proof_vk', 64], ['proof_tx', 64],
    ['recipient', 40], ['condition_recipient', 40],
  ]) {
    const wellFormed = '0x' + 'a'.repeat(width);
    for (const value of [
      null, undefined, 0, true, {}, [], new String(wellFormed),
      '', 'symbolic-id', 'a'.repeat(width), ...(width === 40 ? ['0x' + 'a'.repeat(width - 1)] : ['0x']),
      '0x' + 'a'.repeat(width + 1), '0x' + 'g'.repeat(width),
      ` ${wellFormed}`, `${wellFormed} `, `${wellFormed}\n`,
    ]) {
      assert.deepEqual(evaluateCondition({ ...valid(), [field]: value }, new Set()), {
        decision: 'REJECT', reason_code: 'INVALID_INPUT',
      }, `invalid ${field}: ${String(value)}`);
    }
  }
  const uppercase = Object.fromEntries(Object.entries(valid()).map(([field, value]) =>
    [field, typeof value === 'string' && value.startsWith('0x') ? value.toUpperCase() : value]));
  assert.deepEqual(evaluateCondition(uppercase, new Set()), {
    decision: 'APPROVE', reason_code: 'VALID_CONDITION',
  });
});

test('rejects malformed numeric fields without coercion or precision loss', () => {
  for (const field of [
    'public_balance', 'minimum', 'expiry_block', 'current_block', 'amount', 'max_transfer',
  ]) {
    for (const value of [
      null, undefined, true, false, {}, [], [0], new Number(0), new String('0'), 0n,
      '', ' ', '\n', '-1', '-0', '+1', '1.0', '1e3', '0x10', '0b10', '0o10',
      '1_000', '1,000', '10garbage', ' 10', '10 ', '10\n', '１０',
      -1, 0.5, NaN, Infinity, -Infinity, 9007199254740992,
    ]) {
      const input = { ...valid(), proof_vk: '0x' + 'c'.repeat(64), [field]: value };
      assert.deepEqual(evaluateCondition(input, new Set()), {
        decision: 'REJECT', reason_code: 'INVALID_INPUT',
      }, `invalid ${field}: ${String(value)}`);
    }
  }
});

test('bounds decimal token length before parsing', () => {
  for (const field of [
    'public_balance', 'minimum', 'expiry_block', 'current_block', 'amount', 'max_transfer',
  ]) {
    assert.deepEqual(evaluateCondition({ ...valid(), [field]: '0'.repeat(1024) + '1' }, new Set()), {
      decision: 'REJECT', reason_code: 'INVALID_INPUT',
    }, `oversize ${field}`);
  }
  const maximumToken = '0'.repeat(1023) + '1';
  assert.deepEqual(evaluateCondition({
    ...valid(), public_balance: maximumToken, minimum: maximumToken,
    current_block: '0', expiry_block: maximumToken,
    amount: maximumToken, max_transfer: maximumToken,
  }, new Set()), { decision: 'APPROVE', reason_code: 'VALID_CONDITION' });
});

test('accepts uint32 decimal strings or integer numbers at boundaries', () => {
  for (const value of [0, -0, '0', '0000', '0001', 1, 4294967295, '4294967295']) {
    const input = {
      ...valid(), public_balance: value, minimum: value,
      current_block: 0, expiry_block: 1, amount: value, max_transfer: value,
    };
    assert.deepEqual(evaluateCondition(input, new Set()), {
      decision: 'APPROVE', reason_code: 'VALID_CONDITION',
    }, `boundary ${String(value)}`);
  }
  assert.deepEqual(evaluateCondition({
    ...valid(), public_balance: '0010', minimum: 10,
    current_block: 10, expiry_block: '0011', amount: '0010', max_transfer: 10,
  }, new Set()), { decision: 'APPROVE', reason_code: 'VALID_CONDITION' });
});

test('preserves the input and replay state across repeated evaluations', () => {
  const input = Object.freeze({
    ...valid(), registered_vk: '0x' + 'A'.repeat(64),
    recipient: '0x' + 'Ab'.repeat(20), condition_recipient: '0x' + 'aB'.repeat(20),
    proof_tx: '0X' + 'B'.repeat(64),
  });
  const snapshot = structuredClone(input);
  const unrelated = '0x' + 'c'.repeat(64);
  const seen = new Set([unrelated]);
  for (let attempt = 0; attempt < 2; attempt++) {
    assert.deepEqual(evaluateCondition(input, seen), {
      decision: 'APPROVE', reason_code: 'VALID_CONDITION',
    });
    assert.deepEqual(input, snapshot);
    assert.deepEqual([...seen], [unrelated]);
  }
  // Only the caller records consumption; the next evaluation then rejects replay.
  seen.add(input.proof_tx.toLowerCase());
  assert.deepEqual(evaluateCondition(input, seen), {
    decision: 'REJECT', reason_code: 'PROOF_REUSED',
  });
  assert.deepEqual(input, snapshot);
  assert.deepEqual([...seen], [unrelated, input.proof_tx.toLowerCase()]);
});

test('uses the documented precedence for every combination of valid-input traps', () => {
  const traps = [
    [{ proof_vk: '0x' + 'c'.repeat(64) }, 'VK_SUBSTITUTION'],
    [{ public_balance: '999' }, 'THRESHOLD_MISMATCH'],
    [{}, 'PROOF_REUSED'],
    [{ current_block: 8430001 }, 'EXPIRED_CONDITION'],
    [{ recipient: '0x' + '2'.repeat(40) }, 'RECIPIENT_MISMATCH'],
    [{ amount: '1001' }, 'AMOUNT_OVERFLOW'],
  ];
  for (let mask = 0; mask < 2 ** traps.length; mask++) {
    const input = valid();
    const seen = new Set();
    const reasons = [];
    for (const [index, [fields, reason]] of traps.entries()) {
      if (mask & (1 << index)) {
        Object.assign(input, fields);
        if (reason === 'PROOF_REUSED') seen.add(input.proof_tx);
        reasons.push(reason);
      }
    }
    const originalSeen = [...seen];
    const snapshot = structuredClone(input);
    Object.freeze(input);
    assert.deepEqual(evaluateCondition(input, seen), {
      decision: reasons.length ? 'REJECT' : 'APPROVE',
      reason_code: reasons[0] ?? 'VALID_CONDITION',
    }, `active traps: ${reasons.join(', ') || 'none'}`);
    assert.deepEqual(input, snapshot);
    assert.deepEqual([...seen], originalSeen);
  }
});

test('ignores unrelated payload metadata when checking a valid condition', () => {
  const input = {
    ...valid(), decision: 'REJECT', reason_code: 'VK_SUBSTITUTION',
    metadata: { claimed_balance: '-1', already_used: true },
  };
  assert.deepEqual(evaluateCondition(input, new Set()), {
    decision: 'APPROVE', reason_code: 'VALID_CONDITION',
  });
});

test('compares the public balance with the minimum at the uint32 boundary', () => {
  const minimum = '4294967294';
  for (const [public_balance, decision, reason_code] of [
    ['4294967293', 'REJECT', 'THRESHOLD_MISMATCH'],
    [minimum, 'APPROVE', 'VALID_CONDITION'],
    ['4294967295', 'APPROVE', 'VALID_CONDITION'],
  ]) {
    assert.deepEqual(evaluateCondition({ ...valid(), public_balance, minimum }, new Set()), {
      decision, reason_code,
    }, `balance ${public_balance}`);
  }
});

test('rejects all numeric inputs outside uint32 before evaluating traps', () => {
  for (const field of [
    'public_balance', 'minimum', 'expiry_block', 'current_block', 'amount', 'max_transfer',
  ]) {
    for (const value of [
      4294967296, Number.MAX_SAFE_INTEGER, '4294967296', '0004294967296',
      '9007199254740992', '9007199254740993', '18446744073709551615',
      // BN254 field modulus + 1 must not be normalized into the valid value 1.
      (BN254_MODULUS + 1n).toString(),
    ]) {
      const input = { ...valid(), proof_vk: '0x' + 'c'.repeat(64), [field]: value };
      assert.deepEqual(evaluateCondition(input, new Set()), {
        decision: 'REJECT', reason_code: 'INVALID_INPUT',
      }, `out-of-range ${field}: ${value}`);
    }
  }
});

test('rejects distinct full verification keys that alias in the BN254 field', () => {
  const input = {
    ...valid(), registered_vk: '0x' + '1'.padStart(64, '0'),
    proof_vk: '0x' + (BN254_MODULUS + 1n).toString(16).padStart(64, '0'),
  };
  assert.deepEqual(evaluateCondition(input, new Set()), {
    decision: 'REJECT', reason_code: 'VK_SUBSTITUTION',
  });
});

test('accepts reference-protocol short hex identifiers without field reduction', () => {
  assert.deepEqual(evaluateCondition({ ...valid(), registered_vk:'0x123', proof_vk:'0x0123', proof_tx:'0xabc' }, new Set()), {
    decision:'APPROVE', reason_code:'VALID_CONDITION',
  });
});

test('does not confuse distinct proof transactions that alias in the BN254 field', () => {
  const input = {
    ...valid(), proof_tx: '0x' + (BN254_MODULUS + 1n).toString(16).padStart(64, '0'),
  };
  const seen = new Set(['0x' + '1'.padStart(64, '0')]);
  assert.deepEqual(evaluateCondition(input, seen), {
    decision: 'APPROVE', reason_code: 'VALID_CONDITION',
  });
});

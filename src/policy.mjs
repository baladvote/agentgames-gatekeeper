function isUnsignedInteger(value) {
  if (typeof value === 'number') return Number.isSafeInteger(value) && value >= 0;
  // Resource bound for decimal parsing; the uint32 value bound is checked below.
  return typeof value === 'string' && value.length > 0 && value.length <= 1024
    && !/[^0-9]/.test(value);
}

// Policy checks only; cryptographic proof verification belongs to the caller.
// Input is a JSON record. seenSet contains lowercase transaction hashes and is
// caller-owned: evaluation never records consumption or changes either input.
// Rejection precedence: invalid input, VK, threshold, replay, expiry, recipient,
// amount. Numeric fields must fit uint32; decimal strings (including leading
// zeros) or safe integers are accepted. Expiry is strict: current < expiry.
// Numeric hex/exponent syntax and symbolic identifiers require a separate adapter.
// VK/proof references use the reference protocol's 1–64 hex digits; addresses use 40.
// Compare full VK integers; never reduce identifiers modulo the circuit field.
export function evaluateCondition(input, seenSet) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
  }
  const required = [
    'registered_vk', 'proof_vk', 'public_balance', 'minimum',
    'expiry_block', 'current_block', 'recipient', 'condition_recipient',
    'amount', 'max_transfer', 'proof_tx',
  ];
  if (!(seenSet instanceof Set) || !required.every(field => Object.hasOwn(input, field))) {
    return { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
  }
  const hashes = ['registered_vk', 'proof_vk', 'proof_tx'];
  const addresses = ['recipient', 'condition_recipient'];
  if (!hashes.every(field => typeof input[field] === 'string'
    && input[field].length <= 66 && /^0x[0-9a-f]{1,64}$/i.test(input[field]) && !/\s/.test(input[field]))
    || !addresses.every(field => typeof input[field] === 'string'
      && input[field].length === 42 && /^0x[0-9a-f]{40}$/i.test(input[field]))) {
    return { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
  }
  const numericFields = [
    'public_balance', 'minimum', 'expiry_block', 'current_block', 'amount', 'max_transfer',
  ];
  if (!numericFields.every(field => isUnsignedInteger(input[field]))) {
    return { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
  }
  if (numericFields.some(field => BigInt(input[field]) > 0xffffffffn)) {
    return { decision: 'REJECT', reason_code: 'INVALID_INPUT' };
  }
  if (BigInt(input.registered_vk) !== BigInt(input.proof_vk)) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }
  if (BigInt(input.public_balance) < BigInt(input.minimum)) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  }
  if (seenSet.has(input.proof_tx.toLowerCase())) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
  }
  if (BigInt(input.current_block) >= BigInt(input.expiry_block)) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  }
  if (input.recipient.toLowerCase() !== input.condition_recipient.toLowerCase()) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }
  if (BigInt(input.amount) > BigInt(input.max_transfer)) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

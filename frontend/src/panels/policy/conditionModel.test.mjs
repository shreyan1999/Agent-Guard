/**
 * Unit tests for the condition model.
 *
 * Run with:  npm test
 *
 * The schema fixture below is checked against the live backend by
 * `backend/tests/test_condition_builder.py`, so these tests cannot drift onto
 * a grammar the policy engine does not actually implement.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  serialize, serializeClause, parse, validateValue, operatorsFor,
  describeGrouping, isComplete, splitList,
} from './conditionModel.js';

const FIELD = '([A-Za-z_][A-Za-z0-9_.]*)';
const NUM = '(\\d+(?:\\.\\d+)?)';

const schema = {
  operators: [
    { id: 'eq', label: 'equals', value: 'single', types: ['string'],
      template: "{field} == '{value}'", pattern: `^${FIELD}\\s*==\\s*['"]([^'"]+)['"]$` },
    { id: 'ne', label: 'does not equal', value: 'single', types: ['string'],
      template: "{field} != '{value}'", pattern: `^${FIELD}\\s*!=\\s*['"]([^'"]+)['"]$` },
    { id: 'in', label: 'is one of', value: 'list', types: ['string'],
      template: '{field} in [{value}]', pattern: `^${FIELD}\\s+in\\s+\\[([^\\]]*)\\]$` },
    { id: 'gt', label: 'greater than', value: 'number', types: ['number'],
      template: '{field} > {value}', pattern: `^${FIELD}\\s*>\\s*${NUM}$` },
    { id: 'gte', label: 'at least', value: 'number', types: ['number'],
      template: '{field} >= {value}', pattern: `^${FIELD}\\s*>=\\s*${NUM}$` },
    { id: 'lt', label: 'less than', value: 'number', types: ['number'],
      template: '{field} < {value}', pattern: `^${FIELD}\\s*<\\s*${NUM}$` },
    { id: 'lte', label: 'at most', value: 'number', types: ['number'],
      template: '{field} <= {value}', pattern: `^${FIELD}\\s*<=\\s*${NUM}$` },
    { id: 'truthy', label: 'is true', value: 'none', types: ['boolean'],
      template: '{field}', pattern: `^${FIELD}$` },
  ],
  fields: [
    { path: 'action.type', type: 'string' },
    { path: 'agent.trust_score', type: 'number' },
    { path: 'input_text.has_pii', type: 'boolean' },
  ],
  value_forbidden: {
    characters: ["'", '"', '\\n'],
    substrings: [' and ', ' or '],
    by_operator: { in: { characters: [']'] } },
  },
};

const clause = (o) => ({ joiner: 'and', field: '', operator: '', value: '', ...o });

// ── serializing ─────────────────────────────────────────────────────────────

test('renders each operator in AGT form', () => {
  assert.equal(
    serializeClause(clause({ field: 'action.type', operator: 'eq', value: 'drop' }), schema),
    "action.type == 'drop'");
  assert.equal(
    serializeClause(clause({ field: 'agent.trust_score', operator: 'lt', value: '0.8' }), schema),
    'agent.trust_score < 0.8');
  assert.equal(
    serializeClause(clause({ field: 'input_text.has_pii', operator: 'truthy' }), schema),
    'input_text.has_pii');
});

test('quotes every member of an in-list', () => {
  assert.equal(
    serializeClause(clause({ field: 'action.type', operator: 'in', value: 'drop, delete' }), schema),
    "action.type in ['drop','delete']");
});

test('an incomplete clause serializes to nothing', () => {
  assert.equal(serializeClause(clause({ field: 'action.type', operator: 'eq' }), schema), '');
  assert.equal(serialize([clause({ field: 'action.type', operator: 'eq' })], schema), '');
  assert.equal(isComplete([clause({ field: 'x', operator: 'eq' })], schema), false);
});

test('joins clauses with their own joiners', () => {
  const clauses = [
    clause({ field: 'agent.trust_score', operator: 'lt', value: '0.8' }),
    clause({ joiner: 'and', field: 'action.type', operator: 'eq', value: 'send_email' }),
  ];
  assert.equal(serialize(clauses, schema),
    "agent.trust_score < 0.8 and action.type == 'send_email'");
});

// ── round-trip ──────────────────────────────────────────────────────────────

test('every operator survives a round trip', () => {
  const samples = [
    "action.type == 'drop'",
    "action.type != 'read'",
    "action.type in ['drop','delete']",
    'agent.trust_score > 0.5',
    'agent.trust_score >= 0.95',
    'agent.trust_score < 0.3',
    'agent.trust_score <= 0.6',
    'input_text.has_pii',
  ];
  for (const original of samples) {
    const parsed = parse(original, schema);
    assert.ok(parsed, `failed to parse ${original}`);
    assert.equal(serialize(parsed, schema), original, `round trip changed ${original}`);
  }
});

test('reads the shipped default policy back', () => {
  const shipped = 'action.type in ["drop","delete","truncate","shell_exec"]';
  const parsed = parse(shipped, schema);
  assert.ok(parsed);
  assert.equal(parsed[0].value, 'drop, delete, truncate, shell_exec');
  // Re-serialized with single quotes, which AGT accepts identically.
  assert.equal(serialize(parsed, schema),
    "action.type in ['drop','delete','truncate','shell_exec']");
});

test('parses compound conditions and preserves joiners', () => {
  const parsed = parse("agent.trust_score < 0.8 and action.type == 'send_email'", schema);
  assert.equal(parsed.length, 2);
  assert.equal(parsed[1].joiner, 'and');

  const mixed = parse("action.type == 'a' and action.type != 'b' or input_text.has_pii", schema);
  assert.equal(mixed.length, 3);
  assert.equal(mixed[1].joiner, 'and');
  assert.equal(mixed[2].joiner, 'or');
});

test('refuses to represent what it cannot rebuild', () => {
  assert.equal(parse('input_text matches "[0-9]{3}"', schema), null);
  assert.equal(parse('action.type startswith "del"', schema), null);
  assert.equal(parse('', schema), null);
});

// ── value safety ────────────────────────────────────────────────────────────

test('rejects values that would silently break any clause', () => {
  for (const bad of ["it's", 'say "hi"', 'read and write', 'read or write']) {
    assert.ok(validateValue(bad, schema, 'eq'), `should have rejected ${bad}`);
  }
});

test('a closing bracket breaks only the in-list form', () => {
  // AGT's `in` regex stops at the first "]", but == quotes the value.
  assert.ok(validateValue('a]b', schema, 'in'));
  assert.equal(validateValue('a]b', schema, 'eq'), null);
});

test('accepts ordinary values', () => {
  for (const good of ['drop', 'send_email', 'data-agent', '0.85', 'a-b_c.d']) {
    assert.equal(validateValue(good, schema, 'eq'), null, `should have accepted ${good}`);
  }
});

test('the word and inside a token is fine, the separator is not', () => {
  assert.equal(validateValue('android', schema, 'eq'), null);
  assert.ok(validateValue('a and b', schema, 'eq'));
});

// ── operator filtering ──────────────────────────────────────────────────────

test('offers only operators that suit the field type', () => {
  assert.deepEqual(operatorsFor(schema, 'action.type').map((o) => o.id), ['eq', 'ne', 'in']);
  assert.deepEqual(operatorsFor(schema, 'agent.trust_score').map((o) => o.id),
    ['gt', 'gte', 'lt', 'lte']);
  assert.deepEqual(operatorsFor(schema, 'input_text.has_pii').map((o) => o.id), ['truthy']);
});

// ── precedence ──────────────────────────────────────────────────────────────

test('spells out the grouping AGT will apply', () => {
  const all = [
    clause({ field: 'action.type', operator: 'eq', value: 'a' }),
    clause({ joiner: 'and', field: 'input_text.has_pii', operator: 'truthy' }),
  ];
  assert.equal(describeGrouping(all, schema), 'Every condition must match.');

  const any = [
    clause({ field: 'action.type', operator: 'eq', value: 'a' }),
    clause({ joiner: 'or', field: 'action.type', operator: 'eq', value: 'b' }),
  ];
  assert.equal(describeGrouping(any, schema), 'Any one condition may match.');

  const mixed = [
    clause({ field: 'action.type', operator: 'eq', value: 'a' }),
    clause({ joiner: 'and', field: 'input_text.has_pii', operator: 'truthy' }),
    clause({ joiner: 'or', field: 'action.type', operator: 'eq', value: 'c' }),
  ];
  // or binds looser, so the first two group together.
  assert.equal(describeGrouping(mixed, schema),
    "Reads as: (action.type == 'a' and input_text.has_pii) or action.type == 'c'");
});

test('splitList tolerates quotes and spacing', () => {
  assert.deepEqual(splitList(" 'a' , \"b\" ,c "), ['a', 'b', 'c']);
  assert.deepEqual(splitList(''), []);
});

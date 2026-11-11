/**
 * Pure model behind the condition builder.
 *
 * Everything here is driven by `GET /policies/schema`. Operators, their
 * templates and their parse patterns all come from the backend, so the editor
 * cannot emit a clause the policy engine would reject, nor fail to re-open a
 * condition it wrote itself.
 *
 * AGT's expression grammar has no escaping and no parentheses. Two
 * consequences shape this file:
 *
 *   1. A value containing a quote, a bracket, or the substrings " and " /
 *      " or " silently turns the whole rule into one that never matches.
 *      `validateValue` rejects those before they can be typed into a policy.
 *
 *   2. `or` binds looser than `and`: AGT splits on " or " first, so
 *      `A and B or C` means `(A and B) or C`. `describeGrouping` renders that
 *      back to the author rather than leaving it implicit.
 */

/** A clause the builder can render. `joiner` is null on the first clause. */
export const emptyClause = () => ({ joiner: 'and', field: '', operator: '', value: '' });

/**
 * Characters and substrings AGT cannot carry inside a value.
 *
 * Some break every clause; "]" breaks only the bracketed `in` list, whose
 * regex stops at the first one. Passing the operator keeps the builder from
 * refusing a value that would in fact have been fine.
 */
export function validateValue(value, schema, operatorId) {
  const rules = schema?.value_forbidden;
  if (!rules) return null;
  const text = String(value ?? '');
  const perOperator = rules.by_operator?.[operatorId] || {};
  const characters = [...(rules.characters || []), ...(perOperator.characters || [])];
  const substrings = [...(rules.substrings || []), ...(perOperator.substrings || [])];

  for (const ch of characters) {
    const real = ch === '\\n' ? '\n' : ch;
    if (text.includes(real)) {
      return real === '\n'
        ? 'Value cannot contain a line break.'
        : `Value cannot contain ${ch} — AGT has no escaping, so the rule would never match.`;
    }
  }
  for (const sub of substrings) {
    if (text.includes(sub)) {
      return `Value cannot contain "${sub.trim()}" — AGT splits on it before reading the clause, so the rule would never match.`;
    }
  }
  return null;
}

export const findOperator = (schema, id) =>
  (schema?.operators || []).find((o) => o.id === id) || null;

export const findField = (schema, path) =>
  (schema?.fields || []).find((f) => f.path === path) || null;

/** Operators that apply to a field's type. */
export function operatorsFor(schema, fieldPath) {
  const field = findField(schema, fieldPath);
  if (!field) return schema?.operators || [];
  return (schema.operators || []).filter((o) => o.types.includes(field.type));
}

/** Split a comma-separated list into trimmed, unquoted members. */
export const splitList = (value) =>
  String(value ?? '')
    .split(',')
    .map((part) => part.trim().replace(/^['"]|['"]$/g, ''))
    .filter(Boolean);

/** Render one clause using the operator's own template. */
export function serializeClause(clause, schema) {
  const op = findOperator(schema, clause.operator);
  if (!op || !clause.field) return '';
  if (op.value === 'none') return op.template.replace('{field}', clause.field);

  const value =
    op.value === 'list'
      ? splitList(clause.value).map((v) => `'${v}'`).join(',')
      : String(clause.value ?? '').trim();

  if (!value) return '';
  return op.template.replace('{field}', clause.field).replace('{value}', value);
}

/** Render the whole condition. Returns '' if any clause is incomplete. */
export function serialize(clauses, schema) {
  const parts = [];
  for (let i = 0; i < clauses.length; i += 1) {
    const text = serializeClause(clauses[i], schema);
    if (!text) return '';
    parts.push(i === 0 ? text : `${clauses[i].joiner === 'or' ? ' or ' : ' and '}${text}`);
  }
  return parts.join('');
}

/**
 * Read a condition string back into clauses.
 *
 * Returns null when the condition uses anything the builder cannot represent,
 * which is the signal to show it read-only rather than silently rewriting it.
 * Splitting mirrors AGT: " or " first, then " and " within each group.
 */
export function parse(condition, schema) {
  const text = String(condition ?? '').trim();
  if (!text || !schema?.operators?.length) return null;

  const clauses = [];
  const orGroups = text.split(' or ');

  for (let g = 0; g < orGroups.length; g += 1) {
    const andParts = orGroups[g].split(' and ');
    for (let a = 0; a < andParts.length; a += 1) {
      const atom = andParts[a].trim();
      const parsed = parseAtom(atom, schema);
      if (!parsed) return null;
      const first = g === 0 && a === 0;
      clauses.push({ ...parsed, joiner: first ? 'and' : a === 0 ? 'or' : 'and' });
    }
  }
  return clauses;
}

function parseAtom(atom, schema) {
  for (const op of schema.operators) {
    const match = new RegExp(op.pattern).exec(atom);
    if (!match) continue;
    if (op.value === 'none') {
      return { field: match[1], operator: op.id, value: '' };
    }
    const raw = match[2];
    return {
      field: match[1],
      operator: op.id,
      value: op.value === 'list' ? splitList(raw).join(', ') : raw,
    };
  }
  return null;
}

/**
 * Describe how AGT will group the clauses.
 *
 * There are no parentheses in the grammar, so a mixed condition's meaning
 * comes purely from precedence. Saying it out loud is cheaper than letting an
 * author discover it from a denial that did not happen.
 */
export function describeGrouping(clauses, schema) {
  if (clauses.length < 2) return null;
  const joiners = clauses.slice(1).map((c) => c.joiner);
  if (!joiners.includes('or')) return 'Every condition must match.';
  if (!joiners.includes('and')) return 'Any one condition may match.';

  const groups = [];
  let current = [];
  clauses.forEach((clause, i) => {
    if (i > 0 && clause.joiner === 'or') {
      groups.push(current);
      current = [];
    }
    current.push(serializeClause(clause, schema) || '…');
  });
  groups.push(current);

  return `Reads as: ${groups
    .map((g) => (g.length > 1 ? `(${g.join(' and ')})` : g[0]))
    .join(' or ')}`;
}

/** Whether every clause is complete enough to serialize. */
export const isComplete = (clauses, schema) =>
  clauses.length > 0 && clauses.every((c) => serializeClause(c, schema) !== '');

/* ── plain English ────────────────────────────────────────────────────────
 * A rule is only as accountable as the sentence you can say about it. These
 * two maps cover the closed field list and operator set the backend publishes;
 * anything outside them falls back to the raw path or symbol rather than being
 * silently dropped, so a condition can never read as saying less than it does.
 */

const FIELD_PHRASE = {
  'action.type': 'the action',
  'agent.id': 'the agent name',
  'agent.agent_id': "the agent's lifecycle id",
  'agent.state': "the agent's lifecycle state",
  'agent.ring': "the agent's execution ring",
  'agent.trust_score': "the agent's trust score",
  'tool.name': 'the tool name',
  'tool.category': "the tool's category",
  'tool.risk': "the tool's risk tier",
  'tool.kind': "the tool's kind",
  'sql.verb': 'the SQL verb',
  'sql.target': 'the SQL target',
};

/** Boolean facets read as a whole clause, so `truthy` needs no verb after them. */
const FLAG_PHRASE = {
  'input_text.has_pii': 'the input text contains PII',
  'input_text.has_credentials': 'the input text contains credentials',
};

const OPERATOR_PHRASE = {
  eq: 'is', ne: 'is not', in: 'is one of',
  gt: 'is above', gte: 'is at least', lt: 'is below', lte: 'is at most',
};

const fieldPhrase = (path) =>
  FIELD_PHRASE[path] || FLAG_PHRASE[path] || String(path ?? '').replace(/[._]/g, ' ');

function humanizeClause(clause, schema) {
  const op = findOperator(schema, clause.operator);
  if (op?.value === 'none') {
    return FLAG_PHRASE[clause.field] || `${fieldPhrase(clause.field)} is set`;
  }
  const verb = OPERATOR_PHRASE[clause.operator] || op?.label || clause.operator;
  const raw = String(clause.value ?? '').trim();
  const value = op?.value === 'list'
    ? splitList(clause.value).map((v) => `“${v}”`).join(' or ')
    : op?.value === 'number' ? raw : `“${raw}”`;
  return `${fieldPhrase(clause.field)} ${verb} ${value}`;
}

/**
 * Say a condition out loud, honouring AGT's precedence.
 *
 * Returns null when the condition uses something the grammar model cannot
 * read, which is the signal to show the raw condition instead of a sentence
 * that might not mean the same thing.
 */
export function humanize(condition, schema) {
  const clauses = parse(condition, schema);
  if (!clauses) return null;

  // No parentheses in the grammar: " or " splits first, so `A and B or C`
  // is `(A and B) or C`. Group the same way before wording it.
  const groups = [];
  let current = [];
  clauses.forEach((clause, i) => {
    if (i > 0 && clause.joiner === 'or') {
      groups.push(current);
      current = [];
    }
    current.push(humanizeClause(clause, schema));
  });
  groups.push(current);

  return groups.map((g) => g.join(' and ')).join(', or ');
}

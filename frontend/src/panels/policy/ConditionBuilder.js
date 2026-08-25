import { useEffect, useMemo, useRef, useState } from 'react';
import { Plus, X, AlertTriangle, Code } from 'lucide-react';
import {
  emptyClause, operatorsFor, findOperator, findField, serialize, parse,
  validateValue, describeGrouping, isComplete,
} from './conditionModel';

/**
 * Builds an AGT policy condition from pickers rather than free text.
 *
 * The grammar AGT implements is small and closed, so a builder can cover all
 * of it — and by covering all of it, it makes the unparsable rule impossible
 * to author rather than merely reported after the fact.
 *
 * Props:
 *   schema    — GET /policies/schema
 *   value     — the current condition string
 *   onChange  — called with the new condition string
 */
export default function ConditionBuilder({ schema, value, onChange }) {
  const [clauses, setClauses] = useState([emptyClause()]);
  // A condition the builder cannot represent is shown, not silently rewritten.
  const [unrepresentable, setUnrepresentable] = useState(null);
  // What we last handed upwards. Comparing against this distinguishes our own
  // echo from a condition arriving from elsewhere, without making the effect
  // depend on the clause state it would then overwrite.
  const emitted = useRef('');

  useEffect(() => {
    if (!schema) return;
    if (value === emitted.current) return;

    if (!value) {
      setClauses([emptyClause()]);
      setUnrepresentable(null);
      emitted.current = '';
      return;
    }
    const parsed = parse(value, schema);
    if (parsed) {
      setClauses(parsed);
      setUnrepresentable(null);
      emitted.current = value;
    } else {
      setUnrepresentable(value);
    }
  }, [value, schema]);

  const errors = useMemo(
    () => clauses.map((c) => validateValue(c.value, schema, c.operator)),
    [clauses, schema],
  );

  const commit = (next) => {
    setClauses(next);
    const anyError = next.some((c) => validateValue(c.value, schema, c.operator));
    const condition = anyError ? '' : serialize(next, schema);
    emitted.current = condition;
    onChange(condition);
  };

  const update = (index, patch) => {
    const next = clauses.map((c, i) => (i === index ? { ...c, ...patch } : c));
    // Changing the field can invalidate the operator, and changing either can
    // invalidate the value, so reset downstream rather than keep a stale pair.
    if (patch.field !== undefined) {
      const allowed = operatorsFor(schema, patch.field).map((o) => o.id);
      if (!allowed.includes(next[index].operator)) {
        next[index].operator = allowed[0] || '';
        next[index].value = '';
      }
    }
    if (patch.operator !== undefined) next[index].value = '';
    commit(next);
  };

  const preview = serialize(clauses, schema);
  const grouping = describeGrouping(clauses, schema);
  const complete = isComplete(clauses, schema);

  if (!schema) {
    return <div style={{ fontSize: 12, color: 'var(--text-3)' }}>Loading grammar…</div>;
  }

  if (unrepresentable !== null) {
    return (
      <div style={box('var(--yellow)')}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 8 }}>
          <AlertTriangle size={15} color="var(--yellow)" style={{ flexShrink: 0, marginTop: 1 }} />
          <div style={{ fontSize: 12, color: 'var(--text-2)' }}>
            This condition was not written by the builder and uses something it
            cannot represent. It is shown as stored so nothing is silently rewritten.
          </div>
        </div>
        <code style={{ fontSize: 12, display: 'block', marginBottom: 10, wordBreak: 'break-all' }}>
          {unrepresentable}
        </code>
        <button className="btn btn-ghost" style={{ fontSize: 11 }}
          onClick={() => { setUnrepresentable(null); setClauses([emptyClause()]); onChange(''); }}>
          Replace with a built condition
        </button>
      </div>
    );
  }

  return (
    <div>
      {clauses.map((clause, i) => {
        const operators = operatorsFor(schema, clause.field);
        const op = findOperator(schema, clause.operator);
        const field = findField(schema, clause.field);
        const error = errors[i];

        return (
          <div key={i} style={{ marginBottom: 8 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              {i === 0 ? (
                <span style={joinerLabel}>WHERE</span>
              ) : (
                <select
                  value={clause.joiner}
                  onChange={(e) => commit(clauses.map((c, j) =>
                    (j === i ? { ...c, joiner: e.target.value } : c)))}
                  style={{ width: 74, fontFamily: 'var(--mono)', fontSize: 11 }}
                >
                  <option value="and">and</option>
                  <option value="or">or</option>
                </select>
              )}

              <select value={clause.field} onChange={(e) => update(i, { field: e.target.value })}
                style={{ flex: '1 1 170px', minWidth: 150 }}>
                <option value="">field…</option>
                {(schema.fields || []).map((f) => (
                  <option key={f.path} value={f.path}>{f.path}</option>
                ))}
              </select>

              <select value={clause.operator} onChange={(e) => update(i, { operator: e.target.value })}
                disabled={!clause.field} style={{ flex: '0 1 150px', minWidth: 130 }}>
                <option value="">is…</option>
                {operators.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
              </select>

              {op && op.value !== 'none' && (
                <input
                  value={clause.value}
                  onChange={(e) => commit(clauses.map((c, j) =>
                    (j === i ? { ...c, value: e.target.value } : c)))}
                  type={op.value === 'number' ? 'number' : 'text'}
                  step={op.value === 'number' ? '0.01' : undefined}
                  placeholder={op.value === 'list' ? 'drop, delete, truncate' : 'value'}
                  style={{
                    flex: '1 1 160px', minWidth: 140,
                    borderColor: error ? 'var(--red)' : undefined,
                  }}
                />
              )}

              {clauses.length > 1 && (
                <button
                  onClick={() => commit(clauses.filter((_, j) => j !== i))}
                  title="Remove condition"
                  style={{ background: 'none', color: 'var(--text-3)', padding: 4, lineHeight: 0 }}
                >
                  <X size={14} />
                </button>
              )}
            </div>

            {field?.help && !error && (
              <div style={hint}>{field.help}</div>
            )}
            {op?.value === 'list' && !error && (
              <div style={hint}>Comma-separated. Each value is quoted for you.</div>
            )}
            {error && (
              <div style={{ ...hint, color: 'var(--red)' }}>{error}</div>
            )}
          </div>
        );
      })}

      <button className="btn btn-ghost" onClick={() => commit([...clauses, emptyClause()])}
        style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 5, marginTop: 4 }}>
        <Plus size={12} /> Add condition
      </button>

      {grouping && (
        <div style={{ ...hint, marginTop: 10, marginLeft: 0 }}>{grouping}</div>
      )}

      <div style={{
        marginTop: 10, padding: '8px 10px', borderRadius: 6,
        background: 'var(--bg-3)', border: '1px solid var(--border)',
        display: 'flex', gap: 8, alignItems: 'flex-start',
      }}>
        <Code size={13} color="var(--text-3)" style={{ flexShrink: 0, marginTop: 2 }} />
        <code style={{
          fontSize: 12, wordBreak: 'break-all',
          color: complete ? 'var(--text)' : 'var(--text-3)',
        }}>
          {preview || (complete ? '' : 'Choose a field, an operator and a value.')}
        </code>
      </div>
    </div>
  );
}

const joinerLabel = {
  width: 74, fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--text-3)',
  letterSpacing: '.08em', textAlign: 'center',
};

const hint = {
  fontSize: 11, color: 'var(--text-3)', marginTop: 4, marginLeft: 82,
};

const box = (color) => ({
  padding: '12px 14px', borderRadius: 8,
  background: 'var(--bg-2)', border: `1px solid ${color}44`,
});

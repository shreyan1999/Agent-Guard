/**
 * Slider — Fluent's anatomy: a 4px rail, a solid progress fill, and a ringed
 * thumb that rides the filled end.
 *
 * The fill keeps this app's trust bands rather than Fluent's brand blue,
 * because the colour is carrying meaning here (>=80% healthy, >=50% caution)
 * and a slider should never disagree with the badge sitting next to it.
 *
 * The visible parts are inert; the real control is a transparent native range
 * input laid over the top, so keyboard and assistive-tech behaviour is the
 * platform's own.
 */

import { useState } from 'react';

const bandOf = (ratio) => (ratio < 0.5 ? 'low' : ratio < 0.8 ? 'mid' : 'high');

export default function Slider({
  value,
  defaultValue,
  min = 0,
  max = 1,
  step = 0.01,
  onChange,
  onCommit,
  band,
  ariaLabel,
  className = '',
  style,
}) {
  const controlled = value !== undefined;
  const [internal, setInternal] = useState(defaultValue ?? min);
  const current = controlled ? value : internal;

  const ratio = max === min ? 0 : (current - min) / (max - min);
  const tone = band ?? bandOf(ratio);

  const handle = (e) => {
    const v = Number(e.target.value);
    if (!controlled) setInternal(v);
    onChange?.(v);
  };

  const commit = (e) => onCommit?.(Number(e.target.value));

  // The track is inset by half a thumb at each end so the thumb never hangs
  // off the control; the fill and the thumb share that same usable width.
  const along = `calc(${ratio} * (100% - var(--fslider-thumb)))`;

  return (
    <div className={`fslider band-${tone} ${className}`} style={style}>
      <span className="fslider-rail" aria-hidden />
      <span className="fslider-fill" style={{ width: along }} aria-hidden />

      <input
        type="range"
        className="fslider-input"
        min={min} max={max} step={step}
        value={current}
        aria-label={ariaLabel}
        onChange={handle}
        onMouseUp={commit}
        onTouchEnd={commit}
        onKeyUp={commit}
      />

      <span className="fslider-thumb" style={{ left: along }} aria-hidden />
    </div>
  );
}

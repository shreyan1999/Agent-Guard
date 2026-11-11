/**
 * Apple-style frosted glass nav.
 *
 * Ported from the supplied AppleGlassNav. framer-motion's `layoutId` pill is
 * reproduced by measuring the active item and sliding a single absolutely
 * positioned element, so the effect survives without the dependency. The
 * original is uncontrolled and light-only; this one takes the active tab from
 * the app and picks up both themes from tokens.
 */

import { useEffect, useLayoutEffect, useRef, useState } from 'react';

export default function GlassNav({ items, active, onSelect, className = '' }) {
  const navRef = useRef(null);
  const [pill, setPill] = useState(null);

  useLayoutEffect(() => {
    const nav = navRef.current;
    if (!nav) return undefined;

    // offsetLeft, not getBoundingClientRect: the pill is absolutely positioned
    // inside the scroll container, so it has to move in unscrolled coordinates.
    const measure = () => {
      const el = nav.querySelector(`[data-nav-id="${active}"]`);
      if (el) setPill({ left: el.offsetLeft, width: el.offsetWidth });
    };

    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(nav);
    return () => ro.disconnect();
  }, [active, items]);

  // Narrow viewports scroll the pill horizontally; keep the selected tab on
  // screen. Adjusting scrollLeft directly rather than scrollIntoView, which
  // would also move the page vertically.
  useEffect(() => {
    const nav = navRef.current;
    const el = nav?.querySelector(`[data-nav-id="${active}"]`);
    if (!nav || !el) return;

    const pad = 12;
    const start = el.offsetLeft - pad;
    const end = el.offsetLeft + el.offsetWidth - nav.clientWidth + pad;

    if (start < nav.scrollLeft) nav.scrollTo({ left: start, behavior: 'smooth' });
    else if (end > nav.scrollLeft) nav.scrollTo({ left: end, behavior: 'smooth' });
  }, [active]);

  return (
    <nav ref={navRef} className={`glass-nav ${className}`.trim()} aria-label="Sections">
      {pill && (
        <span
          className="glass-nav-pill"
          aria-hidden
          style={{ transform: `translateX(${pill.left}px)`, width: pill.width }}
        />
      )}

      {items.map(({ id, label }) => (
        <button
          key={id}
          type="button"
          data-nav-id={id}
          className={`glass-nav-item ${active === id ? 'active' : ''}`}
          aria-current={active === id ? 'page' : undefined}
          onClick={() => onSelect(id)}
        >
          <span className="glass-nav-label">{label}</span>
        </button>
      ))}
    </nav>
  );
}

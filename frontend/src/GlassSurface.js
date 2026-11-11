/**
 * GlassSurface — React wrapper around liquid-glass-js's Container.
 *
 * The library is imperative: `new Container(...)` builds its own div with a
 * WebGL canvas behind it, and you append your content into that div. This
 * bridges that to React by creating the Container once and portalling children
 * into its element, so the content stays declarative while the glass stays the
 * library's.
 *
 * Two things about how the effect works drive the design here:
 *
 *   1. The shader refracts a snapshot of the page taken with html2canvas. That
 *      snapshot is static on `Container` and shared by every instance, so the
 *      ~700ms capture is paid once, not per surface.
 *   2. The snapshot never refreshes itself. Our content changes — the poll,
 *      tab switches, the theme — so `refreshGlass()` clears it and lets the
 *      next mount re-capture. Without that the glass refracts whatever the
 *      page looked like at load.
 *
 * The canvas cannot see anything painted after the capture, and it ignores
 * elements that are themselves glass, so a glass surface refracts the ordinary
 * page behind it rather than other glass.
 */

import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Container } from './vendor/liquid-glass/container';

/** Drop the shared snapshot so the next surface to mount re-captures. */
export function refreshGlass() {
  Container.pageSnapshot = null;
  Container.isCapturing = false;
  Container.waitingForSnapshot = [];
}

export default function GlassSurface({
  type = 'rounded',
  radius = 8,
  tintOpacity = 0.2,
  className = '',
  style,
  children,
}) {
  const hostRef = useRef(null);
  const [mount, setMount] = useState(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return undefined;

    // WebGL is required; without it the host simply renders its children
    // unglassed rather than failing.
    let container;
    try {
      container = new Container({ borderRadius: radius, type, tintOpacity });
    } catch {
      return undefined;
    }

    host.appendChild(container.element);
    setMount(container.element);

    return () => {
      const i = Container.instances.indexOf(container);
      if (i > -1) Container.instances.splice(i, 1);
      container.element.remove();
      setMount(null);
    };
  }, [type, radius, tintOpacity]);

  return (
    <div ref={hostRef} className={`glass-host ${className}`.trim()} style={style}>
      {mount ? createPortal(children, mount) : null}
    </div>
  );
}

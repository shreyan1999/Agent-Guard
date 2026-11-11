/**
 * Landing — the full-screen hero shown before the dashboard.
 *
 * Deliberately its own visual world: black and white, Inter, a full-viewport
 * video. None of the app's tokens reach in here and none of these styles reach
 * out — every class is `lp-` prefixed and lives in Landing.css.
 *
 * `onEnter` hands control to the dashboard, which opens on Overview.
 *
 * The video deliberately does not loop: it plays once and holds on its final
 * frame, so the hand rises and stays raised instead of resetting.
 *
 * The brand is static, not staged: no letter-by-letter reveal, no gate on the
 * tagline below it. "AgentGuard" is an outline -- the shadcn "outline-text"
 * treatment, transparent fill with a stroked outline -- ported to plain CSS
 * (`.lp-brand-row` in Landing.css) since this app has no Tailwind. It and the
 * tagline both simply fade up on mount, staggered by a small delay each, the
 * way the rest of the page always has.
 */

import { motion } from 'motion/react';
import './Landing.css';

const VIDEO_SRC =
  'https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260508_215831_c6a8989c-d716-4d8d-8745-e972a2eec711.mp4';

// The one easing the whole page shares.
const EASE = [0.16, 1, 0.3, 1];

// Lucide's arrow-right glyph, hand-authored: this app has no lucide-react
// dependency, and it's one path for two icons.
function ArrowRightIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden focusable="false" {...props}>
      <path d="M5 12h14" />
      <path d="m12 5 7 7-7 7" />
    </svg>
  );
}

export default function Landing({ onEnter }) {
  return (
    <div className="lp">
      {/* ── background video ─────────────────────────────────────────────── */}
      <motion.div
        className="lp-video-wrap"
        initial={{ opacity: 0, scale: 1.05 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 1.8, ease: EASE }}
      >
        <video
          className="lp-video"
          src={VIDEO_SRC}
          autoPlay
          muted
          playsInline
        />
      </motion.div>

      {/* ── footer content: brand, tagline, CTA — one grouped block ──────── */}
      <div className="lp-footer">
        <div className="lp-footer-left">
          <motion.h2
            className="lp-brand-row"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, ease: EASE }}
          >
            AgentGuard
          </motion.h2>

          <motion.h1
            className="lp-heading"
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.7, delay: 0.15, ease: EASE }}
          >
            Govern every agent.
            <br />
            Prove every call.
          </motion.h1>

          <motion.div
            className="lp-actions"
            initial={{ y: 16, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.7, delay: 0.3, ease: EASE }}
          >
            <button type="button" className="lp-btn lp-btn-flow" onClick={onEnter}>
              <ArrowRightIcon className="lp-flow-arrow lp-flow-arrow-in" />
              <span className="lp-flow-label">Get started</span>
              <span className="lp-flow-circle" aria-hidden />
              <ArrowRightIcon className="lp-flow-arrow lp-flow-arrow-out" />
            </button>
          </motion.div>
        </div>
      </div>
    </div>
  );
}

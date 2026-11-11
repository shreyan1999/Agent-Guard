/**
 * BentoGrid — a responsive, animated bento layout with named slots.
 *
 * Ported from the shadcn "bento-product-features" component. That version is
 * TypeScript + Tailwind + framer-motion; this app is plain JS with its own CSS
 * system (see index.css `.bento*`), so the same idea is rebuilt natively: named
 * slots, a staggered spring entrance, and a grid that collapses to one column.
 * `motion` is already a dependency (Landing.js), so nothing new is installed.
 *
 * Desktop layout (four columns, four equal rows, filling the height it is given):
 *
 *     ┌──────┬────────────────────┬────────┐
 *     │      │ hero               │        │
 *     │      │                    │ policy │
 *     │ tall ├────────────────────┤        │
 *     │      │ wide               ├────────┤
 *     │      │                    │ attn   │
 *     └──────┴────────────────────┴────────┘
 *
 * `hero` and `wide` are the two-column cards; `policy` and `attention` share
 * the right-hand column, three rows to one. The reference layout's small
 * "counts" and "statistic" cards are not slots here: they sit in the page
 * header instead, so the grid gets the whole screen.
 */

import { motion, MotionConfig } from 'motion/react';

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.08, delayChildren: 0.05 },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { type: 'spring', stiffness: 100, damping: 12 },
  },
};

// Order is the stagger order, so it reads top-to-bottom, left-to-right.
const SLOTS = ['tall', 'hero', 'policy', 'wide', 'attention'];

export function BentoGrid({ className = '', ...slots }) {
  return (
    // `user` honours prefers-reduced-motion: the entrance becomes a plain fade.
    <MotionConfig reducedMotion="user">
      <motion.section
        className={`bento ${className}`}
        variants={containerVariants}
        initial="hidden"
        animate="visible"
      >
        {SLOTS.filter(name => slots[name] != null).map(name => (
          <motion.div key={name} variants={itemVariants} className={`bento-cell bento-${name}`}>
            {slots[name]}
          </motion.div>
        ))}
      </motion.section>
    </MotionConfig>
  );
}

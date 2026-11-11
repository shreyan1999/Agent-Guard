/**
 * Light / dark switch, drawn as a Fluent subtle icon button.
 *
 * It sits in the brand bar, so it takes the bar's own hover treatment
 * (`.topnav-btn`) rather than the page's button styles. The glyph shows the
 * theme you would move to, which is the convention Microsoft's own apps use.
 */

import { WeatherMoonRegular, WeatherSunnyRegular } from '@fluentui/react-icons';

export default function ThemeToggle({ theme, onChange }) {
  const light = theme === 'light';
  const label = light ? 'Switch to dark theme' : 'Switch to light theme';

  return (
    <button
      type="button"
      className="topnav-btn"
      title={label}
      aria-label={label}
      onClick={() => onChange(light ? 'dark' : 'light')}
    >
      {light ? <WeatherMoonRegular fontSize={20} /> : <WeatherSunnyRegular fontSize={20} />}
    </button>
  );
}

/**
 * Fluent icon set.
 *
 * The app draws from Microsoft's Fluent UI System Icons. Every glyph is
 * re-exported here under the name the call sites already use, so a panel asks
 * for `ShieldCheck` and gets Fluent's `ShieldCheckmark`. Keeping the shim means
 * the swap is one file rather than fifty import lines.
 *
 * Fluent icons size themselves from font-size (their box is 1em square), where
 * the previous set took a `size` prop — so that is what the wrapper translates.
 * `strokeWidth` is dropped: Fluent glyphs are drawn shapes, not strokes, and
 * weight is chosen by picking the Regular or Filled cut instead.
 */

import {
  PulseRegular,
  WarningRegular,
  ProhibitedRegular,
  AlertOnRegular,
  CheckmarkRegular,
  CheckmarkCircleRegular,
  CircleHintRegular,
  ClipboardTaskListLtrRegular,
  ClockRegular,
  CloudRegular,
  CodeRegular,
  DatabaseRegular,
  ArrowDownloadRegular,
  EyeOffRegular,
  DocumentCheckmarkRegular,
  DocumentJavascriptRegular,
  DocumentTextRegular,
  FingerprintRegular,
  BeakerRegular,
  BranchCompareRegular,
  BranchForkRegular,
  GlobeRegular,
  HardDriveRegular,
  HistoryRegular,
  KeyRegular,
  LinkRegular,
  TextBulletListTreeRegular,
  LockClosedRegular,
  MailRegular,
  ChatRegular,
  SubtractRegular,
  PauseCircleRegular,
  EditRegular,
  PlayRegular,
  PlayCircleRegular,
  PlugConnectedRegular,
  AddRegular,
  PowerRegular,
  ArrowClockwiseRegular,
  FlowRegular,
  ScalesRegular,
  SearchRegular,
  ShieldErrorRegular,
  ShieldCheckmarkRegular,
  ShieldProhibitedRegular,
  ShieldDismissRegular,
  TargetArrowRegular,
  WindowConsoleRegular,
  DeleteRegular,
  ArrowTrendingDownRegular,
  ArrowTrendingRegular,
  PersonRegular,
  DismissRegular,
  DismissCircleRegular,
  PersonFilled,
  CheckmarkCircleFilled,
  ProhibitedFilled,
  ScalesFilled,
  WindowConsoleFilled,
  HistoryFilled,
  GlobeFilled,
  DatabaseFilled,
  MailFilled,
  DocumentTextFilled,
} from '@fluentui/react-icons';

const sized = (Glyph, name) => {
  const Icon = ({ size = 20, strokeWidth, absoluteStrokeWidth, ...rest }) =>
    <Glyph fontSize={size} {...rest} />;
  Icon.displayName = name;
  return Icon;
};

export const Activity = /* #__PURE__ */ sized(PulseRegular, 'Activity');
export const AlertTriangle = /* #__PURE__ */ sized(WarningRegular, 'AlertTriangle');
export const Ban = /* #__PURE__ */ sized(ProhibitedRegular, 'Ban');
export const BellRing = /* #__PURE__ */ sized(AlertOnRegular, 'BellRing');
export const Check = /* #__PURE__ */ sized(CheckmarkRegular, 'Check');
export const CheckCircle = /* #__PURE__ */ sized(CheckmarkCircleRegular, 'CheckCircle');
export const CircleDashed = /* #__PURE__ */ sized(CircleHintRegular, 'CircleDashed');
export const ClipboardCheck = /* #__PURE__ */ sized(ClipboardTaskListLtrRegular, 'ClipboardCheck');
export const Clock = /* #__PURE__ */ sized(ClockRegular, 'Clock');
export const Cloud = /* #__PURE__ */ sized(CloudRegular, 'Cloud');
export const Code = /* #__PURE__ */ sized(CodeRegular, 'Code');
export const Database = /* #__PURE__ */ sized(DatabaseRegular, 'Database');
export const Download = /* #__PURE__ */ sized(ArrowDownloadRegular, 'Download');
export const EyeOff = /* #__PURE__ */ sized(EyeOffRegular, 'EyeOff');
export const FileCheck = /* #__PURE__ */ sized(DocumentCheckmarkRegular, 'FileCheck');
export const FileCode = /* #__PURE__ */ sized(DocumentJavascriptRegular, 'FileCode');
export const FileText = /* #__PURE__ */ sized(DocumentTextRegular, 'FileText');
export const Fingerprint = /* #__PURE__ */ sized(FingerprintRegular, 'Fingerprint');
export const FlaskConical = /* #__PURE__ */ sized(BeakerRegular, 'FlaskConical');
export const GitCompare = /* #__PURE__ */ sized(BranchCompareRegular, 'GitCompare');
export const GitMerge = /* #__PURE__ */ sized(BranchForkRegular, 'GitMerge');
export const Globe = /* #__PURE__ */ sized(GlobeRegular, 'Globe');
export const HardDrive = /* #__PURE__ */ sized(HardDriveRegular, 'HardDrive');
export const History = /* #__PURE__ */ sized(HistoryRegular, 'History');
export const KeyRound = /* #__PURE__ */ sized(KeyRegular, 'KeyRound');
export const Link2 = /* #__PURE__ */ sized(LinkRegular, 'Link2');
export const ListTree = /* #__PURE__ */ sized(TextBulletListTreeRegular, 'ListTree');
export const Lock = /* #__PURE__ */ sized(LockClosedRegular, 'Lock');
export const Mail = /* #__PURE__ */ sized(MailRegular, 'Mail');
export const MessageSquare = /* #__PURE__ */ sized(ChatRegular, 'MessageSquare');
export const Minus = /* #__PURE__ */ sized(SubtractRegular, 'Minus');
export const PauseCircle = /* #__PURE__ */ sized(PauseCircleRegular, 'PauseCircle');
export const Pencil = /* #__PURE__ */ sized(EditRegular, 'Pencil');
export const Play = /* #__PURE__ */ sized(PlayRegular, 'Play');
export const PlayCircle = /* #__PURE__ */ sized(PlayCircleRegular, 'PlayCircle');
export const Plug = /* #__PURE__ */ sized(PlugConnectedRegular, 'Plug');
export const Plus = /* #__PURE__ */ sized(AddRegular, 'Plus');
export const Power = /* #__PURE__ */ sized(PowerRegular, 'Power');
export const RefreshCw = /* #__PURE__ */ sized(ArrowClockwiseRegular, 'RefreshCw');
export const Route = /* #__PURE__ */ sized(FlowRegular, 'Route');
export const Scale = /* #__PURE__ */ sized(ScalesRegular, 'Scale');
export const Search = /* #__PURE__ */ sized(SearchRegular, 'Search');
export const ShieldAlert = /* #__PURE__ */ sized(ShieldErrorRegular, 'ShieldAlert');
export const ShieldCheck = /* #__PURE__ */ sized(ShieldCheckmarkRegular, 'ShieldCheck');
export const ShieldOff = /* #__PURE__ */ sized(ShieldProhibitedRegular, 'ShieldOff');
export const ShieldX = /* #__PURE__ */ sized(ShieldDismissRegular, 'ShieldX');
export const Swords = /* #__PURE__ */ sized(TargetArrowRegular, 'Swords');
export const Terminal = /* #__PURE__ */ sized(WindowConsoleRegular, 'Terminal');
export const Trash2 = /* #__PURE__ */ sized(DeleteRegular, 'Trash2');
export const TrendingDown = /* #__PURE__ */ sized(ArrowTrendingDownRegular, 'TrendingDown');
export const TrendingUp = /* #__PURE__ */ sized(ArrowTrendingRegular, 'TrendingUp');
export const User = /* #__PURE__ */ sized(PersonRegular, 'User');
export const X = /* #__PURE__ */ sized(DismissRegular, 'X');
export const XCircle = /* #__PURE__ */ sized(DismissCircleRegular, 'XCircle');

/* Filled cuts. Fluent uses Regular for wayfinding and Filled for selected
   states or "smaller moments that need a little more weight and readability"
   — which is exactly what the tinted metric and tool glyphs are. */
export const UserSolid = /* #__PURE__ */ sized(PersonFilled, 'UserSolid');
export const CheckCircleSolid = /* #__PURE__ */ sized(CheckmarkCircleFilled, 'CheckCircleSolid');
export const BanSolid = /* #__PURE__ */ sized(ProhibitedFilled, 'BanSolid');
export const ScaleSolid = /* #__PURE__ */ sized(ScalesFilled, 'ScaleSolid');
export const TerminalSolid = /* #__PURE__ */ sized(WindowConsoleFilled, 'TerminalSolid');
export const HistorySolid = /* #__PURE__ */ sized(HistoryFilled, 'HistorySolid');
export const GlobeSolid = /* #__PURE__ */ sized(GlobeFilled, 'GlobeSolid');
export const DatabaseSolid = /* #__PURE__ */ sized(DatabaseFilled, 'DatabaseSolid');
export const MailSolid = /* #__PURE__ */ sized(MailFilled, 'MailSolid');
export const FileTextSolid = /* #__PURE__ */ sized(DocumentTextFilled, 'FileTextSolid');

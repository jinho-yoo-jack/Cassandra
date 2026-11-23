---
version: alpha
name: Cassandra Risk Explorer
description: Operational vulnerability triage with a readable, progressive dependency map.
colors:
  primary: "#4D94FC"
  on-primary: "#090D16"
  background: "#090D16"
  on-background: "#EAEFF5"
  surface: "#101622"
  on-surface: "#EAEFF5"
  muted: "#1E2430"
  on-muted: "#969FAB"
  canvas: "#0D111B"
  on-canvas: "#EAEFF5"
  border: "#282E3B"
  ring: "#8CB9FF"
  critical: "#F8495F"
  on-critical: "#090D16"
  high: "#F97C3D"
  on-high: "#090D16"
  medium: "#EDBC4A"
  on-medium: "#090D16"
  low: "#49ABD6"
  on-low: "#090D16"
typography:
  heading:
    fontFamily: "Pretendard Variable, Pretendard, -apple-system, BlinkMacSystemFont, Segoe UI, system-ui, sans-serif"
    fontSize: 1.125rem
    fontWeight: 600
    lineHeight: 1.4
  body:
    fontFamily: "Pretendard Variable, Pretendard, -apple-system, BlinkMacSystemFont, Segoe UI, system-ui, sans-serif"
    fontSize: 0.875rem
    fontWeight: 400
    lineHeight: 1.5
  mono:
    fontFamily: "JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: 0.875rem
    fontWeight: 400
    lineHeight: 1.5
spacing:
  xs: 4px
  sm: 8px
  md: 12px
  lg: 16px
  xl: 24px
rounded:
  sm: 4px
  md: 8px
  lg: 10px
components:
  graph-canvas:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.on-canvas}"
    typography: "{typography.body}"
  panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "{spacing.lg}"
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.body}"
    rounded: "{rounded.sm}"
    padding: "{spacing.sm}"
  button-secondary:
    backgroundColor: "{colors.muted}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body}"
    rounded: "{rounded.sm}"
    padding: "{spacing.sm}"
  finding-critical:
    backgroundColor: "{colors.critical}"
    textColor: "{colors.on-critical}"
    rounded: "{rounded.sm}"
  finding-high:
    backgroundColor: "{colors.high}"
    textColor: "{colors.on-high}"
    rounded: "{rounded.sm}"
  finding-medium:
    backgroundColor: "{colors.medium}"
    textColor: "{colors.on-medium}"
    rounded: "{rounded.sm}"
  finding-low:
    backgroundColor: "{colors.low}"
    textColor: "{colors.on-low}"
    rounded: "{rounded.sm}"
---

## Overview

Primary direction: **Operational**. Readable, focused, explainable. Preserve Cassandra's existing dark/light visual language, not a new brand. Default dark hex values above were sampled from the live app's existing OKLCH theme; semantic CSS variables in `web/src/index.css` remain the theme source. Existing light values are retained under the same variable names, without component-level dark/light branches.

Audience: developers/security engineers deciding what to inspect and remediate in repositories with hundreds or thousands of components. The primary task is choosing a vulnerable component, understanding its dependency context, then inspecting or initiating its existing remediation workflow. This is not exploit reachability analysis.

## Signature Element

A risk-ranked list and a focused dependency map operate together. The first screen is a readable project/manifest overview, not a 6% zoom hairball. Selecting a risk item reveals only its incoming dependency context and a persistent detail panel. The bottom-right navigator always makes the current viewport understandable.

## Colors

Use semantic surfaces and text pairs; maintain WCAG AA contrast for actual new control/body pairs. Primary blue indicates interaction/selection, not vulnerability. Severity colors are reserved for vulnerable nodes and badges; intermediary dependency nodes stay neutral. Highlight selection by outline and text/icon as well as color. A separate bright focus ring is visible on both selected and unselected surfaces. Scope local styling to the graph experience; do not recolor unrelated pages.

The format's component property whitelist has no border/focus-stroke property. The linter's orphan warnings for `border` and `ring` are therefore accepted: these tokens are consumed by semantic CSS, not by fake component text/background declarations.

## Typography

Keep the current Pretendard/system stack and monospace identifiers. New Korean controls, list text and detail prose have a 14px floor before canvas scaling. Truncate long package identifiers only with a full accessible name/title and an untruncated detail view. Counters use tabular numerals. Far-zoom canvas glyphs are navigation marks, never the only readable representation of a finding.

## Layout

- Desktop: risk list (approximately 300px, independently scrollable), flexible canvas, optional collapsible detail panel (approximately 340px). Detail is closed until selection, so the canvas is not permanently squeezed.
- Tablet: collapsible list/detail panels; controls wrap without page-level horizontal overflow.
- Mobile: list-first with an explicit map toggle or stacked bounded-height map, and dismissible detail content. Do not compress three desktop columns into 375px.
- Keep map navigation controls and minimap together at the bottom-right, with no overlap. Default map size about 200×130px desktop; compact/collapsible on narrow screens. Show current zoom, whole-view fit and selection fit. Its caption says it represents the current filtered/projected view.
- Keep the overview small by displaying repository and project/manifest groups, with member and vulnerable-component counts derived from real graph data. Do not invent service boundaries. Expand/collapse a group or focus it to progressively reveal its direct dependencies; expand transitive branches deliberately rather than displaying the whole closure immediately.
- Distinguish matching findings, vulnerable components, displayed graph nodes, and total graph nodes. These nouns must match their counts. Project aggregates may share dependencies and must not be summed as a global unique count.

## Elevation & Depth

Flat layered surfaces with restrained borders. Raise the selected detail surface and existing hover popovers only; no decorative gradients, glass panels or blanket shadows. Keep the canvas background quiet.

## Shapes

Keep the existing radius scale driven by `--radius`. Panels are rounded-md/lg, controls rounded-sm/md. No new decorative shapes.

## Components

- **Risk list:** only components with findings matching active severity/KEV/search filters. Stable deterministic ordering: KEV first, worst matching severity, EPSS (missing shown as unknown, not 0), fixed-version availability, then name/version/id. Display ranking reasons, not an unexplained synthetic risk score. A row is a keyboard-operable button.
- **Filters:** explicit overview, vulnerable-components-only, existing dependency exploration/full structure, and selected-path affordance. The strict vulnerable mode excludes healthy nodes; selected-path mode includes neutral prerequisites but excludes unrelated branches. Keep direct/dependency exploration available without misleading it as strict vulnerabilities-only. Show active filters and counts; provide reset.
- **Selection:** linked list, canvas and details; preserve selected package/version identity. Selected path emphasizes nodes AND edges; unrelated nodes AND edges dim or disappear. No animation on every high-risk edge. Closing selection must leave a valid view, not an empty path mode.
- **Groups:** pure view projections, never mutate backend graph/SBOM/finding data. Group expansion must have a clear collapse/back control. Count orphan findings rather than silently losing them.
- **Semantic zoom:** far shows simplified shapes/aggregate counts, medium names and severity, near versions/details. Keep layout geometry stable across these levels and the readable list available regardless of zoom.
- **Details:** reuse existing CVE display, FixTarget behavior and remediation controls. Hover remains an optional preview, not the only way to inspect or act. No new automatic remediation, approval or push behavior.
- **Navigation:** minimap bottom-right, high-contrast viewport outline, click/drag navigation, collapse toggle, zoom percentage and clearly labelled fit controls. Respect reduced motion.
- States: selected/focus-visible/hover/disabled, loading with text, layout error with retry, no matching vulnerabilities with reset, empty graph, pending/failed scan. Do not represent unknown severity or unavailable data as safe.

## Motion & Interaction

Use existing modest transition language: roughly 150–250ms for state changes, at most 300ms for user-initiated fit/focus. Disable animation with prefers-reduced-motion. Do not run an expensive layout on each search keystroke; use indexed adjacency/memoized projections, and cancel stale layout results. Debounce viewport fitting when filtering changes the displayed node identities, without recalculating their layout. View/group changes and explicit fit actions also fit their scope; inspecting details without changing that scope preserves the viewpoint.

## Do's and Don'ts

- Do show actionable risk information without requiring the user to locate a tiny node.
- Do retain the exact component ID/version and all existing finding/approval semantics.
- Do make filtering visibly remove non-matches; highlighting must affect both nodes and edges.
- Do use projection/model functions with deterministic tests rather than burying traversal/ranking in JSX.
- Do not add dependencies for a small list or new backend endpoints; reuse React Flow, ELK, Zustand, TanStack Query and existing primitives.
- Do not call dependency ancestry an actual exploit path.
- Do not leave a blank/unreadable graph while layout failed or filters match nothing.

## Accessibility Constraints & Accepted Debt

Keyboard-operable risk rows, filters, close/reset controls; visible focus; Escape can dismiss detail. Touch users have the same persistent-detail entry point as hover users. Canvas graph navigation alone is not an accessible alternative: the list/detail view carries the same information. No comprehensive WCAG certification is claimed. Existing unrelated UI accessibility debt is not expanded into this task.

## Route and State Matrix

Target: `/scans/nodejs-goof` with its actual large stored graph, plus synthetic empty/cycle/shared-dependency test fixtures. Verify at 1440×960, 768×1024 and 375×812: initial overview, risk selection/path, strict vulnerability filter, severity/KEV/search empty result and reset, group expand/collapse, zoomed minimap/fit, detail open/close. Also check pending/error layout states with tests and readable fallbacks. Never click real remediation creation/approval in browser QA.

## Performance Budget

Target diagnostic budget: list selection/filter response under 200ms on the live desktop test profile when layout is not required; project/graph layout is measured separately with progress feedback beyond one second. This is a local interaction target, not a field p75 claim. Baseline observation: direct view 197 nodes, vulnerable paths 182 of 996 total; default 1280px view fit about 6.6% zoom. Capture comparable post-change states rather than claiming an unmeasured speedup.

## Research Log

Inspected the live nodejs-goof graph, current CSS tokens, graph filtering/model/store/components and existing tests. Queried local OMH dev-tool palette/font/UX references; retained the current product palette and Pretendard stack instead of adopting a new look. No external design assets or logos copied. Original rendered graph screenshots are in the task's scratch evidence directory.

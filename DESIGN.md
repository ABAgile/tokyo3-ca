---
version: alpha
name: Tokyo3 CA Admin Portal
description: A restrained, security-oriented certificate-authority console with warm neutral surfaces and precise plum interaction cues.
colors:
  primary: "#A93A8C"
  primary-hover: "#92307A"
  primary-active: "#782563"
  on-primary: "#FFFFFF"
  surface: "#F5F5F3"
  surface-subtle: "#F0F1EE"
  surface-card: "#FBFAF8"
  secondary-action: "#F3F4F1"
  secondary-action-hover: "#F0F1EE"
  dark-secondary-action: "#303631"
  dark-secondary-action-hover: "#3A423B"
  dark-surface: "#151714"
  dark-surface-subtle: "#242823"
  dark-surface-card: "#1B1E1A"
  dark-on-surface: "#F0F2ED"
  dark-on-surface-muted: "#AEB4AA"
  dark-placeholder: "#777E75"
  dark-error-action: "#A52834"
  dark-error-action-hover: "#8E202B"
  surface-selected: "#FAEEF6"
  on-surface: "#20231F"
  on-surface-subtle: "#363A35"
  on-surface-muted: "#5F635D"
  outline: "#EEEEEB"
  outline-strong: "#D1D3CE"
  success: "#18794E"
  success-container: "#EDF8F2"
  warning: "#8F4F00"
  warning-container: "#FFF7E6"
  error: "#B4232C"
  error-action: "#B4232C"
  error-action-hover: "#941B24"
  error-container: "#FFF0F1"
  info: "#245EA8"
  info-container: "#EEF6FF"
typography:
  page-title:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 22px
    fontWeight: 650
    lineHeight: 1.25
    letterSpacing: -0.02em
  section-title:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 18px
    fontWeight: 650
    lineHeight: 1.25
  card-title:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 15px
    fontWeight: 650
    lineHeight: 1.3
  body:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 15px
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: -0.006em
  control:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 14px
    fontWeight: 600
    lineHeight: 1.2
  metadata:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 14px
    fontWeight: 400
    lineHeight: 1.5
  navigation:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 14px
    fontWeight: 500
    lineHeight: 1.25
  helper:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 12px
    fontWeight: 400
    lineHeight: 1.5
  badge-label:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 12px
    fontWeight: 650
    lineHeight: 1.2
  label-caps:
    fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: 11px
    fontWeight: 700
    lineHeight: 1.25
    letterSpacing: 0.08em
  code:
    fontFamily: "SFMono-Regular, Cascadia Code, Consolas, monospace"
    fontSize: 12px
    fontWeight: 400
    lineHeight: 1.5
rounded:
  sm: 4px
  md: 6px
  lg: 10px
  full: 999px
spacing:
  xs: 4px
  sm: 8px
  md: 12px
  base: 16px
  lg: 20px
  xl: 24px
  2xl: 32px
  3xl: 40px
  4xl: 48px
  sidebar-width: 240px
  content-max: 1280px
  form-max: 680px
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.control}"
    rounded: "{rounded.md}"
    padding: 8px 16px
    height: 38px
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "{colors.on-primary}"
  button-primary-active:
    backgroundColor: "{colors.primary-active}"
    textColor: "{colors.on-primary}"
  button-secondary:
    backgroundColor: "{colors.secondary-action}"
    textColor: "{colors.on-surface-subtle}"
    typography: "{typography.control}"
    rounded: "{rounded.md}"
    padding: 8px 16px
    height: 38px
  button-secondary-hover:
    backgroundColor: "{colors.secondary-action-hover}"
  button-danger:
    backgroundColor: "{colors.error-action}"
    textColor: "{colors.on-primary}"
    typography: "{typography.control}"
    rounded: "{rounded.md}"
    padding: 8px 16px
    height: 38px
  button-danger-hover:
    backgroundColor: "{colors.error-action-hover}"
    textColor: "{colors.on-primary}"
  input-field:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.on-surface}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: 8px 12px
    height: 38px
  card:
    backgroundColor: "{colors.surface-card}"
    textColor: "{colors.on-surface}"
    rounded: "{rounded.lg}"
    padding: "{spacing.lg}"
  navigation-active:
    backgroundColor: "{colors.surface-selected}"
    textColor: "{colors.primary-active}"
    typography: "{typography.navigation}"
    rounded: "{rounded.md}"
    padding: 8px 12px
  badge-neutral:
    backgroundColor: "{colors.surface-subtle}"
    textColor: "{colors.on-surface-subtle}"
    typography: "{typography.badge-label}"
    rounded: "{rounded.full}"
    padding: 2px 8px
  badge-success:
    backgroundColor: "{colors.success-container}"
    textColor: "{colors.success}"
    typography: "{typography.badge-label}"
    rounded: "{rounded.full}"
    padding: 2px 8px
  badge-warning:
    backgroundColor: "{colors.warning-container}"
    textColor: "{colors.warning}"
    typography: "{typography.badge-label}"
    rounded: "{rounded.full}"
    padding: 2px 8px
  badge-danger:
    backgroundColor: "{colors.error-container}"
    textColor: "{colors.error}"
    typography: "{typography.badge-label}"
    rounded: "{rounded.full}"
    padding: 2px 8px
  badge-info:
    backgroundColor: "{colors.info-container}"
    textColor: "{colors.info}"
    typography: "{typography.badge-label}"
    rounded: "{rounded.full}"
    padding: 2px 8px
  table-heading:
    textColor: "{colors.on-surface-muted}"
    typography: "{typography.label-caps}"
  helper-text:
    textColor: "{colors.on-surface-muted}"
    typography: "{typography.helper}"
  page-canvas:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
  page-canvas-dark:
    backgroundColor: "{colors.dark-surface}"
    textColor: "{colors.dark-on-surface}"
  card-dark:
    backgroundColor: "{colors.dark-surface-card}"
    textColor: "{colors.dark-on-surface}"
    rounded: "{rounded.lg}"
    padding: "{spacing.lg}"
  input-field-dark:
    backgroundColor: "{colors.dark-surface-subtle}"
    textColor: "{colors.dark-on-surface}"
    rounded: "{rounded.md}"
    height: 38px
  helper-text-dark:
    textColor: "{colors.dark-on-surface-muted}"
    typography: "{typography.helper}"
  placeholder-dark:
    textColor: "{colors.dark-placeholder}"
    typography: "{typography.body}"
  button-danger-dark:
    backgroundColor: "{colors.dark-error-action}"
    textColor: "{colors.on-primary}"
  button-danger-dark-hover:
    backgroundColor: "{colors.dark-error-action-hover}"
  button-secondary-dark:
    backgroundColor: "{colors.dark-secondary-action}"
    textColor: "{colors.dark-on-surface}"
  button-secondary-dark-hover:
    backgroundColor: "{colors.dark-secondary-action-hover}"
  divider:
    backgroundColor: "{colors.outline}"
    size: 1px
  control-outline:
    backgroundColor: "{colors.outline-strong}"
    size: 1px
---

# Tokyo3 CA Design System

## Overview

The certd admin portal implements the Tokyo3 design system: a well-kept
control-room logbook translated into a modern operations console. It has the
precision and restraint of infrastructure tooling, but the calm reading
rhythm of a carefully typeset technical handbook. The interface is for
operators making consequential certificate-authority decisions; it must
inspire confidence without looking theatrical or severe. certd's product
theme color is **plum** (`{colors.primary}`), chosen so this console reads
as its own product at a glance.

The visual character is quiet, warm, and exact:

- Warm off-white canvas rather than cold blue-gray or pure white.
- White instrument panels separated by fine rules.
- Plum interaction cues used with discipline.
- Compact information density with enough space to prevent mistakes.
- Explicit language and visible consequences for security actions.

This is an operations console for certificate authority state — roles, host
registrations, audit events, and revocations. No hero metrics, decorative
charts, glass effects, oversized headings, or ornamental gradients.

## Colors

The palette uses **warm paper neutrals with a single plum control signal**.
Dark mode preserves the same semantic hierarchy with charcoal surfaces and
softened plum controls rather than inverting every color mechanically.

- **Primary Plum (`{colors.primary}`):** Primary actions, focus, active
  navigation, and selected controls. It signals that something is
  actionable, not merely important. Do not reuse this hue for semantic
  states.
- **Warm Canvas (`{colors.surface}`):** The application background.
- **Soft Card (`{colors.surface-card}`):** Forms, resource panels, and cards.
- **Soft Surface (`{colors.surface-subtle}`):** Hover states, disabled fields,
  and quiet metadata.
- **Ink (`{colors.on-surface}`)** and **Muted Ink (`{colors.on-surface-muted}`):**
  Primary and secondary text.
- **Outlines (`{colors.outline}`, `{colors.outline-strong}`):** Hairline
  grouping and control boundaries.

Semantic colors communicate state rather than branding: success
(`{colors.success}`) for active, registered, or completed; warning
(`{colors.warning}`) for recoverable but consequential states; error
(`{colors.error}`) for failure, blocked access, and irreversible actions;
and information (`{colors.info}`) for policies and capabilities. Never
communicate status through color alone; pair color with clear text.

Links use a dedicated link token pair, separate from control fills, so text
links stay legible in both modes: the primary plum in light mode, and
lighter plum text tones in dark mode (`#E18FC8` links, `#EFB9DE` link
hover). Dark-mode plum control fills use a deeper plum (`#B0459A` action,
`#BD54A7` hover, `#D06FBB` active) so white labels retain clear contrast,
with `#E7A3D2` focus, `#EFB9DE` active navigation, and a muted plum
selection surface (`#43203B`).

## Typography

The portal uses the native system sans-serif stack: text should look at home
on the operator's platform, render immediately, and remain highly legible
without a font-download dependency. Use sentence case for headings,
navigation, labels, and buttons; avoid title case, all-caps prose, and
oversized display typography. Page titles use the compact
`{typography.page-title}`; caps labels (`{typography.label-caps}`) appear
only on table headings and sidebar section labels; monospace
(`{typography.code}`) is reserved for technical values — serials, key IDs,
SPIFFE URIs, group claims, host patterns. Technical identifiers may truncate
visually only when the full value remains available through selection, title
text, or a copy action.

## Layout

The desktop application uses a fixed `{spacing.sidebar-width}` sidebar and a
fluid content region capped at `{spacing.content-max}`. Forms remain readable
at `{spacing.form-max}`. The layout follows a 4px base rhythm expressed by
the spacing scale.

The sidebar groups certd destinations into **Access** (Roles, Hosts) and
**Operations** (Revocations, then Audit log last), with an ungrouped
Overview link first.
Pages whose data source is not wired render as non-interactive planned
entries — visual completeness must not imply unsupported functionality.

At widths below 1024px the sidebar falls back to normal document flow above
the content (no JavaScript dependency). At widths below 640px forms become
single-column and cards use reduced padding. Dense tables scroll only inside
their table region; the document itself must never scroll horizontally.

Dark mode is the default. An explicit user choice is persisted locally and
overrides the default; the toggle lives in the sidebar footer next to the
signed-in identity. The POST-based Sign out action sits on the row below and
appears only when native OIDC login is active (HTTP Basic auth has no logout
semantics). The chrome carries no version line and no page-level footer.

## Elevation, Shapes, and Components

- Flat, tonal depth: cards sit one step above the canvas with a 1px outline
  and at most a `0 1px 2px` shadow at ~6% opacity; overlays may use
  `0 12px 32px` at ~16%.
- Controls use `{rounded.md}`, cards `{rounded.lg}`, badges `{rounded.full}`.
- Buttons: one `{components.button-primary}` per page or bounded section;
  `{components.button-secondary}` for neutral actions;
  `{components.button-danger}` for irreversible operations such as revoking
  a certificate.
- Inputs follow `{components.input-field}` with programmatic labels, helper
  text beneath the field, and recoverable validation errors.
- Resource tables use `{components.table-heading}` headings, monospace
  technical identifiers, and complete empty states. Timestamps never wrap.
  Audit event detail blobs render inline as monospace panels — always
  visible, with no disclosure toggle.
- Badges use the semantic component tokens; status text accompanies any dot
  or color.

Revocation is a consequential, effectively irreversible security action: the
revoke form states its consequence in plain language and uses danger action
styling, never a bare default button.

## Do's and Don'ts

- **Do** make identity, status, risk, and the next safe action obvious
  before adding visual decoration.
- **Do** keep one primary action per page or bounded task.
- **Do** use warm neutral surfaces, fine outlines, and compact typography to
  create hierarchy.
- **Do** pair every semantic color with meaningful text.
- **Do** preserve keyboard access, visible focus, native semantics, and WCAG
  AA contrast.
- **Do** keep technical identifiers selectable, copyable, and visually
  distinct.
- **Do** state the scope and consequence of every security-sensitive action.
- **Don't** add hero cards, vanity metrics, decorative charts, or marketing
  copy to operational pages.
- **Don't** use gradients, glassmorphism, glows, large ambient shadows, or
  animated elevation.
- **Don't** recolor success, warning, error, or information states to match
  the plum theme, or reuse plum for semantic states.
- **Don't** add navigation entries or controls for pages whose backing store
  is not configured; render them as clearly non-interactive planned items.
- **Don't** introduce a frontend framework or build pipeline solely to
  reproduce this design.
- **Don't** change routes, methods, input names, CSRF wiring, auth gating, or
  confirmation behavior during visual work.

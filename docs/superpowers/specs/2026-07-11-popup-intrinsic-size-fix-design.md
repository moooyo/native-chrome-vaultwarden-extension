# Popup Intrinsic Size Fix

## Problem

The extension popup collapses to a few pixels when Chrome opens it. The popup document uses
`width: fit-content`, while the Lit app and popup frame cap themselves with `100vw` and `100vh`.
During Chrome's initial popup measurement, that viewport is not yet the intended popup size, so
the content shrinks to the provisional viewport and Chrome adopts the resulting tiny dimensions.

The fixture-based Playwright tests do not expose this behavior because they assign a 350 x 450 or
600 x 450 viewport before rendering the popup frame.

## Design

The popup frame will provide intrinsic geometry based on its layout mode:

- `auth` and `single` modes are 350 x 450 CSS pixels.
- `double` mode is 600 x 450 CSS pixels.
- Width and height are not derived from `100vw` or `100vh` during extension popup startup.
- Internal panes remain constrained with `min-width: 0`, `min-height: 0`, and local scrolling.

The popup application will select `auth` for authentication routes and `double` for unlocked
routes. It will not use an initial viewport media query to choose `single`, because Chrome popup
dimensions are content-driven and that query creates a circular dependency. The `single` mode
remains available as an explicit component mode for fixtures and embedded or constrained uses.

The popup document will size itself from the Lit root. It will retain zero margins and hidden
document overflow, but it will not impose a competing fixed body size.

## Testing

A browser layout regression test will render the actual popup document sizing rules without
pre-sizing the viewport to the intended popup dimensions. It will assert that the document and
frame expose the correct intrinsic width and height for authentication and unlocked layouts.

Existing component, layout, visual, accessibility, keyboard, typecheck, lint, and production-build
checks will continue to run. The built extension will also be inspected to ensure the corrected
popup CSS and JavaScript are included.

## Scope

This change only fixes popup geometry and its regression coverage. It does not change vault state,
navigation, authentication, permissions, visual styling, or business behavior.

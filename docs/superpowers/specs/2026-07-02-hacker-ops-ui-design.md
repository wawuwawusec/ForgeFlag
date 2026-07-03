# ForgeFlag Hacker Ops UI Design

ForgeFlag should feel like a serious CTF operations console, not a generic SaaS dashboard. The visual language is dark, dense, evidence-first, and tool-oriented: a player should immediately understand that this is for local or authorized challenge research, replay evidence, and solver orchestration.

## Direction

- Theme name: `forgeflag-hacker-ops`.
- Core metaphor: mission console plus evidence rail.
- Mood: professional hacker workbench, restrained scan-grid texture, terminal-like evidence surfaces, and high-contrast operational controls.
- Avoid: decorative blobs, marketing hero layouts, playful neon overload, and one-note green-only styling.

## UI Contract

- The header identifies the CTF scope and highlights `Mission console`, `Evidence rail`, and `CTF scoped`.
- The background uses scan-grid and subtle line textures instead of large gradient ornaments.
- Cards, tabs, command blocks, flags, and raw JSON use dark surfaces with green/cyan/violet/amber signals.
- Runtime state stays visible in the top mission strip and is updated by the existing status function.
- Desktop layout uses a three-zone console: `Challenge queue` on the left, `Run control` plus tabbed result canvas in the center, and `Evidence rail` on the right.
- The desktop shell is viewport-height bounded. The queue, result canvas, and evidence rail scroll independently so normal use does not become one long page.
- Low-frequency challenge intake controls live in the evidence rail; the left column stays focused on selection and filtering.
- Existing Web UI behavior, tab loading, LLM controls, and browser-player flows remain unchanged.

## Verification

- `tests.test_webapp.WebAppApiTest.test_index_uses_hacker_ops_workbench_theme` locks the theme contract.
- `tests.test_webapp.WebAppApiTest.test_index_uses_three_zone_commercial_console_layout` locks the three-zone layout and independent scroll contract.
- Full Web tests and browser-player benchmark should pass before this UI is treated as deliverable.

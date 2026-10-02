# Detailed design assets

The canonical editable document is [DETAILED_DESIGN.md](../DETAILED_DESIGN.md).
Separate Markdown documents cover [community SONiC](../COMMUNITY_SONIC_DESIGN.md)
and the [intelligence service](../INTELLIGENCE_SERVICE_DESIGN.md).
Its [HTML](../DETAILED_DESIGN.html) embeds all diagrams as local inline vectors.
Its [PDF](../DETAILED_DESIGN.pdf) has a linked contents page, section bookmarks and
larger diagram pages for legibility.

Each diagram in `diagrams/` has editable Mermaid source plus SVG and PNG exports:

1. System overlay and ownership.
2. Community SONiC module interactions.
3. Inventory synchronization and acknowledgement.
4. Intelligence service internals.
5. Analysis and cache flow.
6. Optional AI and evidence review.
7. Maintenance approval and staging.
8. Build identity and external signature verification.
9. SQL tables and logical record families.
10. Signed-in external-agent interaction.
11. Apply-time health checks and rollback.

The rendering helpers use a documentation environment, not the running service.
`render_diagrams.py` takes `--mermaid-js /path/to/mermaid.min.js`; the inspected
renderer is Mermaid11.6.0, with checksum in `diagram-validation.json`.
It uses Playwright Chromium and performs no network requests during rendering.
`render_design.py` uses Markdown3.8.2 and the existing user-guide documentation
style. Rebuild the HTML after editing the Markdown or diagrams, then print with
Chromium to regenerate the PDF with `python docs/render_exports.py`. This preserves named page sizes and verifies page bounds and internal links.

`checkpoint-example.json` is illustrative, not a live enrollment request. Its
component hash and request schema have been checked against the current service.
`design-validation.json` records source/artifact checks and documentation-only
scope. No switch deployment or runtime validation is implied by these exports.

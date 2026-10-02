# SONiC Smart Patch documentation

The engineering design is available as three Markdown documents. Start with the
overall design for shared contracts and end-to-end interactions, then use the
repository-specific documents for implementation review.

| Document | Scope |
| --- | --- |
| [Overall design](DETAILED_DESIGN.md) | System approach and tradeoffs; switch–service interactions; common identity, evidence and authorization contracts; complete validation boundaries |
| [Community SONiC changes](COMMUNITY_SONIC_DESIGN.md) | Changes in `sonic-buildimage`: native configuration/CLI, lightweight collection, package deltas, durable synchronization, resource controls, build identity and guarded local actions |
| [Intelligence service changes](INTELLIGENCE_SERVICE_DESIGN.md) | Central scanning, evidence/AI, durable jobs and storage, cache identities, source/build integration, maintenance coordination, authentication, UI and observability |

The component documents embed editable Mermaid diagrams directly in Markdown and
link their rendered SVG alternatives. Shared diagram assets are in
[design/diagrams](design/diagrams). Changes describe the implemented working tree;
test and deployment limitations remain explicit. The proposed custom-patch,
rebuild and separate staging-VM qualification pipeline is not presented as an
implemented capability.

For operation and setup, use the [illustrated user guide](USER_GUIDE.md) and
[deployment instructions](DEPLOYMENT.md). The overall design is also available as
[HTML](DETAILED_DESIGN.html) and [PDF](DETAILED_DESIGN.pdf).

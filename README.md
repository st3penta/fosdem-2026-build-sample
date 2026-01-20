# FOSDEM 2026 Build Sample

Sample repository demonstrating policy-based validation using Conforma.
Artifacts pushed to: https://quay.io/repository/spentass/fosdem-2026

## Workflows

- **Release** (`release.yml`) - Builds, attests, validates, and releases to `:latest` on main branch pushes
- **PR Build** (`pr-build.yml`) - Validates pull requests using a separate policy configuration

Only images passing policy validation are promoted to production.

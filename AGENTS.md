# Agent instructions

This repository owns Legal Hold cases, exact held scopes, release evidence,
and Retention Guard decisions. It does not own data-retention execution,
Organization membership, RBAC, Auth identities, or participant data.

Capability source is `capability.json` plus package-local JSON Schemas.
Generated Rust is locked output and must not be hand-edited. Use the workspace
Cargo wrapper when available and read `docs/release-process.md` before release
work.

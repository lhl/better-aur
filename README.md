# Better AUR

A sketch for a safer, more transparent, and more democratic community package recipe system inspired by the Arch User Repository, but designed around explicit trust, review, sandboxing, and maintainership continuity.

This document is intentionally a working draft. The goal is to iterate on the model, identify tradeoffs, and eventually turn the design into concrete specs and prototypes.

## Table of Contents

- [Problem Statement](#problem-statement)
- [Core Principle](#core-principle)
- [Current System Snapshot](#current-system-snapshot)
- [Prior Art and Features to Adopt](#prior-art-and-features-to-adopt)
- [Goals](#goals)
- [Threat Model](#threat-model)
- [Design Overview](#design-overview)
- [Package Model](#package-model)
- [Namespace Stewardship and Update Proposals](#namespace-stewardship-and-update-proposals)
- [Maintainership Model](#maintainership-model)
- [Identity and Account Security](#identity-and-account-security)
- [Reputation Model](#reputation-model)
- [Web of Trust](#web-of-trust)
- [Recipe Format](#recipe-format)
- [Source, Namespace, and Dependency Provenance](#source-namespace-and-dependency-provenance)
- [Static and Dynamic Analysis](#static-analysis)
- [Pre-Distribution Gate](#pre-distribution-gate)
- [Cloaking and TOCTOU Prevention](#cloaking-and-toctou-prevention)
- [Global Indicators and Campaign Detection](#global-indicators-denylists-and-campaign-detection)
- [Update Delta Taxonomy](#update-delta-taxonomy)
- [Risk Classification](#risk-classification)
- [Review Workflow](#review-workflow)
- [Sandboxed Builds](#sandboxed-builds)
- [Build Attestations and Reproducibility](#build-attestations-and-reproducibility)
- [Install Hooks](#install-hooks)
- [Client Policy](#client-policy)
- [User Interface Requirements](#user-interface-requirements)
- [Governance and Emergency Response](#governance)
- [Minimum Viable Version](#minimum-viable-version)
- [Open Questions](#open-questions)

## Problem Statement

Community package repositories are useful because they make it easy for users to share build recipes for software that is not available in official distribution repositories.

The weakness is that many systems treat package names and package history as if they imply trust. If an abandoned or orphaned package can be adopted by any account and updated without review, an attacker can inherit user trust attached to that package name.

A safer system should preserve the ease of community contribution while making trust explicit.

## Core Principle

> Contribution should be open, but trust should be earned, visible, scoped, and revocable.
>
> Package names are community namespaces, not permanent private property. Maintainers are stewards, not owners.

The system should answer these questions for every package update:

- Who proposed this recipe change?
- Who reviewed or approved it?
- What changed?
- What capabilities does the recipe require?
- Did maintainership change recently?
- Was the package dormant before this update?
- Has the recipe been built in a sandbox?
- Has the resulting artifact been independently reproduced or attested?
- What risk class does this update fall into?

## Current System Snapshot

The current design is an AUR-like community recipe system with four major upgrades over traditional single-owner package repositories:

1. **Open contribution without single-owner lock-in** — anyone can propose updates, while package namespaces are stewarded by maintainers, reviewers, and orphan stewards rather than permanently owned by the first submitter.
2. **Delta-aware security** — the system judges updates by what changed: a strict version bump is very different from a new install hook, new source origin, new dynamic dependency installer, or new root-running behavior.
3. **Layered trust and reputation** — users, packages, reviewers, builders, and trust edges all have scoped reputation. Reputation helps route low-risk work, but confirmed malware instantly flips an account into bad-actor quarantine.
4. **Automated analysis plus human confirmation** — static analysis, sandboxed builds, provenance checks, install-hook simulation, indicator feeds, and campaign detection catch common attacks before publication; high-risk changes still require independent human review.

In short, the system is designed to be more secure and more responsive at the same time:

- Routine, low-risk maintenance can move faster.
- Stale packages can receive update proposals without waiting forever on an inactive first maintainer.
- High-risk changes become much harder to hide.
- Users and helpers get actionable warnings instead of raw unstructured diffs.
- Known attacks become global protections through signed indicators and denylists.

## Prior Art and Features to Adopt

Other package ecosystems already implement pieces of this design. The goal is not to copy any one system, but to combine their strongest ideas and add delta-aware review, sandbox analysis, reputation, and reverse-reputation response.

Useful patterns to adopt:

- **PyPI** — mandatory 2FA for all users, Trusted Publishing with OIDC, and Sigstore/in-toto digital attestations for package releases.
- **npm** — mandatory 2FA or granular tokens for publishing/settings changes, OIDC Trusted Publishing, and public provenance statements for packages built in CI.
- **RubyGems** — MFA requirements for high-impact gems and OIDC Trusted Publishing to avoid long-lived API tokens in CI.
- **crates.io** — package-scoped and action-scoped API tokens, owner teams, and OIDC Trusted Publishing.
- **Go modules** — checksum database / transparency-log model to make source version changes tamper-evident across the ecosystem.
- **Maven Central** — namespace verification through DNS/group ownership, required checksums, and signed artifacts.
- **Debian** — maintainer identity, signed uploads, archive-level trust, source-only uploads, reproducible-builds work, and a long-running social web of trust for project membership.
- **Fedora** — packager sponsorship, formal package review, Koji builds, Bodhi update gating, provenpackagers who can fix packages they do not own, and policy-backed maintainer roles.
- **openSUSE / OBS** — submit requests, devel projects, Factory review, staging projects, automated rebuilds, and an integrated public build service.
- **Gentoo** — multiple maintainers in package metadata, proxy maintainers, Manifest-based distfile integrity, repository verification, and source-first packaging.
- **Nixpkgs / Guix** — declarative recipes, sandboxed/pure builds, content-addressed or derivation-based stores, reproducibility goals, large-scale review through patches/PRs, and binary cache/substitute signatures.
- **Alpine / Void** — centralized recipe trees, pull-request workflows, build infrastructure, checksums, package signing, and relatively simple auditable package recipe formats.
- **Fedora COPR / third-party build services** — user-submitted packages built on central infrastructure, useful as a model for sandboxed community builds but not sufficient as a trust model by itself.
- **Homebrew** — audits, CI for formula changes, bottle provenance work, and explicit trust boundaries for third-party taps.
- **Flathub / Flatpak** — app verification, review process, visible permissions, and a sandbox-first runtime model.
- **Sigstore / Rekor / SLSA / in-toto** — keyless signing, transparency logs, and build provenance attestations tied to identity and CI context.
- **TUF / Uptane-style update security** — threshold signatures, delegated roles, metadata expiry, rollback protection, freeze-attack resistance, and explicit trusted roots.
- **OpenSSF package-repository principles** — MFA, incident response, malware reporting, security contacts, vulnerability handling, and supply-chain maturity levels.

Things these systems often do not solve completely:

- They improve publisher identity, but usually do not prove the package is safe.
- They often lack delta-aware risk classification.
- They often do not treat maintainer changes as package-trust events.
- They rarely combine package reputation, user reputation, automated sandboxing, and global campaign detection.
- They usually do not provide democratic stale-package update paths without takeover risk.

This project should adopt the proven mechanisms while adding a stronger review and reputation layer around recipe behavior.

### Distro Lessons

The state of the art is not one system. It is a collection of lessons spread across distributions and registries:

- AUR is optimized for low-friction contribution, but it lacks most modern supply-chain controls.
- Debian and Fedora show that maintainership can be gated through identity, sponsorship, signed uploads, and social review.
- Fedora's provenpackager concept shows that trusted maintainers can fix packages they do not own, which is useful for responsiveness.
- openSUSE OBS shows that submit requests, staging, public builders, and rebuild testing can scale beyond one maintainer per package.
- Nix and Guix show that declarative recipes, sandboxed builds, derivation identity, binary-cache signatures, and reproducibility are powerful primitives.
- Go's checksum database shows how transparency logs can make version/source tampering visible across the whole ecosystem.
- Flathub shows that user-facing permissions and app verification can make trust more understandable.

The proposed system should combine these ideas rather than choosing between them: AUR-like openness, Fedora/openSUSE-style review workflows, Nix/Guix-style sandboxed builds, Go/Sigstore-style transparency, PyPI/npm-style OIDC publishing, and Flathub-style user-visible risk metadata.

### Integrated Best-of-Breed Architecture

A hardened community package system should be built as a set of cooperating layers:

1. **Identity layer** — MFA/WebAuthn, OIDC Trusted Publishing, scoped short-lived tokens, signed commits, and account recovery controls.
2. **Namespace layer** — package names are stewarded community namespaces with maintainer sets, contributor proposals, stale-maintainer escalation, and orphan-adoption review.
3. **Recipe layer** — declarative package metadata, explicit capabilities, pinned sources, dependency manifests, and semantic diffs.
4. **Analysis layer** — static analysis, sandboxed dynamic analysis, dependency graph analysis, install-hook simulation, artifact diffing, and campaign correlation.
5. **Review layer** — risk-based confirmations, independent reviewer diversity, provenance checks, and provenpackager-style non-owner fixes.
6. **Pre-distribution gate layer** — signed allow/deny verdicts that bind recipe hash, source hashes, analysis results, approvals, build outputs, and repository metadata before anything becomes installable.
7. **Build layer** — disposable builders, reproducibility checks, N-of-M attestations, binary cache signatures, and local sandbox fallback.
8. **Metadata layer** — TUF-style signed metadata, threshold signatures, expiry, rollback protection, and append-only transparency logs.
9. **Client policy layer** — helper warnings, deny rules, enterprise policies, local trust roots, and visible package risk/reputation state.
10. **Response layer** — global malicious-indicator feeds, bad-actor quarantine, package freezes, advisories, rollback guidance, and user notification.

This architecture explicitly avoids one brittle trust decision. A package update is accepted only when the right combination of identity, provenance, analysis, review, build evidence, and policy checks agree for that update's risk level.

## Goals

- Allow many people to submit and maintain package recipes.
- Make maintainership changes visible and reviewable.
- Prevent silent trust inheritance after orphan adoption.
- Track reputation for both users and packages, separately from popularity.
- Classify updates by what changed, not just by the final recipe state.
- Require higher scrutiny for high-risk recipe changes.
- Provide automated static analysis for package recipes and install hooks.
- Support sandboxed builds with limited filesystem and network access.
- Give users and helpers clear warnings before risky installs.
- Encourage reproducible builds and public build attestations.
- Preserve the speed and openness that make community repositories useful.

## Non-Goals

- Guarantee that all community packages are safe.
- Replace official distribution repositories.
- Require every contributor to have real-world identity verification.
- Eliminate all arbitrary code from build recipes on day one.
- Turn every package update into a heavyweight bureaucratic process.

## Threat Model

The system should assume attackers may:

- Create new accounts.
- Create many accounts to farm reputation or create fake consensus.
- Adopt or target orphaned packages.
- Compromise maintainer accounts.
- Submit plausible version bumps with malicious build steps.
- Build reputation through harmless low-risk updates, then later push a high-risk payload.
- Launder trust through an old package name, old package popularity, or an old maintainer lineage.
- Add malicious install hooks.
- Change upstream source URLs.
- Abuse mutable tags, generated archives, compromised upstream releases, or retargeted source artifacts.
- Introduce dynamic dependency installers such as `npm`, `pip`, `cargo`, or `bun` invocations.
- Hide payloads in generated files, binary blobs, minified code, or dependency lockfiles.
- Exploit user trust in old package names.

The system should especially defend against:

- Silent maintainer takeover.
- Dormant package revival attacks.
- Malicious `.install` or post-install scripts.
- Build scripts that read user secrets from `$HOME`.
- Unexpected network access during build.
- Bulk automated adoption or update campaigns.

## Design Overview

A safer AUR-like system separates five concepts that are often conflated:

1. **Recipe submission** — anyone can propose a package recipe or update.
2. **Maintainership** — trusted users or teams steward package namespaces.
3. **Review** — humans and automated tools evaluate risky changes.
4. **Build execution** — recipes are built in constrained environments.
5. **Install privilege** — root-level hooks are treated as exceptional and dangerous.

## Package Model

Each package should track:

- Package name.
- Upstream project URL.
- Recipe repository.
- Current maintainer set.
- Previous maintainers.
- Co-maintainers.
- Reviewers.
- Maintainer-change history.
- Adoption history.
- Risk history.
- Package reputation status.
- Reputation-affecting events.
- Build attestations.
- User-facing warnings.

Package identity should not be based only on the package name. The system should distinguish between:

- The original package lineage.
- A new maintainer lineage.
- A forked recipe.
- An abandoned upstream continuation.
- A replacement package.

If a package changes hands after being orphaned, clients should show that clearly.

### Package Reputation

Packages should have reputation separate from votes, downloads, comments, and popularity. Popularity means many users installed it; it does not mean the recipe is safe.

Package reputation should summarize the security posture of a package lineage:

- Maintainer continuity.
- Age of the current maintainer lineage.
- Frequency of high-risk changes.
- Review coverage.
- Static analysis history.
- Reproducible build history.
- Successful sandboxed build history.
- Incident and rollback history.
- Whether the package uses install hooks.
- Whether the package requires network access during build.
- Whether the package uses dynamic dependency installers.
- Whether source URLs and upstream identity have remained stable.

Package reputation should be delta-sensitive:

- A routine version bump may preserve package reputation.
- A new maintainer should put the package into probation.
- A new source origin should reduce confidence.
- A new install hook should make the package high risk immediately.
- A dormant package that suddenly becomes active should lose inherited trust until reviewed.
- A package's reputation should attach to a lineage, not merely to a package name.

The UI should avoid a single misleading score when possible. A package can be popular but risky, obscure but clean, or historically safe but currently probationary.

## Namespace Stewardship and Update Proposals

The first user to package a piece of software should not permanently own the package namespace.

A better model:

- The first submitter becomes the initial steward, not the permanent owner.
- The package namespace is a community record that maps a recipe lineage to an upstream project.
- Any authenticated user can propose updates to any package.
- Proposed updates are reviewable changes, not immediate live package updates.
- Maintainers merge routine proposals.
- Reviewers or orphan stewards can merge proposals when maintainers are inactive.
- Repeated accepted proposals can earn package-specific contributor reputation.
- Maintainer privileges can decay after inactivity.
- Popular or high-impact packages should require multiple active stewards.

This creates a path for keeping packages fresh without requiring the original submitter to delegate manually or remain active forever.

A package page should therefore show at least three groups:

- **Maintainers** — users with merge authority for that package.
- **Active contributors** — users with recent accepted proposals for that package.
- **Reviewers** — users who reviewed risk-relevant changes.

## Maintainership Model

Instead of a single owner, packages should support a maintainer set.

Recommended rules:

- Packages may have multiple maintainers.
- The first submitter is the initial steward, not the permanent owner.
- Anyone may submit an update proposal.
- Popular or high-impact packages should require more than one maintainer.
- Maintainers can merge low-risk updates.
- Risky updates require additional review.
- Maintainer additions and removals are logged publicly.
- New maintainers start with limited privileges.
- Inactive maintainers lose exclusive control over stalled packages.
- Orphaned packages enter a stewardship queue instead of being instantly claimable.

### Orphan Handling

Orphaned packages are high risk because they carry historical user trust without active stewardship.

Proposed orphan workflow:

1. Package is marked orphaned.
2. Package enters a public adoption queue.
3. Interested maintainers submit adoption proposals.
4. Automated checks classify the package's risk and popularity.
5. A cooldown period gives users and reviewers time to notice.
6. Low-impact packages may be adopted after delay.
7. High-impact packages require reviewer approval or maintainer quorum.
8. Clients warn users for a configurable period after adoption.

Example warning:

```text
WARNING: package was adopted by a new maintainer 3 days ago.
Previous maintainer: alice
New maintainer: bob
Dormant period: 14 months
Risk level: high
Reason: new install hook added after adoption
```

### Stale Maintainer Escalation

A maintained package can still become effectively abandoned if the maintainer stops responding.

Proposed stale-update workflow:

1. Contributor submits an update proposal.
2. Maintainers are notified.
3. Automated checks classify the update.
4. If maintainers respond, normal review proceeds.
5. If maintainers do not respond within a defined window, the proposal can be escalated.
6. Low-risk routine version bumps may be merged by an authorized reviewer after timeout.
7. Medium-risk changes require reviewer approval.
8. High-risk and critical changes still require elevated review, even if the maintainer is absent.
9. Repeated non-response lowers maintainer activity status and can trigger co-maintainer recruitment or stewardship transfer.

This avoids the failure mode where one inactive account blocks all legitimate maintenance while still preventing arbitrary takeover.

### Non-Owner Fixes and Proven Maintainers

The system should borrow from Fedora's provenpackager idea and openSUSE's submit-request model: trusted contributors should be able to propose or land narrowly scoped fixes for packages they do not own, without requiring full takeover.

Rules:

- Non-owner fixes should start as proposals with full analysis and visible diffs.
- Low-risk routine version bumps can be merged by proven maintainers after maintainer timeout.
- Security fixes can be escalated through security responders.
- High-risk behavior changes still require normal high-risk review.
- Landing a non-owner fix does not automatically grant long-term maintainer control.
- Repeated high-quality non-owner fixes can nominate a contributor for co-maintainer status.

This creates responsiveness without converting every maintenance problem into an ownership transfer.

## Identity and Account Security

Accounts should be more than email plus SSH key. SSH keys may be acceptable for Git transport, but they should not be the whole authorization model.

Recommended controls:

- Mandatory MFA for all accounts that can submit, review, adopt, publish, or manage packages.
- WebAuthn/passkeys or hardware security keys required for maintainers, reviewers, orphan stewards, and administrators.
- Step-up authentication for high-risk actions such as adoption, maintainer changes, critical updates, install-hook approval, token creation, and account recovery.
- Signed commits or signed recipe releases.
- Public maintainer keys.
- Account age and activity visible in package metadata.
- Rate limits for new accounts.
- Bulk adoption limits.
- Bulk update limits.
- Session and token hygiene.
- Emergency account lock and package freeze workflows.

### Trusted Publishing and OIDC

The preferred publishing path should be OIDC-based Trusted Publishing rather than long-lived SSH keys or API tokens.

Model:

1. A maintainer links a package to a trusted source repository, workflow, branch/tag rule, and CI identity provider.
2. The CI provider issues a short-lived OIDC identity token for a specific workflow run.
3. The registry exchanges that identity token for a short-lived, package-scoped, action-scoped publish token.
4. The publish token can submit only the specific package revision or attestation it was minted for.
5. The registry records the OIDC claims in the package's provenance metadata.

OIDC claims should include:

- Identity provider.
- Repository.
- Organization/user.
- Workflow name.
- Commit SHA.
- Ref or tag.
- Build environment.
- Triggering actor.
- Timestamp.

Trusted Publishing reduces stolen-token risk because there is no long-lived publish secret to steal from CI.

It does not prove the code is safe. It only says where the upload came from and under which identity. Therefore OIDC must be combined with static analysis, sandboxing, risk classification, reputation, review, and incident response.

### Token Policy

Long-lived tokens should be discouraged and limited to exceptional cases.

If tokens exist, they should be:

- Package-scoped.
- Action-scoped.
- Time-limited.
- Revocable.
- IP- or environment-restricted where possible.
- Unable to change ownership or trust policy.
- Unable to bypass high-risk review.

No token should grant broad account-level authority by default.

### Signed Metadata, Transparency, and Rollback Protection

The repository should have signed metadata and an append-only transparency log, not only signed Git commits.

Recommended metadata protections:

- TUF-style root metadata with offline root keys.
- Threshold signatures for repository-wide trust roots.
- Delegated signing roles for package namespaces, ecosystems, build attestations, and security advisories.
- Metadata expiry to prevent freeze attacks.
- Version counters and snapshot metadata to prevent rollback attacks.
- Signed malicious-indicator feeds and revocation records.
- Public append-only transparency log for package events.

The transparency log should record:

- Package creation.
- Maintainer additions and removals.
- Adoption proposals and approvals.
- Recipe revisions.
- Risk classifications.
- Review approvals.
- Build attestations.
- Published artifacts.
- Indicator matches.
- Quarantines, freezes, and reversions.

Clients should be able to verify not just "is this artifact signed?" but also "is this the current signed view of the package according to the repository metadata, and is there evidence of suspicious history?"

Optional stronger controls for high-impact packages:

- Organization-backed accounts.
- Real-world identity verification.
- Hardware-backed signing keys.
- Multiple approvers for privileged changes.

## Reputation Model

Reputation should exist for users, packages, and the relationship between a user and a package lineage.

A good reputation system should not ask only "is this account trusted?" It should ask:

- Trusted to do what?
- In which ecosystem?
- For which package lineage?
- At what risk level?
- With which reviewers or co-maintainers?
- How recently was this trust earned?

### User Reputation

User reputation should be earned through useful, reviewable actions.

Potential positive inputs:

- Account age.
- Accepted recipe updates.
- Known-good submissions that age without incident.
- Successful reviews.
- Maintained package history.
- Reproducible build participation.
- Responsiveness to bug reports.
- Vouches from trusted maintainers.
- Long-term clean stewardship of packages.

Potential negative inputs:

- Reverted changes.
- Security incidents.
- Abandoned packages.
- Ignored reports.
- Suspicious bulk actions.
- Reviews later found to have approved malicious behavior.
- Account compromise.

Reputation should be scoped. A user may be trusted for one ecosystem or package family but not globally trusted for all high-risk changes.

Possible trust scopes:

- General contributor.
- Package maintainer.
- Ecosystem maintainer, such as Python, Rust, Node, Go, fonts, kernels.
- Security reviewer.
- Orphan steward.
- Build attestor.
- Namespace administrator.

### Reputation Grants Capabilities

Reputation should grant narrow capabilities, not vague prestige.

Examples:

- Submit recipe proposals.
- Merge low-risk updates for specific packages.
- Approve medium-risk changes in a specific ecosystem.
- Approve orphan adoption.
- Approve install-hook changes.
- Approve package-maintainer changes.
- Publish build attestations.

High-risk capabilities should require stronger account security, older accounts, reviewer diversity, and recent good behavior.

### Known-Good Submission Credit

Reputation can build automatically from known-good submissions, but the credit should be delayed, scoped, and risk-weighted.

Suggested rules:

- A low-risk version bump earns only small package-specific credit.
- A medium-risk update earns credit only after review and clean aging.
- A high-risk update earns credit only after independent review, successful builds, and time without incident.
- Reputation from accepted proposals should be tied to the package and ecosystem involved.
- Reputation should be clawed back if a later incident traces to the submission or review.
- Repeated routine maintenance can help a contributor become a co-maintainer candidate.

The goal is to reward useful maintenance without allowing attackers to farm many trivial updates into broad trust.

### Credential Theft Limits

Reputation is only one signal. A trusted account can be compromised.

Therefore high-risk actions should still require current assurance:

- Recent MFA or hardware-key confirmation.
- Signed commits or signed releases.
- Anomaly detection for unusual packages, IPs, velocity, or ecosystems.
- Cooldowns after credential changes.
- Co-review for high-risk deltas even from reputable maintainers.
- Automatic package freeze after suspected account compromise.

A reputation system should reduce noise and route review effort; it should not make trusted accounts omnipotent.

### Instant Trust Inversion

A high-reputation account that submits a confirmed malicious update should flip from trusted to bad-actor emergency state immediately.

There is no meaningful "a little bad" state for confirmed malware. If confirmed analysis shows that an account submitted a malware attack vector through a package, the account must be treated as a bad actor for operational purposes immediately.

The later investigation can distinguish between:

- Credential compromise.
- Session/token theft.
- Maintainer machine compromise.
- Malicious insider or mole.
- Coerced maintainer.
- False attribution or infrastructure error.

But the first response should be the same: stop trusting the account now.

Immediate actions:

- Mark the account as bad-actor/quarantined.
- Disable publishing, adoption, review, vouching, and build-attestation privileges.
- Freeze packages maintained by the account, or at least freeze high-risk pending changes.
- Revoke or suspend active sessions and API tokens.
- Require hardware-key reauthentication or manual recovery.
- Mark recent submissions as suspect until re-reviewed.
- Temporarily invalidate or suspend recent trust edges created by the account.
- Notify co-maintainers, reviewers, and affected users.
- Preserve forensic logs for investigation.

High reputation should increase blast-radius concern, not reduce suspicion. A trusted account going bad is more dangerous than a new account going bad because users, reviewers, and automation may be inclined to trust it.

### Anti-Gaming Requirements

The reputation system should be designed assuming adversarial manipulation.

Defenses:

- Low-risk version bumps should contribute only limited reputation.
- Reputation from one ecosystem should not automatically transfer to another.
- New accounts should face rate limits regardless of early positive activity.
- Vouches should be public, signed, and reputation-affecting for the voucher.
- Collusive review rings should be detectable through graph analysis.
- Dormant accounts returning after long inactivity should enter probation.
- Account compromise should trigger reputation freeze and package freeze workflows.
- A single malicious or negligent high-risk approval should cost more reputation than many trivial updates earn.
- Package reputation should not be inherited automatically after maintainer change.

## Web of Trust

The system should use a web of trust rather than a single global trust bit.

Trust edges should be explicit, typed, scoped, and preferably signed.

Examples of trust edges:

- Maintainer A vouches for contributor B for a specific package.
- Reviewer A approved contributor B's update in a specific ecosystem.
- Contributor B has N accepted proposals for package X.
- Builder C produced a matching build attestation for recipe revision R.
- Security reviewer D approved a high-risk install hook.
- Orphan steward E approved a stewardship transfer.

Trust edges should carry metadata:

- Scope.
- Risk level.
- Timestamp.
- Expiration or decay policy.
- Whether the edge was automatic or explicit.
- Whether the edge was later implicated in an incident.

High-risk actions should require independent trust paths. For example, a critical update should not be approved only by accounts that all vouched for each other last week.

The web of trust should combine:

- User reputation.
- Package reputation.
- Maintainer lineage.
- Review history.
- Build attestations.
- Static analysis results.
- Current account-security state.

No single component is sufficient by itself.

## Recipe Format

Traditional package recipes are arbitrary shell scripts. That is flexible but difficult to analyze.

A better system should move toward a more declarative recipe model while still allowing escape hatches.

Example manifest:

```yaml
name: example
version: 1.2.3
upstream: https://github.com/example/example

sources:
  - url: https://github.com/example/example/archive/v1.2.3.tar.gz
    sha256: deadbeef...

build:
  system: cmake
  network: false
  home_access: false
  filesystem:
    read:
      - source
    write:
      - build

package:
  root_required: false
  install_hooks: false

external_package_managers:
  npm: false
  pip: false
  cargo: false
  bun: false
```

If a recipe needs extra power, it must declare it.

Examples:

- Network access during build.
- Access to `$HOME`.
- Root install hooks.
- Dynamic dependency fetching.
- Kernel module compilation.
- eBPF artifacts.
- Browser extension installation.
- Systemd unit installation.
- Setuid files.

## Source, Namespace, and Dependency Provenance

The recipe should make provenance explicit enough for automation to reason about it.

Source metadata should include:

- Upstream project identity.
- Canonical source URL pattern.
- Expected hosting provider or domain.
- Immutable source identifier where possible, such as commit SHA or signed release tag.
- Source hash.
- Upstream signature or attestation if available.
- Whether generated archives are known to be stable or mutable.

Namespace metadata should distinguish:

- Package namespace in this repository.
- Upstream project namespace.
- Language ecosystem namespace, if any.
- Organization or domain verification, if available.
- Forks, replacements, and abandoned upstream continuations.

Dependency metadata should avoid hidden resolver behavior:

- Dynamic dependency resolution should be disabled by default during build.
- Language ecosystem dependencies should come from declared manifests and lockfiles.
- New lockfiles or large dependency graph changes should be reviewed.
- Dependencies should have their own reputation, provenance, and indicator checks where possible.
- Cross-ecosystem dependency additions should be high risk unless clearly justified.

A source hash verifies bytes, not intent. Provenance metadata helps decide whether those bytes came from the expected party through the expected path.

## Static Analysis

Every submitted recipe and update should be scanned automatically.

The scanner should detect:

- New or changed install hooks.
- `curl | sh` or equivalent patterns.
- Dynamic dependency installation.
- New package-manager invocations that were not present in previous recipes.
- New cross-ecosystem installers unrelated to the package's normal build system.
- Newly added package-manager dependencies with low reputation or known-bad indicators.
- Changes to dependency manifests or lockfiles.
- Network access in build phases.
- Unexpected writes outside build/package directories.
- Access to `$HOME`, `.ssh`, browser profiles, password stores, cloud config, or token paths.
- Binary blobs.
- Minified or obfuscated scripts.
- Source URL changes.
- Hash removals or weak checksums.
- New systemd services.
- New timers or autostart entries.
- Setuid/setgid files.
- Kernel modules.
- eBPF programs.
- Suspicious post-install behavior.

The scanner should produce a clear risk report, not just a pass/fail result.

Example:

```text
Risk: HIGH

Reasons:
- Package adopted 2 days ago.
- New .install file added.
- post_install runs as root.
- build() now invokes `npm install` for a package that previously had no Node.js build path.
- Newly fetched dependency has no relationship to the upstream project.
- Source URL changed from GitHub release to arbitrary tarball.
- Package was dormant for 11 months before this update.
```

## Automated Analysis Pipeline

Automated analysis should run before human review and before publication. The goal is to catch most mistakes, known-bad patterns, and commodity attacks while producing a report humans and clients can understand.

Recommended pipeline:

1. Parse and lint the recipe.
2. Produce a semantic diff against the previous accepted revision.
3. Classify the update delta and requested capabilities.
4. Verify source provenance, URL patterns, checksums, upstream signatures, and tag immutability where possible.
5. Analyze dependency manifests, lockfiles, and transitive dependency changes.
6. Run static analysis over shell, Python, JavaScript, Rust build scripts, and install hooks.
7. Build in a disposable sandbox with filesystem, process, and network monitoring.
8. Simulate install, upgrade, and removal hooks in a disposable root filesystem.
9. Diff produced package artifacts against the previous version.
10. Record logs, network attempts, filesystem writes, syscalls, and generated files.
11. Produce a machine-readable risk report and a human-readable explanation.

The analysis environment should include traps that make malicious behavior visible:

- Fake home directory with canary files.
- Fake SSH, Git, cloud, browser, and token paths.
- Network egress proxy or default-deny network policy.
- DNS and HTTP request logging.
- Filesystem write monitoring.
- Detection of attempts to escape build directories.
- Detection of attempts to behave differently inside a sandbox.

Automated analysis will not catch everything. It may miss dormant payloads, targeted malware, time bombs, sandbox-aware behavior, compromised upstream source, or attacks hidden in complex dependency graphs. Therefore analysis is a required signal, not a complete security proof.

If automated systems disagree, fail, or cannot analyze a change, the update should be escalated rather than treated as safe.

## Pre-Distribution Gate

A distro-grade system should have a dedicated analyzer/checker gate before an update can be distributed.

The gate should be mandatory for every recipe revision, built artifact, metadata update, and install hook. Nothing should become visible as an installable update until the gate has produced and signed a verdict.

The gate should verify:

- Recipe diff and declared capabilities.
- Source provenance and source hashes.
- Upstream signatures or attestations where available.
- Dependency graph and lockfile changes.
- Static analysis results.
- Sandboxed build results.
- Install, upgrade, and removal hook simulation.
- Artifact contents and package metadata.
- Known malicious-indicator matches.
- Required human approvals for the risk tier.
- Required build attestations for the risk tier.

The output should be a signed decision record:

```yaml
package: example
revision: 1.2.3-1
recipe_hash: sha256:...
source_hashes:
  - sha256:...
artifact_hash: sha256:...
risk_tier: medium
verdict: allow
checks:
  static_analysis: pass
  sandboxed_build: pass
  install_hook_simulation: none
  provenance: pass
  indicators: no_matches
approvals:
  - reviewer: alice
    signature: sig:...
expires: 2026-07-01T00:00:00Z
signature: sig:...
```

Clients should refuse updates without a valid signed gate record unless the user explicitly opts into unsafe development mode.

## Cloaking and TOCTOU Prevention

All recipe inputs, source artifacts, build outputs, analysis results, and distribution metadata should be content-addressed, hashed, signed, and logged.

This prevents cloaking attacks where different users, builders, reviewers, or analyzers see different content.

Rules:

- The analyzer must analyze the exact source hashes that builders use.
- Builders must build the exact recipe hash that reviewers approved.
- Distributed packages must match the artifact hash in the signed gate record.
- Clients must verify repository metadata signatures and artifact hashes before install.
- Source fetches should prefer immutable commits, signed tags, release artifacts, or content-addressed mirrors.
- Mutable upstream tags or generated archives should be flagged or mirrored by hash.
- Any mismatch between analyzed content and distributed content is a hard failure.
- Transparency logs should make equivocation visible if the repository serves different metadata to different clients.

Signing alone is not enough if the wrong thing is signed. The system must bind together recipe, source, analysis, approvals, build output, and published metadata into one verifiable chain.

## Global Indicators, Denylists, and Campaign Detection

Known attacks should become global protection immediately.

When static or sandbox analysis finds a confirmed malicious payload, the system should publish signed machine-readable indicators so every package, reviewer, helper, and builder can block repeats.

Indicator types:

- Malicious source hashes.
- Malicious package artifacts.
- Malicious dependency names and versions.
- Malicious URLs and domains.
- Malicious maintainer keys or account IDs.
- Suspicious script snippets and command patterns.
- Network indicators observed in sandbox.
- Filesystem paths targeted by malware.
- Install-hook behavior signatures.

The indicator feed should support both hard blocks and soft flags:

- **Hard block** — confirmed malicious hash, URL, package artifact, or exact payload signature.
- **Soft flag** — suspicious pattern requiring review, such as a newly added random npm package in a recipe that has no Node.js build history.

This would catch many commodity attacks quickly. For example, if one sandboxed build observes a newly added dependency resolving to an infostealer, that dependency, payload hash, network behavior, and recipe pattern should be distributed as global indicators. Subsequent proposals using the same indicator should be blocked before publication.

The system should also correlate campaigns:

- Many packages adding the same new dependency.
- Many orphan adoptions followed by similar recipe changes.
- Multiple accounts using the same source URLs, payload hashes, or network endpoints.
- Similar script snippets spread across unrelated packages.
- Review approvals clustered inside a suspicious trust graph.

### Reverse Reputation and Taint

Reputation should work both ways. Known-bad submissions should not merely subtract points; they should trigger immediate bad-actor quarantine for users, packages, reviewers, and trust edges involved in the event.

If a proposal or accepted update matches a confirmed malicious indicator, the system should:

- Freeze the package revision.
- Mark the submitting account as bad-actor/quarantined immediately, even if it has high reputation.
- Disable the account's ability to publish, adopt, review, vouch, or attest builds.
- Treat the event as account takeover, credential compromise, maintainer-host compromise, or malicious insider until proven otherwise.
- Quarantine or downgrade affected package reputation.
- Flag reviewers or maintainers who approved it.
- Trace related proposals by the same account, key, IP range, dependency, source URL, or payload signature.
- Notify users who installed affected revisions.
- Require re-review of recent submissions from the implicated account or trust cluster.

This should be evidence-based. A confirmed malicious payload should be treated differently from a suspicious false-positive-prone pattern. But once the payload is confirmed, current trust must flip immediately. Account compromise can be distinguished from deliberate abuse later; either way, the account is not safe to trust while the incident is unresolved.

## Update Delta Taxonomy

Risk should be based primarily on the delta from the previous accepted recipe.

A package's current contents matter, but most attacks hide inside changes that users perceive as routine. The system should therefore classify what changed, who changed it, and whether the new behavior crosses a trust boundary.

### Routine Version Bump

A routine version bump is the safest common update class, but it is not automatically safe.

A change qualifies as routine only if all of the following are true:

- Version and package release fields changed.
- Hashes changed to match the new declared upstream artifact.
- Source URL pattern is unchanged.
- Upstream project identity is unchanged.
- Build, package, and install logic are unchanged.
- No new dependencies are declared.
- No new dynamic dependency installers are invoked.
- No install hooks are added or changed.
- No new network access is requested.
- Maintainer lineage is stable.

Even then, residual risks remain:

- Upstream may be compromised.
- Upstream may intentionally ship malicious code.
- Tags or generated archives may be mutable.
- A checksum confirms bytes, not intent.
- A source URL template may hide a trust-boundary change if not parsed carefully.

Routine version bumps can usually be fast-tracked, but they should still be scanned, logged, and made easy to inspect.

### Source or Trust Boundary Change

Changing where code comes from is more important than changing the version number.

Examples:

- GitHub release changed to arbitrary tarball.
- Release archive changed to a moving branch.
- Pinned commit changed to a tag.
- Official source changed to a mirror.
- Source URL now points to a maintainer-controlled domain.
- Checksums are removed or weakened.

These changes should be medium or high risk depending on package impact.

### Dependency Surface Change

Changes to dependency behavior often deserve more scrutiny than version bumps.

Examples:

- New declared system dependency.
- New language ecosystem dependency.
- New dependency manifest.
- New or changed lockfile.
- Vendored dependency tree changed.
- Build system starts resolving packages dynamically.

Dependency changes are especially risky in ecosystems with large transitive dependency graphs.

### New Installer or Fetcher Behavior

Any update that adds or changes behavior that fetches or installs code outside the declared source list should be high risk by default.

Examples:

- `npm install`
- `pip install`
- `cargo install`
- `go install`
- `bun install`
- `curl`, `wget`, or `git clone` during build
- Downloading scripts during `prepare()`, `build()`, `package()`, or install hooks

This is a major trust-boundary change. It moves review from a finite recipe and source list to an open-ended dependency resolver or remote script.

It is especially suspicious when the new installer belongs to an ecosystem the package has never used before. Most packages should not suddenly need a random npm, pip, cargo, or bun package added during build or install. That pattern should be high risk by default and should become a hard block if the dependency or behavior matches a known malicious indicator.

### Privileged Install-Time Behavior

Anything that runs as root at install or upgrade time is high or critical risk.

Examples:

- New `.install` file.
- Changed `post_install`, `post_upgrade`, or `pre_remove` hook.
- Systemd service enablement.
- User/group creation.
- Kernel module setup.
- eBPF setup.
- Setuid/setgid file installation.
- Writes to shell startup files, SSH config, browser profiles, or credential stores.

These changes should require elevated review and prominent client warnings.

## Risk Classification

Updates should be classified into risk tiers.

### Low Risk

Examples:

- Strict routine version bump.
- Hash update for an unchanged source URL pattern.
- Metadata-only change.
- No new dependencies.
- No new hooks.
- No maintainer change.
- No new capabilities requested.

Default action:

- Maintainer may publish directly.
- Automated scan required.
- User-visible changelog generated.
- Package reputation is preserved if checks pass.

### Medium Risk

Examples:

- New declared dependency.
- Dependency manifest or lockfile changed.
- Build system changed.
- Source URL changed within the same upstream trust boundary.
- New optional feature.
- Package revived after moderate dormancy.

Default action:

- Require review or delayed publication.
- Show warning in clients.
- Temporarily lower package confidence until the change ages cleanly.

### High Risk

Examples:

- Recent maintainer change.
- Orphan adoption.
- New build-time or install-time package-manager invocation.
- Network access added during build.
- Source origin changed across a trust boundary.
- Dynamic dependency installer added.
- Binary blob added.
- Package revived after long dormancy.
- Large dependency tree added or replaced.

Default action:

- Require reviewer approval.
- Require cooldown.
- Show strong warning in clients.
- Optionally block by default in strict mode.
- Put package reputation into probation.

### Critical Risk

Examples:

- New install hook.
- Root-level script added or changed.
- Kernel/eBPF/system service behavior added.
- Setuid/setgid behavior added.
- Credential, browser, SSH, shell profile, or token-store access.
- High-risk change made immediately after adoption or maintainer replacement.

Default action:

- Block by default unless explicitly approved.
- Require elevated security review.
- Require stronger maintainer reputation.
- Require sandboxed build evidence where applicable.
- Notify subscribers or affected users when published.

## Review Workflow

A democratic system can allow broad participation without allowing unreviewed high-risk changes.

Suggested workflow:

1. Contributor submits recipe update.
2. Automated analysis produces a risk report.
3. Required confirmations are calculated from the risk tier.
4. Low-risk changes may be merged by maintainers when automated checks pass.
5. Medium-risk changes require review or delay.
6. High-risk changes require multiple independent confirmations.
7. Critical changes require elevated security review.
8. Clients consume the risk metadata and warn users.
9. Users can opt into stricter local policy.

Reviews should be structured:

- Does the recipe match the upstream release?
- Are source URLs correct?
- Are checksums pinned?
- Are new dependencies justified?
- Are install hooks necessary?
- Is network access necessary?
- Is the package doing anything unrelated to its stated purpose?

### Confirmation Requirements

Updates should require multiple confirmations, with more confirmations for higher risk.

Confirmation types:

- Static analysis pass.
- Sandboxed build pass.
- Install-hook simulation pass.
- Provenance verification.
- Reproducible build or independent build attestation.
- Maintainer approval.
- Reviewer approval.
- Security reviewer approval.
- User local policy approval.

Suggested matrix:

| Risk tier | Required confirmations |
| --- | --- |
| Low | Static analysis, sandboxed build, maintainer merge |
| Medium | Static analysis, sandboxed build, one reviewer or second maintainer |
| High | Static analysis, dynamic sandbox analysis, provenance check, two independent reviewers, cooldown |
| Critical | All high-risk confirmations, security reviewer, maintainer quorum, install-hook simulation, optional N-of-M build attestations |

Confirmation diversity matters. A high-risk update should not be approved only by accounts from the same new trust cluster, the same organization, or the same recent vouch chain.

Automation should be able to approve only narrow low-risk cases. For risky deltas, automated systems should route and explain review; they should not silently grant trust.

## Sandboxed Builds

Users should not have to run arbitrary build scripts on their main workstation with access to personal secrets.

Default build restrictions:

- Dedicated build user.
- No access to the user's real `$HOME`.
- No access to SSH keys, browser profiles, password stores, cloud credentials, or Git credentials.
- Network disabled after source fetch unless declared.
- Isolated filesystem.
- Limited process capabilities.
- Build logs captured.
- Source inputs recorded.
- Build environment recorded.
- Network attempts recorded and blocked unless explicitly allowed.
- Filesystem reads and writes monitored.
- Package artifacts diffed against previous versions.
- Install, upgrade, and removal hooks tested in a disposable root filesystem.

Sandboxing should be preventative, not only diagnostic. Even if analysis misses malicious behavior, the default sandbox should prevent the build from reading real user secrets or modifying the host.

### Central Builders and Local Builders

The system should support both central analysis builders and local user builds.

- Central builders provide consistent automated analysis, public logs, artifact hashes, and reproducibility checks.
- Independent builders provide diversity and reduce trust in a single build farm.
- Local builders give users control but should use the same sandbox policy and metadata checks.
- Binary caches may be offered, but clients should verify signatures, provenance, and policy before installation.
- A locally built package should still inherit repository risk metadata, indicator checks, and maintainer-history warnings.

This combines Nix/Guix-style build isolation with a community-repository workflow while avoiding a hard dependency on either central binaries or unsafe local builds.

Possible enforcement tools:

- Containers.
- Namespaces.
- Landlock.
- Bubblewrap.
- systemd-nspawn.
- chroots.
- seccomp.

## Build Attestations and Reproducibility

A stronger system should support public build attestations.

An attestation should state:

- Recipe version.
- Source hashes.
- Builder identity.
- Build environment.
- Build timestamp.
- Output package hash.
- Logs.
- Whether the build was reproducible.

Users could require:

- One successful sandboxed build.
- N-of-M independent matching builds.
- A trusted builder signature.
- Reproducibility before install.

### Attestation Levels

Attestations should have levels so clients can enforce policy without reading every log manually.

Example levels:

- **Observed** — a sandboxed build completed and logs are available.
- **Provenance-attested** — the build is tied to OIDC identity, source revision, recipe revision, and builder identity.
- **Reproducible-once** — one independent builder produced the same output.
- **Reproducible-N** — multiple independent builders produced matching outputs.
- **Policy-clean** — the build passed static analysis, sandbox policy, source checks, dependency checks, and install-hook simulation for its declared risk tier.

Higher-risk updates should require higher attestation levels.

## Install Hooks

Install hooks are privileged code and should be treated as exceptional.

Rules:

- No install hooks by default.
- Adding or changing a hook is high risk.
- Hooks must be declared separately from the build recipe.
- Hook diffs are shown prominently.
- Root-running hooks require elevated review.
- Clients warn loudly when hooks are present.

Example warning:

```text
This package contains a root-level post_install hook.
Review required before installation.
```

## Client Policy

Package helpers should enforce user-configurable trust policy with sane safe defaults.

The default user experience should be:

- Safe routine updates can be installed normally when they meet trust thresholds.
- Untrusted, risky, or unusual updates require explicit user confirmation.
- Dangerous updates require a forced step-through review and should not be hidden inside bulk upgrades.
- Confirmed malicious indicators are blocked, not merely warned about.
- Users can inspect, edit, fork, or adapt recipes easily before building.
- The UI should explain exactly which threshold failed and what would be required to pass it.

Example policy:

```yaml
auto_install:
  enabled: true
  min_risk_tier: low
  max_risk_tier: low
  min_package_reputation: established
  min_submitter_reputation: package_contributor
  min_install_count: 1000
  min_clean_age_days: 30
  require_no_failed_thresholds: true

force_step_through:
  risk_tier_at_least: medium
  maintainer_changed_within_days: 30
  dormant_package_revived_after_days: 180
  source_url_changed: true
  new_dependency_surface: true
  package_reputation_below: established

deny:
  unreviewed_high_risk_updates: true
  newly_adopted_packages: true
  new_install_hooks: true
  new_dynamic_installers: true
  known_malicious_indicators: true
  suspicious_new_cross_ecosystem_installer: true
  build_home_access: true
  package_reputation_below: probationary

warn:
  maintainer_changed_within_days: 30
  dormant_package_revived_after_days: 180
  source_url_changed: true
  package_reputation_changed: true
  submitter_new_to_package: true
  dependency_reputation_low: true
  campaign_similarity_detected: true
  install_count_below: 1000
  clean_age_below_days: 30

require:
  signed_recipe: true
  signed_gate_record: true
  sandboxed_build: true
  static_analysis_passed: true
  indicator_feed_current: true
  no_confirmed_malicious_indicator_matches: true
  min_submitter_reputation_for_high_risk: reviewer
  package_reputation_not_probationary: true
```

Client modes:

- **Permissive** — warn only, except confirmed malicious indicators remain blocked.
- **Default** — auto-install only low-risk, well-established updates; step through anything below threshold; block clearly dangerous updates unless user explicitly overrides.
- **Strict** — require review, signatures, sandboxing, gate records, and strong package reputation.
- **Enterprise** — allow only packages matching organization policy.

### Auto-Install Thresholds

Automatic installation should be earned, not assumed.

A package update should be eligible for default auto-install only when it satisfies all required thresholds, such as:

- Low risk tier.
- Signed recipe revision.
- Valid signed pre-distribution gate record.
- No malicious indicator matches.
- Static analysis passed.
- Sandboxed build passed.
- No new install hooks.
- No new dynamic dependency installers.
- No source trust-boundary change.
- Package reputation at or above `established`.
- Submitter reputation sufficient for the package or ecosystem.
- Package has enough successful installs, clean aging time, or build attestations.
- Maintainer lineage is stable.

Install count should be treated as adoption evidence, not proof of safety. It should help only when combined with clean analysis, clean history, and trust metadata.

Anything that fails an auto-install threshold should become an interactive decision, not a silent upgrade.

### Forced Step-Through Review

When an update is below threshold but not hard-blocked, the client should guide the user through a clear review flow:

1. Show the package identity, maintainer lineage, and reputation state.
2. Show exactly which thresholds failed.
3. Show the semantic diff: version, source, dependencies, build logic, hooks, capabilities, and artifacts.
4. Show the automated analysis report and sandbox observations.
5. Show required approvals and which are missing.
6. Offer safe actions: skip, pin current version, subscribe for review updates, open recipe, fork/adapt recipe, or build in extra-strict sandbox.
7. Require an explicit typed confirmation or policy exception for risky installation.

The user should never be asked to approve a vague prompt like "build package?" without context.

### Browsing, Editing, and Adapting Recipes

The client and web UI should make it easy to inspect and adapt recipes:

- Browse package history and maintainer history.
- Compare proposed updates against the installed version.
- Open the recipe and install hooks in an editor.
- Remove or modify suspicious optional behavior locally.
- Fork a recipe into a personal namespace.
- Submit an improvement proposal upstream.
- Save local policy exceptions with expiration dates and explanations.

Power users should be able to take control, but the system should make clear when they are leaving the safe default path.

## User Interface Requirements

The web UI and package helpers should show security-relevant context prominently.

Important fields:

- Maintainer history.
- Recent ownership changes.
- Dormancy period.
- Risk score.
- Package reputation state.
- Submitter reputation state.
- Install count and clean-age history.
- Auto-install eligibility.
- Failed trust/safety thresholds.
- Review status.
- Static analysis report.
- Install hook presence.
- Build sandbox status.
- Attestation status.
- Recent suspicious changes.

Good UI should make risky state impossible to miss. It should also make safe state explainable: users should be able to see why an update was auto-installed, why another requires review, and what evidence would move it across the threshold.

## Governance

The system needs roles, but roles should be narrow and auditable.

Potential roles:

- Contributor — can submit recipe proposals.
- Maintainer — can maintain specific packages.
- Reviewer — can approve risk-classified changes.
- Orphan steward — can approve or deny adoption proposals.
- Security responder — can freeze packages and revoke malicious updates.
- Build attestor — can publish signed build results.
- Administrator — can manage accounts and namespace disputes.

All privileged actions should be logged publicly where possible.

## Emergency Response

The system should have explicit incident response tools:

- Freeze package.
- Freeze maintainer account.
- Revoke malicious recipe revision.
- Mark affected package versions as malicious.
- Notify subscribed users.
- Publish machine-readable advisories.
- Publish signed global malicious-indicator updates.
- Block known-bad hashes, URLs, dependency versions, payload signatures, and behavior signatures.
- Correlate related accounts, packages, reviewers, and source indicators.
- Apply reverse reputation penalties or quarantine to implicated accounts and packages.
- Show detection guidance.
- Provide rollback instructions.

## Minimum Viable Version

A practical first version could implement:

1. Public maintainer history.
2. Basic user reputation and package reputation metadata.
3. Adoption cooldowns.
4. Bulk adoption and update rate limits.
5. Mandatory MFA for maintainers.
6. Signed recipe commits or releases.
7. Static recipe scanner.
8. Automated sandboxed analysis pipeline.
9. Signed global malicious-indicator feed.
10. Reverse reputation/quarantine for confirmed malicious submissions and approvals.
11. Delta-based risk classification metadata.
12. Risk-based confirmation requirements.
13. Helper warnings for recent adoption, package reputation changes, new hooks, source changes, dynamic dependency installers, and indicator matches.
14. Sandboxed local builds without access to the user's home directory.
15. High-risk update review queue.
16. OIDC Trusted Publishing for automated package submissions and build attestations.
17. Mandatory signed pre-distribution gate records for every published update.
18. Content-addressed hashes binding recipe, source, analysis, build output, and metadata.
19. TUF-style signed repository metadata with expiry and rollback protection.
20. Append-only transparency log for package events and trust changes.

## Open Questions

- What should the default adoption cooldown be?
- Which packages count as high impact?
- How should user reputation be calculated without becoming a popularity contest?
- How should package reputation be calculated without becoming a popularity contest?
- How much should routine version bumps contribute to reputation?
- Which events should decay, reset, or put package reputation into probation?
- Which malicious indicators should be hard blocks versus soft review flags?
- How should false positives in the global indicator feed be appealed and corrected?
- How should reverse reputation handle compromised accounts versus deliberate malicious actors?
- How should the system detect reputation farming, sybil accounts, and collusive review rings?
- Who can approve high-risk changes?
- How many reviewers should be required for orphan adoption?
- How strict should default client policy be?
- Should community-built binaries be allowed, or should users always build locally?
- How should forks and abandoned upstream continuations be represented?
- What recipe language balances safety and flexibility?
- How do we prevent review bottlenecks?
- How do we avoid excluding casual contributors?

## Design Mantra

> Make contribution easy. Make trust explicit. Make risky changes visible. Make dangerous behavior require review. Make local compromise harder.

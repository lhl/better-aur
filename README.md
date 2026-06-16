# Better AUR

A sketch for a safer, more transparent, and more democratic community package recipe system inspired by the Arch User Repository, but designed around explicit trust, review, sandboxing, and maintainership continuity.

This document is intentionally a working draft. The goal is to iterate on the model, identify tradeoffs, and eventually turn the design into concrete specs and prototypes.

## Table of Contents

- [Problem Statement](#problem-statement)
- [Terminology](#terminology)
- [Motivating Incident: The Atomic Arch Campaign](#motivating-incident-the-atomic-arch-campaign)
- [Core Principle](#core-principle)
- [Defense Layers and Their Limits](#defense-layers-and-their-limits)
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
- [Binary and Vendor-Artifact Packages](#binary-and-vendor-artifact-packages)
- [Static and Dynamic Analysis](#static-analysis)
- [Pre-Distribution Gate](#pre-distribution-gate)
- [Cloaking and TOCTOU Prevention](#cloaking-and-toctou-prevention)
- [Global Indicators and Campaign Detection](#global-indicators-denylists-and-campaign-detection)
- [Update Delta Taxonomy](#update-delta-taxonomy)
- [Risk Classification](#risk-classification)
- [Ownership Transition vs Content Change](#ownership-transition-vs-content-change)
- [Default-Deny Publication Rules and Escalation Paths](#default-deny-publication-rules-and-escalation-paths)
- [Automation and the Labor Model](#automation-and-the-labor-model)
- [Review Workflow](#review-workflow)
- [Sandboxed Builds](#sandboxed-builds)
- [Build Attestations and Reproducibility](#build-attestations-and-reproducibility)
- [Install Hooks](#install-hooks)
- [Client Policy](#client-policy)
- [User Interface Requirements](#user-interface-requirements)
- [Adoption Path and Compatibility](#adoption-path-and-compatibility)
- [Governance and Emergency Response](#governance)
- [Limitations and Residual Risk](#limitations-and-residual-risk)
- [Core Object Model](#core-object-model)
- [Worked Policy Examples](#worked-policy-examples)
- [Social and Governance Risks](#social-and-governance-risks)
- [Minimum Viable Version](#minimum-viable-version)
- [Open Questions](#open-questions)

## Problem Statement

Community package repositories are useful because they make it easy for users to share build recipes for software that is not available in official distribution repositories.

The weakness is that many systems treat package names and package history as if they imply trust. If an abandoned or orphaned package can be adopted by any account and updated without review, an attacker can inherit user trust attached to that package name.

A safer system should preserve the ease of community contribution while making trust explicit.

## Terminology

This document uses standard supply-chain and Linux-packaging terms in their usual sense (OIDC, Trusted Publishing, TUF, SLSA, in-toto, reproducible builds, attestation, provenance, content-addressing, seccomp, Landlock, DKMS, eBPF). The terms below are specific to this design or are given a precise meaning here:

- **Recipe** — the build definition for a package: the PKGBUILD-equivalent plus its manifest.
- **Manifest** — the recipe's declared capabilities (network, `$HOME` access, install hooks, external package managers). It is an enforced allowlist: the build sandbox is configured from it.
- **Lineage** — a package's stable identity across renames and maintainer changes. Reputation and trust attach to the lineage rather than the package name.
- **Stewardship** — the maintainer role over a lineage. A steward can propose and merge changes within granted capabilities but does not own the name.
- **Capability** — a discrete privilege a recipe may use: build network, a specific external package manager, an install hook, or a privileged install action.
- **Capability baseline** — the set of capabilities a lineage's accepted revisions have used.
- **Delta** — the classified change of an update relative to the previous accepted revision, named by what changed: recipe delta, source-tree delta, dependency delta, capability delta.
- **Capability delta** — the capabilities an update adds or removes relative to the baseline; the structured input to risk classification.
- **Risk tier** — the assigned severity of an update: low, medium, high, or critical.
- **Gate record** — the signed decision produced by the pre-distribution gate, binding recipe hash, source hashes, analysis result, approvals, and artifact hash. A client installs only after verifying a gate record against local policy.
- **Default-deny** — refused for automatic publication but reachable through an escalation path (declaration, scoped review, simulation, gate record).
- **Hard block** — outright refusal with no escalation path, reserved for confirmed malicious indicators and unmitigable violations.
- **Indicator (IoC)** — a confirmed malicious artifact such as a payload hash, package version, source URL, or command-and-control endpoint. The **indicator feed** is the signed, subscribable distribution of these.
- **Trust edge** — a signed, scoped vouch from one account or entity to another in the web of trust.
- **Trust inversion** — on confirmed malware, an account's accumulated trust is immediately revoked and the account, its packages, reviews, and trust edges are quarantined.
- **Taint** — propagating that quarantine to related accounts, packages, and trust edges implicated in the same event.
- **Execution phase** — fetch, build/package, hook simulation, real install, or runtime. Controls differ by phase (see [Execution phases](#execution-phases)).

## Motivating Incident: The Atomic Arch Campaign

This design responds to the "Atomic Arch" supply-chain campaign against the AUR, first disclosed by Sonatype on 11 June 2026 (tracked as Sonatype-2026-003775, CVSS 8.7) and still being cleaned up as of this writing. The campaign exercises most of the weaknesses this document addresses, and its evolution over a few days shows which defenses hold and which do not.

### What happened

- **Inherited trust.** Attackers did not typosquat or publish new packages. They claimed ownership of *orphaned* AUR packages through the normal adoption process, keeping each package's existing name, history, and accumulated user trust. From a user's perspective they were updating a familiar package.
- **Only the build logic changed.** The visible package looked clean. Attackers modified the `PKGBUILD`/`.install` logic to add a post-install script that invoked a package manager — initially `npm install atomic-lockfile minimist chalk`, with `minimist` and `chalk` as plausible decoys. Signature- and content-based checks on the package itself saw nothing wrong.
- **The payload lived off-repository.** The pulled npm package `atomic-lockfile@1.4.2` carried a `preinstall` lifecycle hook (`"preinstall": "./src/hooks/deps"`) that executed a bundled, stripped Rust ELF during installation. The recipe and the package were both "clean"; the malice was one dependency-resolution hop away.
- **The payload targeted developer trust.** The ELF harvested Chromium/Electron credentials and session tokens (Slack, Teams, Discord, Telegram), GitHub and npm tokens, HashiCorp Vault tokens, SSH keys, Docker/Podman credentials, VPN profiles, shell history, and OpenAI/ChatGPT bearer tokens. It established systemd persistence (`Restart=always`) and exfiltrated through a Tor onion C2 reached via a local SOCKS loopback, with bulk uploads to `temp.sh`.
- **With root, it hid itself.** When the install ran with sufficient privilege (`CAP_BPF`/`CAP_SYS_ADMIN`), it loaded an eBPF rootkit hooking `getdents64()` with pinned maps (`/sys/fs/bpf/hidden_pids`, `hidden_names`, `hidden_inodes`) to hide its processes, files, and sockets from `ls`/`ps`/`find`, and killed `ptrace` attempts — making conventional on-host scanning unreliable.

### How it evolved

- **Within 24–48 hours**, a second wave swapped the installer to evade the first round of indicators — `bun add execa js-digest commander` (and `lockfile-js`) instead of `npm install atomic-lockfile` — tracked separately as Sonatype-2026-003808. Attackers also spoofed git commit metadata so changes appeared to come from previously trusted committers.
- **Scale:** the first wave was roughly 408 packages; within a day community tracking put the total above 1,500 (some counts near 1,600) across both waves, suggesting pre-staged alternate delivery infrastructure.
- **Incumbent response:** Arch suspended new AUR account registration and throttled package updates, adoptions, and creation while maintainers hunted malicious commits by hand, and asked users to manually review every `PKGBUILD` and install-script change. The response is almost entirely manual because the AUR has no analysis pipeline and no labor model for an incident at this scale.

### How this design responds

Each row gives an attack step, the guard that addresses it, and the outcome: **prevented** (structurally impossible), **contained** (runs but cannot cause harm), **blocked by default** (refused unless explicitly declared and independently reviewed), or **residual** (not solved; blast radius reduced only). Atomic Arch ran its fetch and payload from a post-install script, so the governing guard is install-hook policy, not the build sandbox; the same actions placed in a build phase would be stopped by default-deny egress (see [Execution phases](#execution-phases)).

| Attack step | Guard | Outcome |
| --- | --- | --- |
| Adopt an orphan, then ship a behavior-changing update in the same step | Ownership transition and content change are separate transactions; the first post-adoption update may only be a strict routine version bump | Blocked by default |
| Add a post-install script that runs `npm install atomic-lockfile …` (as observed) | A new or changed `.install` hook is denied by default; a cross-ecosystem installer with no prior history is a critical capability delta; the hook runs under simulation before any gate | Blocked by default |
| Place the same fetch in a build phase (`build()`/`package()`) instead | Default-deny build egress and fixed-output fetch (network only in a hash-pinned phase) | Prevented |
| Execute the npm `preinstall` lifecycle script that runs the ELF | Disabled when dependencies are resolved through declared `language_sources`; a hook that invokes `npm` on the host is governed by hook policy instead | Prevented under declared sources; otherwise via hook policy |
| Steal `~/.ssh`, browser, and token-store credentials during a build phase | Build sandbox with no real `$HOME` and no secrets present | Contained |
| Steal the same credentials from a post-install hook on the real host | Governed by the install-hook policy above, not the build sandbox | Blocked by default; not contained once the hook runs |
| Install an eBPF rootkit at install time, as root | eBPF/DKMS/kernel-module/setuid are denied by default and require elevated review | Blocked by default; not contained once it runs |
| Spoof git commit metadata to impersonate a trusted committer | The signed server event log is authoritative; Git author and committer fields are evidence only | Prevented for the trust decision |

The same guards cover the observed variants. Swapping `npm` for `bun`, `pip`, `cargo`, `go install`, or `curl | sh` changes nothing: each is treated as source acquisition, denied by default-deny egress in a build phase and by hook policy in an install script, regardless of the binary's name. The second wave's `bun add … js-digest` is blocked on the same basis as the first wave's `npm install`. Lexical obfuscation does not matter to a guard at the network and syscall layer. Decoy dependencies do not lower the tier, since the capability delta flags the new ecosystem relationship rather than the package names. Bulk campaigns are slowed by adoption and update rate limits and turned into ecosystem-wide blocks by the indicator feed and log watchers.

Three classes remain residual:

- A backdoor compiled into upstream source or a release tarball builds cleanly. Source-tree delta, build-from-VCS, and tarball-vs-VCS diffing narrow this but do not close it (see [Limitations and Residual Risk](#limitations-and-residual-risk)).
- A patient adopter who maintains a package through cooldown and then defects with a routine-looking change. Containment limits build-time damage and instant inversion limits persistence, but the change is not prevented.
- Malicious runtime behavior of installed software, which is out of scope for any packaging system.

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
- What risk tier does this update fall into?

## Defense Layers and Their Limits

The layers below do different jobs: some stop attacks, others help people understand and respond to them. The distinction matters because detection can be evaded while containment cannot.

### Containment and detection

Most attacks on an update fall into a few channels:

| Channel | Example | Contained by sandbox + enforced manifest? |
| --- | --- | --- |
| Build-time secret theft | build reads `~/.ssh`, browser profiles, token stores | Yes — nothing sensitive exists in the build environment |
| Build-time exfiltration / undeclared fetch | `npm`/`bun install`, `curl \| sh` in `build()` | Yes — egress is refused at the network layer regardless of obfuscation |
| Poisoned artifact | backdoor in upstream source, a patch, or a release tarball, compiled into the binary | No — the build faithfully compiles whatever it is given |
| Privileged install-time behavior | `.install` hook running as root on the user's real machine | No — only the build-farm *simulation* is sandboxed; the real hook runs for real |
| Malicious runtime behavior | the installed program misbehaves with the user's real credentials | No — out of scope of any packaging system |

The first two channels are the bulk of observed attacks, and they are what Atomic Arch used. A build sandbox with default-deny egress and no real secrets closes them regardless of obfuscation, reputation, or review, because it acts at the syscall and network boundary rather than by matching a pattern. Containment is the safety floor.

Detection — static analysis, indicator feeds, pattern matching — still runs, but to triage and explain rather than to gate. It can be evaded: the Atomic Arch second wave defeated the first round of indicators within 48 hours by switching `npm` to `bun` and adding decoy dependencies. A sandbox that refuses undeclared egress does not depend on recognizing the command.

### Limits of containment

Containment does not close the remaining channels:

- A build sandbox protects the builder, not the artifact. A backdoor in upstream source, a patch, or a release tarball builds and reproduces normally. Reproducible builds prove the artifact matches the recipe, not that the source is benign. Source-tree delta analysis, building from version control, and diffing tarballs against their VCS tags reduce this risk (see [Update Delta Taxonomy](#update-delta-taxonomy)).
- Install hooks run on the user's real system, not in the build sandbox. They are treated as critical-risk, simulated, and require elevated review (see [Install Hooks](#install-hooks)).
- Malicious runtime behavior of installed software is out of scope for any packaging system; downstream application sandboxing (Flatpak-style) is the mitigation.

### Reputation, web of trust, and provenance UX

Reputation, the web of trust, and provenance UI are not the primary barrier and must never lower the safety floor (see [Reputation Model](#reputation-model)). They do three things:

- **Legibility.** Users and helpers need to see why an update is safe, risky, or blocked: who maintains it, whether ownership changed, whether the package was dormant, what changed, and what evidence backs it. Provenance and reputation state make that judgement visible instead of leaving it in a raw diff.
- **Routing.** Reputation decides how much attention a change gets and who may review it, so review effort lands where it matters. It buys speed within a risk tier, not exemption from the gates.
- **Response.** A confirmed malicious submission inverts trust immediately and propagates (instant quarantine, package freeze, indicator feed). This trust-inversion path turns one confirmed detection into ecosystem-wide quarantine.

Containment and analysis decide whether a change can do harm; reputation decides how much scrutiny it gets and how fast the system reacts. Conflating the two is how a farmed-reputation account gets a dangerous change approved.

### Execution phases

Controls differ by phase; conflating phases misreads the guarantees:

| Phase | Runs where | Default network | Real user secrets present | Primary control |
| --- | --- | --- | --- | --- |
| Fetch | builder or helper | declared, hash-pinned sources only | no | fixed-output source closure |
| Build/package (`prepare`, `build`, `check`, `package`) | sandbox | denied | no | manifest-enforced sandbox |
| Hook simulation | disposable root filesystem | denied by default | no | behavior analysis, gate input |
| Real install (`.install` hooks) | user host | host policy | yes; root possible | deny-by-default hooks, client policy, signed gate record |
| Runtime | user host | normal application policy | yes | out of scope; application sandboxing |

The build sandbox covers only the fetch and build/package phases. Anything in a `.install` hook runs on the real host at install time; its controls are install-hook gating, default-deny client policy, declarative install actions, and pre-install simulation, not the build sandbox.

## Current System Snapshot

The current design is an AUR-like community recipe system with five major upgrades over traditional single-owner package repositories:

1. **Containment-first builds** — recipe build and install logic runs in a sandbox with default-deny network egress and no access to real user secrets, so the most common attacks (build-time credential theft and undeclared payload fetching) are blocked by construction rather than by recognition. This is the safety floor; the other layers are defense in depth.
2. **Open contribution without single-owner lock-in** — anyone can propose updates, while package namespaces are stewarded by maintainers, reviewers, and orphan stewards rather than permanently owned by the first submitter.
3. **Delta-aware security** — the system judges updates by what changed: a strict version bump is very different from a new install hook, new source origin, new dynamic dependency installer, or new root-running behavior. This includes the source-tree delta, not only the recipe delta.
4. **Automated analysis plus human confirmation** — static analysis, sandboxed builds, provenance checks, install-hook simulation, indicator feeds, and campaign detection catch common attacks before publication; high-risk changes still require independent human review.
5. **Layered trust and reputation for legibility and response** — users, packages, reviewers, builders, and trust edges all have scoped reputation. Reputation routes review effort, makes package provenance and status legible to users, and instantly flips an account into bad-actor quarantine when malware is confirmed — but it never lowers the objective safety floor.

The system aims to be both more secure and more responsive:

- Routine, low-risk maintenance can move faster.
- Stale packages can receive update proposals without waiting forever on an inactive first maintainer.
- High-risk changes become much harder to hide.
- Users and helpers get actionable warnings instead of raw unstructured diffs.
- Known attacks become global protections through signed indicators and denylists.

## Prior Art and Features to Adopt

Other package ecosystems already implement pieces of this design. The goal is not to copy any one system, but to combine their strongest ideas and add delta-aware review, sandbox analysis, reputation, and trust-inversion response.

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

Several existing systems implement pieces of this design closely enough that they should be reused or studied rather than reinvented:

- **rebuilderd** — independent rebuilders that verify reproducibility for Arch and Debian today; the natural backend for N-of-M build attestation rather than a bespoke reimplementation.
- **Socket.dev** — production delta-aware behavioral analysis for npm and PyPI (new install scripts, network and filesystem access, obfuscation, suspicious new dependencies); the closest existing implementation of this document's analysis layer, including its false-positive failure modes.
- **OpenSSF Scorecard** — objective repository-health signals (branch protection, signed releases, CI, dependency hygiene) usable to seed *package* reputation without a popularity contest.
- **GUAC / OSV / deps.dev** — ecosystem-wide graphs linking provenance, vulnerabilities, and dependency metadata; prior art for campaign correlation rather than a bespoke engine.
- **Nix fixed-output derivations and `nix store diff-closures`** — the model for hash-pinned network access during build and for detecting dependency-surface changes.
- **Nix build sandboxing** — isolated PID, mount, network, IPC, and UTS namespaces exposing only declared dependencies; the concrete reference for build-time isolation.
- **Provenance is not safety (PyPI/npm Trusted Publishing).** OIDC and short-lived tokens improve *authentication* and record where and how a build happened; they assert nothing about whether the code is malicious. Adopt the authentication model, but never let provenance stand in for a safety verdict.
- **OpenSSF Malicious Packages / OSV** — the signed indicator feed should interoperate with OSV-style malicious-package reports so detections are consumable across tools rather than siloed.
- **openSUSE Factory staging and TUF roles** — staging projects with automated checks and layered review are a model for the review pipeline; TUF's snapshot role (anti mix-and-match) and timestamp role (anti replay of stale metadata) are the specific properties to inherit, not just "TUF" generically.

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

No single check is authoritative. A package update is accepted only when the combination of identity, provenance, analysis, review, build evidence, and policy checks required for its risk tier all agree.

The recipe layer and the build layer are two ends of one mechanism: the manifest's declared capabilities are the allowlist, and the sandbox enforces them, recording any undeclared-but-attempted capability as a hard build failure. The build layer is the safety floor, because it contains attacks at the syscall and network boundary rather than by recognizing them.

## Goals

- Allow many people to submit and maintain package recipes.
- Make maintainership changes visible and reviewable.
- Prevent silent trust inheritance after orphan adoption.
- Track reputation for both users and packages, separately from popularity.
- Classify updates by what changed, including the source tree, not only the final recipe state.
- Require higher scrutiny for high-risk recipe changes.
- Provide automated static analysis for package recipes and install hooks, to triage and explain rather than to gate.
- Contain builds by default in a sandbox with default-deny network egress and no access to real user secrets, treated as the system's safety floor.
- Build from version control where possible and detect source-tree anomalies, not only recipe changes.
- Make the common, low-risk update auto-decidable without a human in the loop.
- Give users and helpers clear warnings, and legible provenance and status, before risky installs.
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

### Trusted Computing Base

The defenses above assume the build sandbox, the base images, the compilers, and the build farm are themselves trustworthy. A compromised compiler or base image backdoors every package built with it (the classic "trusting trust" problem), and a compromised central builder can sign attestations for artifacts it did not faithfully build. This trusted computing base is in scope as an assumption, not a solved problem. Mitigations are partial: N-of-M independent reproducible builds so no single builder is authoritative, bootstrappable and reproducible toolchains in the spirit of Guix's work, and signed, version-pinned, publicly described build environments. The design reduces, but does not eliminate, trust in its own build infrastructure.

## Design Overview

A safer AUR-like system separates five concepts that are often conflated:

1. **Recipe submission** — anyone can propose a package recipe or update.
2. **Maintainership** — trusted users or teams steward package namespaces.
3. **Review** — humans and automated tools evaluate risky changes.
4. **Build execution** — recipes are built in constrained environments. This is the primary containment boundary and the system's safety floor.
5. **Install privilege** — root-level hooks are treated as exceptional and dangerous, and notably run on the user's real system rather than inside the build sandbox.

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
Risk tier: high
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

### Pseudonymity and Participation

Mandatory MFA, OIDC identity, public maintainer keys, transparency logs, and public reputation create durable public linkage of contributor activity. That linkage helps trust but works against the pseudonymous long-tail contributors who are much of the AUR's base today. The design keeps identity verification optional (see Non-Goals) and relies on per-account security (MFA, scoped tokens) and behavior-based reputation rather than real-world identity where possible, requiring stronger identity only for high-impact packages.

## Reputation Model

Reputation should exist for users, packages, and the relationship between a user and a package lineage.

Reputation is user-facing, but it is not the safety floor. Mechanical signals — delta class, sandbox result, reproducibility, source-tree delta, and indicator matches — decide whether a change is safe to apply. Reputation decides how much scrutiny a change gets, who may review it, and how a package's history is shown to users. It can lower scrutiny within a risk tier but cannot lower the tier itself or waive a safety check. Because a high-reputation account can be compromised (see [Instant Trust Inversion](#instant-trust-inversion)), reputation may demote an account quickly but may never promote a change past the gates.

Reputation is expressed as capability grants rather than a single trust score, answering what an account may do, for which scope, and at which risk tier:

```yaml
capabilities:
  package/example:
    merge_low_risk: true
    merge_medium_risk: false
    approve_install_hook: false
    approve_adoption: false
  ecosystem/rust:
    review_dependency_delta: true
    review_binary_blob: false
  global:
    security_responder: false
```

Capabilities are scoped, auditable, expirable, and revocable, and they bound the blast radius of a compromised account: stolen maintainer credentials still cannot approve an install hook or an adoption the account was never granted.

A good reputation system should not ask only "is this account trusted?" It should ask:

- Trusted to do what?
- In which ecosystem?
- For which package lineage?
- At what risk tier?
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

Like reputation, the web of trust is advisory. It determines reviewer eligibility and independence, records how trust was earned, and supports fast revocation when an edge is implicated; the gates still decide whether a change can be applied. Its main use during an incident is the reverse direction: tracing and quarantining related accounts, edges, and packages.

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
- Risk tier.
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

### The Manifest Is an Enforced Allowlist

The manifest is an enforced allowlist. The sandbox treats every field as a capability boundary: a build declared `network: false` runs with egress denied at the network layer, and any undeclared-but-attempted capability — network, `$HOME` access, a package-manager invocation — fails the build and is recorded in the attestation. A declaration the sandbox does not enforce is worse than none, because it gives false assurance. The manifest declares what a package needs; the sandbox enforces it.

Network access follows the fixed-output model used by Nix derivations: it is allowed only during a fetch phase whose outputs are pinned by hash, and denied during `prepare()`, `build()`, and `package()`. Undeclared code cannot be fetched during build, which is what stops the Atomic Arch `npm`/`bun install` step regardless of how the command is written.

### Capability Baseline and Per-Update Capability Delta

A manifest describes one revision. Because risk is about change, each package lineage also carries a capability baseline — the capabilities its accepted revisions have used:

```yaml
baseline:
  source_domains:
    - github.com/upstream/project
  build_systems:
    - cmake
  external_package_managers: []
  build_network: false
  install_hooks: false
  privileged_features: []
```

Every proposed update is reduced to a machine-readable capability delta against that baseline. The delta, rather than the raw PKGBUILD, drives classification and is what reviewers and users see:

```yaml
capability_delta:
  added:
    external_package_managers: [npm]
    install_hooks: [post_install]
  risk_effect:
    tier: critical
    reasons:
      - new cross-ecosystem dynamic installer
      - new root-time install hook
      - added after maintainer change
```

This gives stable policy rules ("a new external package manager in a package with no such history is critical") and is easier to review than a textual diff. The capability delta is a field of the `RecipeRevision` and `AnalysisReport` objects (see [Core Object Model](#core-object-model)).

### Nested Package Managers Are Untrusted Source Fetchers

In Atomic Arch the malicious behavior was not in the recipe; the recipe invoked `npm`, and the payload arrived through npm's lifecycle scripts. The design treats `npm install`, `pip install`, `bun install`, `cargo install`, `go install`, `curl`, `wget`, and `git clone` during build or install as source acquisition, not build commands, and disallows them unless modeled explicitly.

Where a package needs language-ecosystem dependencies, they must be modeled explicitly rather than resolved dynamically:

```yaml
language_sources:
  npm:
    registry: https://registry.npmjs.org
    lockfile: package-lock.json
    lifecycle_scripts: disabled
    packages:
      - name: minimist
        version: 1.2.8
        integrity: sha512-...
```

Dependencies come from a pinned registry and lockfile with integrity hashes, and lifecycle scripts are disabled by default, which is what would have stopped the `preinstall` hook that ran the Atomic Arch ELF. Disabling lifecycle scripts breaks some builds; such a build then requires explicit review rather than silently gaining trust.

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

### Building From Version Control

A checksum confirms that bytes did not change after the maintainer pinned them, not that those bytes match what upstream develops in the open. The xz/liblzma backdoor (CVE-2024-3094) used this gap: the malicious code was in the release tarball (a fake test file and an obfuscated `m4` build-script change) and not in the project's git repository. A recipe pinning the poisoned tarball's hash would pass every byte-integrity check and every "routine version bump" rule.

Therefore:

- Prefer building from an immutable VCS revision (a commit SHA, or a signed tag resolved to a commit) over a release tarball.
- Where a release tarball is used, fetch the corresponding VCS tag and diff the two. Files present in the tarball but absent from VCS — generated build scaffolding, vendored blobs, test fixtures executed at build time — are where this class of attack hides and should be surfaced as a high-risk signal.
- Treat a discrepancy between tarball and VCS as a trust-boundary change, even when the version number and the recipe are otherwise unchanged.

## Binary and Vendor-Artifact Packages

Source-tree delta, build-from-VCS, and reproducible source builds assume the package builds from source. Much of the AUR does not: `*-bin`, AppImage, container-image, firmware, and font packages ship a pre-built artifact, so those controls do not apply and the package needs different evidence.

Each package declares its source kind:

```yaml
source_kind: source | upstream_binary | appimage | container_image | firmware | font | kernel_artifact
```

For any non-source kind, the evidence is artifact provenance rather than build reproducibility:

```yaml
binary_source_policy:
  hash_pinned: true
  vendor_identity_required: true
  upstream_signature_required_if_available: true
  extracted_artifact_diff_required: true     # diff unpacked contents across versions
  embedded_autostart_detection: true         # systemd units, desktop autostart, profile scripts
  bundled_library_inventory: true
  never_low_risk_on_first_introduction: true
```

A version bump of a binary package is not a routine source bump and is never auto-eligible on first introduction. After a stable history it may auto-publish on different evidence: a stable vendor identity and signature, an unchanged source origin, an extracted-artifact diff with no new autostart or executable surface, a malware scan, and package reputation.

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

Static analysis routes review effort and makes risky deltas legible. It does not stop attacks on its own — the sandbox does — because pattern matching can be evaded, as the Atomic Arch second wave showed within 48 hours. Socket.dev runs close to this analysis for npm and PyPI today (flags for newly added install scripts, network or filesystem access, obfuscation, and suspicious new dependencies); its design and failure modes are worth studying before reimplementing.

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

### Trust Inversion and Taint

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

Routine version bumps can usually be fast-tracked, but they should still be scanned, logged, and made easy to inspect. "Routine" describes the recipe delta only. The same version bump can still carry an anomalous source-tree delta (see below), in which case it is not low risk regardless of how clean the recipe looks.

### Source-Tree Delta

Risk classification must consider what changed in the *extracted source*, not only what changed in the recipe. A version bump that updates the recipe in an entirely routine way can still pull in a source tree that differs from the previous version in suspicious ways, and the other taxonomy classes — all defined in terms of the recipe — would miss it. This is the class that recipe-only review waves through, and the class that upstream-compromise attacks such as xz depend on.

The system should diff the extracted source between the previous and proposed versions and flag:

- New or modified build scaffolding: `configure`, `Makefile.in`, `*.m4`, `autogen.sh`, `build.rs`, `setup.py`, and similar files that execute at build time.
- New binary blobs, large generated or minified files, and test fixtures or sample data that are executed or linked during the build.
- Source-tree contents present in a release tarball but absent from the corresponding VCS tag (see [Building From Version Control](#building-from-version-control)).
- Large or structurally unusual diffs relative to the upstream change between the same two tags.

A clean recipe delta combined with an anomalous source-tree delta should raise the risk tier.

Source-tree diffs are noisy: generated `configure` scripts, vendored JavaScript, minified assets, generated protocol-buffer code, and lockfiles change routinely. Classification uses deterministic metrics rather than a single "large diff" heuristic:

```yaml
source_tree_delta:
  metrics:
    - files_added
    - executable_files_added
    - binary_files_added
    - generated_build_scaffolding_changed
    - tarball_only_files            # present in tarball, absent from VCS tag
    - build_executed_test_fixtures
    - minified_or_obfuscated_files_added
    - diff_size_percentile_for_project
  policy:
    anomalous_delta: medium
    tarball_only_executable_build_logic: high
    new_binary_executed_during_build: critical
```

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

## Ownership Transition vs Content Change

The Atomic Arch pattern was adoption immediately followed by a behavior-changing update, riding the trust of the old package name. The defense is to make ownership transition and content change separate transactions that cannot be combined.

- **The adoption event grants stewardship only.** It may request the maintainer role, prove intent, and pass cooldown — but it may not, in the same event, add or change install hooks, add dynamic installers, change the source trust boundary, or add network access.
- **The first post-adoption update is auto-eligible only if it is a strict routine version bump.** Every other delta from a freshly adopted package requires independent review regardless of the new steward's reputation, which is necessarily low or inherited.

```text
Adoption event:
  allowed:     request stewardship, prove intent, receive limited maintainer role
  not allowed: add hooks, add dynamic installers, change source trust boundary, add network

First post-adoption update:
  auto-allowed only if: strict routine version bump
  all other deltas:     independent review required
```

This makes "newly adopted" a hard precondition rather than a risk score that can be outweighed: the event the campaign relied on cannot be expressed as a single transaction. It complements the adoption cooldown and maintainer-lineage warnings.

## Default-Deny Publication Rules and Escalation Paths

Some change classes should be refused by default on the server, not only surfaced as a client warning. Warnings are for unusual but plausibly benign behavior; default-deny is for classes where the safe answer is almost always no.

```yaml
deny_by_default:
  - confirmed malicious indicator match
  - new or changed .install hook within N days of adoption
  - dynamic package-manager invocation from an .install hook
  - new npm/pip/bun/cargo/go install in a package with no prior ecosystem relationship
  - build-time network access unless declared and reviewed
  - access to the real $HOME, SSH keys, browser profiles, or credential stores
  - new eBPF, DKMS, kernel module, setuid/setgid, systemd unit, timer, or autostart
  - source URL moved across a trust boundary
```

These are default-deny, not forbidden. Many legitimate packages are DKMS modules, install systemd units, or need a language ecosystem. Default-deny means the change is never auto-published, but it can still proceed through an escalation path: the capability declared in the manifest, an elevated review by a scoped reviewer, hook simulation, and a signed gate record. A hard block is the stronger case, an outright refusal with no escalation path, reserved for confirmed malicious indicators and violations that cannot be mitigated. Keeping hard blocks rare (see [Social and Governance Risks](#social-and-governance-risks)) prevents the policy from degrading into prompt fatigue.

## Automation and the Labor Model

Every "requires review" in this document spends a scarce resource: human reviewers. The likely failure mode is an unstaffed control rather than a defeated one. Fedora and Debian run multi-year maintainer shortages at a fraction of the AUR's package count. cargo-crev built the same kind of distributed code-review web of trust proposed here, and its limiting problem was coverage: most crates have zero reviews, so the graph is empty where a user needs it. AUR's response to the ~1,500-package incident was manual cleanup, because it has no review capacity and no automation.

If human review is on the critical path for a meaningful fraction of routine updates, queues grow to weeks and users route around the system back to raw recipes, or the small reviewer pool becomes a bottleneck to capture or collude with.

The design takes a measurable position:

- **The common case is auto-decidable with no human in the loop.** A strict version bump built reproducibly in a default-deny sandbox, with no source-tree anomaly, no capability change, no install-hook change, and no indicator match, auto-publishes. The sandbox prevents exfiltration and secret theft during build, reproducibility confirms the artifact matches the recipe, and the source-tree delta confirms no foreign build logic was added. None of this needs a person.
- **Human review is reserved for the irreducible cases:** a new or changed install hook, a new capability, a source or trust-boundary change, an orphan adoption, or an indicator near-match. These should be a small minority of daily traffic.
- **"Fraction of updates requiring human review" is a tracked KPI,** with an explicit target (for example, well under 5%). If it climbs, the analysis and containment layers, not the reviewer pool, are what must improve.

For the common case, automation replaces review rather than assisting it, because containment is what makes that case safe. Review then concentrates where containment cannot help: install-time and source-tree risk.

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

Automation should auto-decide the common low-risk case (see [Automation and the Labor Model](#automation-and-the-labor-model)), since containment is what makes it safe. For risky deltas, automation routes and explains review rather than granting trust from reputation alone.

Review queues should be specialized rather than one backlog: cross-ecosystem (Node, Python, Rust) changes go to reviewers with that context, kernel/eBPF/DKMS changes go to kernel-aware reviewers, and new binary blobs go to provenance reviewers. Routing follows the capability delta, so a reviewer sees only changes they are scoped to judge. This avoids a single generalist reviewing everything.

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

The sandbox enforces the recipe manifest: it is configured from the declared capabilities, and any attempt to exceed them fails the build and is recorded in the attestation. This closes the build-time credential-theft and undeclared-fetch channels by construction, whether or not static analysis recognizes the specific attack.

The guarantee is bounded: the sandbox protects the build host and the builder's secrets, not the resulting package. A backdoor in upstream source, a patch, or a release tarball builds normally, and reproducibly, inside the sandbox. Install hooks run on the user's real system, not in the sandbox, so they are outside the guarantee too. Those risks are handled by source-tree delta analysis, build-from-VCS provenance, and install-hook review.

### Central Builders and Local Builders

The system should support both central analysis builders and local user builds.

- Central builders provide consistent automated analysis, public logs, artifact hashes, and reproducibility checks.
- Independent builders provide diversity and reduce trust in a single build farm.
- Local builders give users control but should use the same sandbox policy and metadata checks.
- Binary caches may be offered, but clients should verify signatures, provenance, and policy before installation.
- A locally built package should still inherit repository risk metadata, indicator checks, and maintainer-history warnings.

This combines Nix/Guix-style build isolation with a community-repository workflow while avoiding a hard dependency on either central binaries or unsafe local builds.

The pre-distribution gate requires a central sandboxed build of every submission before publication. This has costs worth naming:

- Anyone can submit a recipe the build farm must build, so the farm needs per-account quotas, resource limits, timeouts, and abuse detection, and must absorb burst load (Atomic Arch was roughly 1,500 packages in days).
- Distributing built binaries, even only for analysis or as an optional cache, is a shift away from AUR's recipes-only posture, with storage, signing, and liability obligations.
- Reproducibility lets independent and local builders check central output instead of trusting it, so the farm should be verifiable rather than a single point of trust. rebuilderd (deployed for Arch and Debian) is the natural mechanism and should be reused.

The [Adoption Path and Compatibility](#adoption-path-and-compatibility) section discusses how to bound this cost by migrating high-impact packages first instead of building the entire AUR centrally on day one.

Because every submission triggers a build, the farm rejects or defers expensive work before spending CPU:

```yaml
build_farm_controls:
  cheap_static_prefilter_before_build: true
  new_account_build_quota: low
  high_cost_builds_require_reputation: true
  content_addressed_fetch_cache: true
  repeated_failure_penalty: true
  per_ecosystem_resource_limits: true
  timeout_profile_by_package_kind: true
  no_unbounded_test_suites: true
```

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

These levels should be mapped onto SLSA build levels rather than maintained as a parallel vocabulary, so the system inherits shared, well-understood terms (provenance, hermeticity, isolated build, two-person review) instead of a bespoke ladder. "Provenance-attested" corresponds to SLSA provenance requirements; the hermetic, default-deny sandbox build corresponds to higher SLSA build levels; N-of-M reproducibility is the cross-check that makes those claims verifiable. rebuilderd is the natural reproducibility backend.

## Install Hooks

### Build-Time Versus Install-Time Privilege

Build scripts and install hooks are different threat classes and must be governed separately. A build can be fully sandboxed: no host secrets, no real `$HOME`, no network after the pinned fetch phase, and no root. An install hook is worse, because it runs at install or upgrade time on the user's real system, frequently as root, outside any build sandbox. The design rule is therefore:

> A community package may not introduce or materially change root-time behavior without elevated review, explicit user-facing capability labels, and hook simulation.

### Declarative Install Actions

Common install-time needs should be declarative, so they can be analyzed and constrained instead of run as opaque shell:

```yaml
install_actions:
  systemd_units: { install: [example.service], enable_by_default: false }
  sysusers: [example]
  tmpfiles: [example.conf]
  icon_cache_update: true
  desktop_database_update: true
```

A package built only from declarative actions needs no arbitrary hook. An arbitrary `.install` hook is allowed only through an explicit gate:

```yaml
arbitrary_install_hook:
  default: deny
  allowed_only_with:
    - explicit_manifest_capability
    - security_reviewer
    - hook_simulation
    - user_visible_capability_label
    - signed_gate_record
```

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
  # Objective safety gates: all required. Reputation cannot waive any of these.
  safety_gates:
    max_risk_tier: low
    signed_gate_record: true
    static_analysis_passed: true
    sandboxed_build_passed: true
    reproducible: true
    no_source_tree_anomaly: true
    no_new_install_hooks: true
    no_new_dynamic_installers: true
    no_source_trust_boundary_change: true
    no_confirmed_indicator_matches: true
  # Reputation fast-track: may only speed up an already-safe change, never lower a gate.
  fast_track:
    min_package_reputation: established
    min_submitter_reputation: package_contributor
    min_clean_age_days: 30
    install_count_as_evidence_only: 1000

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

These thresholds fall into two distinct kinds that must not be conflated:

- **Objective safety gates** (risk tier, signed gate record, passed static analysis, passed sandbox build, reproducibility, no source-tree anomaly, no new hooks or dynamic installers, no trust-boundary change, no indicator match) decide whether the change *can* be auto-applied safely. Reputation can never waive these.
- **Reputation and adoption signals** (package reputation, submitter reputation, clean age, install count) decide whether an already-safe change can skip a *queue* or a cooldown. They speed up a safe change; they do not make an unsafe one eligible.

An attacker who farms reputation, or who compromises a high-reputation account, must still clear every objective gate, and those gates are what the sandbox and analysis layers enforce.

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

## Adoption Path and Compatibility

A hardened design only matters if it reaches users, and a parallel ecosystem that requires a flag day — new helpers, new infrastructure, and mass migration at once — is likely to lose to the network effects of the existing AUR. The pragmatic path is an incremental overlay rather than a replacement:

- Run the analysis, sandbox-build, and gate machinery as a service that sits *in front of* the existing AUR, producing signed risk metadata and gate records for packages as they are migrated or as updates are observed.
- Extend existing helpers (paru, yay) to read and enforce those gate records and risk metadata when present, with graceful fallthrough to current behavior for packages that have not been migrated. The near-term win condition is "paru learns to read a signed gate record," not "everyone switches to a new tool."
- Migrate high-impact and frequently-installed packages first, so the most-used surface gets coverage soonest, and let coverage grow without blocking the long tail.
- Treat the transparency log and indicator feed as independently consumable: even a user on stock tooling should be able to subscribe to the malicious-indicator feed and benefit from confirmed detections.

This also bounds the cost discussed under [Central Builders and Local Builders](#central-builders-and-local-builders): coverage can expand with available build and review capacity instead of requiring the entire AUR to be built centrally on day one.

### Bootstrapping Baselines for Migrated Packages

The capability-baseline model assumes a vetted history, but a migrated AUR package has none. Importing its current behavior as the baseline would treat whatever it does today as historical and launder old risky recipes into the new system.

A migrated package enters through an explicit bootstrap record:

```yaml
BaselineBootstrap:
  package: example
  imported_revision: sha256:...
  source: legacy_aur
  trust_state: probationary
  baseline_method:
    - last_known_clean_revision
    - automated_history_scan
    - maintainer_attestation
    - reviewer_confirmation_for_high_impact
  rechecks_after: ...
```

A low-impact package can be seeded from an automated history scan. A high-impact package requires explicit review, or a clean gate record plus an aging period, before its baseline is treated as established. Until then the package is probationary, and any capability beyond the imported set is treated as new.

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

### Due Process for Privileged Actions

Freeze, quarantine, and revocation are powerful, and they are themselves an abuse and censorship vector: unilateral, unappealable freeze authority is its own threat. Privileged actions should therefore be constrained as carefully as they are enabled:

- Emergency freezes in response to a confirmed malicious indicator may be unilateral and fast, but must be logged to the transparency log and subject to after-the-fact review.
- Freezes that are not backed by a confirmed indicator should require a second responder or a quorum.
- Every freeze, quarantine, and trust inversion must carry a stated reason, an audit record, and a defined appeals path for the affected maintainer, including the case of mistaken or malicious attribution.
- The same anti-collusion and independence requirements applied to high-risk approvals apply to responders, so that responder authority cannot be captured.

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
- Apply trust inversion and quarantine to implicated accounts and packages.
- Show detection guidance.
- Provide rollback instructions.

## Limitations and Residual Risk

This design reduces the attack surface that Atomic Arch and similar campaigns exploit. It does not make community packages safe. The limits:

- **Upstream and source compromise.** Containment protects the build host, not the artifact. A backdoor in upstream source, a malicious patch, or a poisoned release tarball (the xz/liblzma pattern) builds successfully and reproducibly. Source-tree delta, build-from-VCS, and tarball-vs-VCS diffing narrow this gap but cannot close it; a sufficiently patient attacker who commits malicious code to the real upstream repository defeats all of them.
- **Reproducibility proves matching, not benignity.** N-of-M reproducible builds prove every builder produced the same artifact from the same recipe. They say nothing about whether that artifact is malicious. Reproducibility defends against build-farm and toolchain tampering, not against a poisoned input.
- **Install-time and runtime behavior.** Hooks run on the user's real system, and installed software runs with the user's real privileges and credentials. The design treats hooks as critical-risk and simulates them, but cannot contain what the user deliberately installs and runs. Downstream application sandboxing is the appropriate mitigation and is out of scope.
- **Trusted computing base.** See [Trusted Computing Base](#trusted-computing-base). The build infrastructure is trusted and is a residual risk.
- **The patient defector.** Review, signing, and reputation do not stop an attacker who builds a useful package, accrues real trust over months, and then ships one malicious update, or sells the package to someone who does. The browser-extension ecosystems (Chrome Web Store, AMO), which have review, signing, and reputation, are repeatedly defeated by this "build trust, then defect" pattern. This is the same maintainer-defect and orphan-adoption threat with patience and money attached. The controls here raise its cost and limit its blast radius (containment limits build-time damage, instant inversion limits persistence) but do not eliminate it.

These limits set the priority order: invest most in the controls that hold against obfuscation (containment, reproducibility, source-tree provenance), and treat detection, reputation, and review as layers that triage, explain, and respond.

## Core Object Model

These are the first-class objects the system stores and signs. Clients and policies are defined against them.

```yaml
PackageNamespace:
  name: alvr
  upstream_identity: github.com/alvr-org/ALVR
  lineage_id: sha256:...        # stable across renames; trust attaches here, not to the name
  current_stewards: [user:...]
  baseline: { ... }             # capability baseline (see Recipe Format)
  trust_state: probationary|established|frozen|quarantined

RecipeRevision:
  package: alvr
  recipe_hash: sha256:...
  source_hashes: [sha256:...]
  submitted_by: user:bob
  delta_from_previous: sha256:...
  capability_delta: { ... }
  requested_capabilities: [ ... ]

TrustEvent:
  type: maintainer_added|adoption_approved|review_approved|package_frozen|...
  actor: user:...
  subject: package:...|user:...
  scope: low_risk_merge|install_hook_review|orphan_steward|...
  expires: ...

AnalysisReport:
  recipe_hash: sha256:...
  static_findings: [ ... ]
  sandbox_findings: [ ... ]
  dependency_findings: [ ... ]
  risk_tier: low|medium|high|critical
  machine_readable_reasons: [ ... ]

GateRecord:
  recipe_hash: sha256:...
  artifact_hash: sha256:...
  risk_tier: high
  verdict: allow|deny|quarantine
  required_approvals: [ ... ]
  actual_approvals: [ ... ]
  expires: ...
  signature: ...
```

The client installs a revision only after verifying a `GateRecord` whose verdict, risk tier, and approvals satisfy local policy and whose hashes match what is about to be built or fetched. The gate record is the single check that ties recipe, analysis, approvals, and artifact together.

### Event Authority and Watchers

Two rules make the event model trustworthy:

- **The signed event log is authority; Git metadata is only evidence.** Atomic Arch coverage noted spoofed commit author and committer fields, so a change could appear to come from a long-standing maintainer. The registry must therefore record its own signed, append-only `TrustEvent`s keyed on the authenticated `server_actor` (with the authentication method and any step-up assurance), and the UI must privilege that actor over Git author text. Git history is useful evidence; it is never the authority for a trust decision.
- **A transparency log needs watchers.** Append-only logs (like Go's checksum database and Sigstore's Rekor) make events tamper-evident, which is not the same as safe. The value comes from watchers on the log:

```text
- notify upstream when a package claiming its namespace changes maintainer
- notify subscribers when a dormant package revives
- notify reviewers when many packages add the same new dependency
- notify security responders when "adoption + new dynamic installer" recurs
```

Watchers turn campaign correlation into early warning rather than after-the-fact reconstruction.

## Worked Policy Examples

Two end-to-end examples, also usable as fixtures for the risk-classification and gate-record specs.

### Atomic-Arch-like update (deny)

```yaml
package: example
events:
  maintainer_changed_within_days: 2
  dormant_for_days: 420
delta:
  new_install_hook: true
  new_external_package_manager: npm
  new_dependency: atomic-lockfile
  package_historical_ecosystems: []
classification:
  risk: critical
  verdict: deny
  reasons:
    - newly adopted package (ownership transition cannot carry a behavior change)
    - new root-time install hook
    - new cross-ecosystem dynamic installer
    - dependency not historically related to the package
required_to_proceed:
  - security_reviewer
  - orphan_steward
  - ecosystem_reviewer: npm
  - cooldown
  - disabled lifecycle scripts or a mirrored, pinned dependency source
```

### Routine version bump after stable maintainership (allow)

```yaml
package: example
events:
  maintainer_lineage_stable_days: 900
delta:
  version_changed: true
  source_url_pattern_unchanged: true
  source_hash_changed: true
  build_logic_changed: false
  dependencies_changed: false
  install_hooks_changed: false
  source_tree_anomaly: false
classification:
  risk: low
  verdict: allow
required:
  - static_scan_pass
  - sandbox_build_pass
  - valid_source_hash
  - reproducible_build
```

## Social and Governance Risks

The technical controls fail if the social system around them does. The design should explicitly defend against:

- **Reviewer capture.** A cluster of accounts could vouch for each other and approve risky changes. Require independent trust paths, account age, ecosystem diversity among approvers, and reviewer-reputation loss for approvals later shown to be malicious.
- **Maintainer exhaustion.** Flooded maintainers ignore the system. The auto-decidable common case, narrow capability deltas instead of raw PKGBUILD diffs, and low-risk fast paths exist to keep human attention scarce where it matters (see [Automation and the Labor Model](#automation-and-the-labor-model)).
- **Prompt fatigue.** Users click through warnings they see too often. Default clients auto-allow only low-risk established updates, step through medium risk, and hard-block critical patterns unless policy is explicitly changed — so prompts stay rare and meaningful.
- **False positives.** Hard blocks are reserved for high-confidence indicators only: exact malicious hashes, exact payload signatures, known-bad package versions, and confirmed C2 domains. Heuristics produce soft flags, not blocks, and the indicator feed needs a published appeal-and-correction path.
- **Privacy.** Package reputation must not depend on invasive install telemetry. Prefer public, low-linkage signals — package age, clean gate history, reproducible-build status, maintainer lineage, incident history — and treat install counts as opt-in or privacy-preserving aggregates used only as supporting evidence (see [Pseudonymity and Participation](#pseudonymity-and-participation)).

## Minimum Viable Version

Controls that hold against obfuscation come first; trust, transparency, and UX build on a foundation that is already safe by construction. Reputation and web-of-trust come last, since they need a corpus of trustworthy events before they can be computed without being gamed. A practical first version, in roughly this order:

### MVP-0 — AUR safety shim (no server required)

The earliest useful deliverable needs no new infrastructure: a client-side shim over the existing AUR that already removes the most common risk.

1. Local sandboxed build with no real `$HOME` and default-deny network after the fetch phase.
2. A static scanner for `.install` hooks, `curl | sh`, and `npm`/`pip`/`bun`/`cargo`/`go install` / `git clone` during build or install.
3. A subscribable known-malicious indicator feed.
4. Maintainer-change and orphan-adoption warnings.

This is the overlay described in [Adoption Path and Compatibility](#adoption-path-and-compatibility): it ships value before any server-side gate exists. As a concrete contract:

```text
baur-shim
  input:   AUR package name, or a local PKGBUILD directory
  output:  risk report; sandboxed build result; blocked network attempts;
           hook presence and diff; maintainer-change warning
  default: refuse real $HOME; refuse build network after source fetch;
           refuse install hooks unless the user switches mode
```

### Phase 0 — Containment foundation (highest leverage)

1. Sandboxed builds with default-deny network egress and no access to the user's real `$HOME` or secrets, for both central and local builds.
2. An enforced recipe manifest: declared capabilities are the sandbox's allowlist, and any undeclared-but-attempted capability is a hard build failure.
3. Fixed-output fetch model: network only during a hash-pinned fetch phase, denied during build.
4. Source-tree delta analysis, with build-from-VCS and tarball-vs-VCS diffing.

### Phase 1 — Gate, analysis, and provenance

5. Static recipe scanner producing a risk report (triage, not gate).
6. Automated sandboxed analysis pipeline with canary secrets and egress logging.
7. Delta-based risk classification metadata, covering both recipe delta and source-tree delta.
8. Mandatory signed pre-distribution gate records for every published update.
9. Content-addressed hashes binding recipe, source, analysis, build output, and metadata.
10. Build attestations and reproducibility checks, reusing rebuilderd; map attestation levels to SLSA.

### Phase 2 — Trust, response, and legibility

11. Public maintainer history and adoption cooldowns.
12. Mandatory MFA for maintainers; OIDC Trusted Publishing for automated submissions and attestations.
13. Bulk adoption and update rate limits.
14. Basic user and package reputation metadata (for legibility and routing, not the safety floor).
15. Signed global malicious-indicator feed.
16. Trust inversion and quarantine for confirmed malicious submissions and approvals, with due process.
17. Risk-based confirmation requirements and a high-risk review queue, with an auto-decidable common case and a tracked human-review-rate KPI.
18. Helper warnings and provenance/status UI for recent adoption, reputation changes, new hooks, source changes, dynamic installers, and indicator matches.

### Phase 3 — Ecosystem hardening

19. TUF-style signed repository metadata with expiry and rollback protection.
20. Append-only transparency log for package events and trust changes.
21. Overlay compatibility so existing helpers (paru, yay) consume gate records and risk metadata for migrated packages.

## Open Questions

- What should the default adoption cooldown be?
- Which packages count as high impact?
- How should user reputation be calculated without becoming a popularity contest?
- How should package reputation be calculated without becoming a popularity contest? (See OpenSSF Scorecard in Prior Art for objective repo-health seeds.)
- How much should routine version bumps contribute to reputation?
- Which events should decay, reset, or put package reputation into probation?
- Which malicious indicators should be hard blocks versus soft review flags?
- How should false positives in the global indicator feed be appealed and corrected?
- How should trust inversion handle compromised accounts versus deliberate malicious actors?
- How should the system detect reputation farming, sybil accounts, and collusive review rings?
- Who can approve high-risk changes?
- How many reviewers should be required for orphan adoption?
- How strict should default client policy be?
- Should community-built binaries be allowed, or should users always build locally?
- How should forks and abandoned upstream continuations be represented?
- What recipe language balances safety and flexibility?
- How do we prevent review bottlenecks? (See [Automation and the Labor Model](#automation-and-the-labor-model); the common case must be auto-decidable.)
- How do we avoid excluding casual contributors?
- How should the central build farm be funded and protected from resource-exhaustion abuse?
- What is an acceptable false-positive rate for source-tree delta and tarball-vs-VCS diffing?
- How is the auto-decidable-update KPI measured, and what target is acceptable?
- How are gate records and risk metadata best surfaced to existing helpers (paru, yay) during incremental migration?

### Next Step: Two Concrete Specs

The next step is to split this working draft into an architecture overview plus implementable specs, which the [Core Object Model](#core-object-model) and [Worked Policy Examples](#worked-policy-examples) already begin:

1. **Risk Classification Spec** — the phase model, capability and delta taxonomy, risk tiers, default-deny rules, and required confirmations per tier.
2. **Gate Record Spec** — the object schemas, signatures, hash binding, expiry, and the client verification algorithm.
3. **Client Policy Spec** — the default, strict, and enterprise modes, warnings, override behavior, and local sandbox requirements.

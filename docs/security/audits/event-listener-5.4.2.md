# event-listener 5.4.2 release-delta audit

**Decision:** reviewed for the safe-to-deploy criterion used by this workspace.

**Scope:** upstream smol-rs/event-listener v5.4.1 to v5.4.2, including the crate manifest, changelog, src/lib.rs, src/intrusive.rs, and removal of the slab/node implementation.

## Soundness correction

Release 5.4.2 addresses [RUSTSEC-2026-0221](https://rustsec.org/advisories/RUSTSEC-2026-0221.html) and upstream [PR #163](https://github.com/smol-rs/event-listener/pull/163): StackSlot<T>'s Send and Sync implementations are now conditional on T: Send. The prior unconditional implementations could let a !Send tag cross threads through safe APIs. The correction aligns the auto-trait guarantee with the tag's thread-safety.

## Synchronization and unsafe-code review

- Reviewed the Event<T>, EventListener<T>, and InnerListener<T, B> unsafe Send/Sync implementations in the release source; their trait bounds remain tied to T: Send and the corresponding storage/borrow bounds.
- The release switches from the slab-backed implementation to the intrusive linked-list implementation. Reviewed the changed list insertion/removal/notification paths and the unsafe pointer accesses that they use.
- The newly added spinlock is compiled only when neither std nor critical-section is enabled. It acquires the atomic flag with Acquire ordering, releases with Release ordering, and uses an RAII guard so the lock is released during unwinding.
- Upstream explicitly warns that this no-std, no-critical-section spinlock configuration is dangerous for production because spinning can harm liveness under preemption. The Xenia workspace uses the default std feature configuration; this audit does not endorse disabling both synchronization backends for a production target.
- The change removes the slab/concurrent-queue fallback and updates feature wiring and documentation accordingly.

## Boundary

This is a source review of the exact upstream release delta, not a substitute for this repository's fresh exact-head build, tests, or runtime qualification. The workspace's existing cargo vet --locked check remains required. If a target later enables neither std nor critical-section, reassess that configuration before deployment.

References: [v5.4.2 release notes](https://github.com/smol-rs/event-listener/releases/tag/v5.4.2), [RUSTSEC-2026-0221](https://rustsec.org/advisories/RUSTSEC-2026-0221.html).

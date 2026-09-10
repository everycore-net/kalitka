# Contributing to kalitka

Thanks for wanting to help. kalitka is a small, security-critical codebase, so the
bar is "boring and correct" over clever.

## License and the CLA

kalitka is licensed under **AGPL-3.0-or-later** (see [LICENSE](LICENSE)), and is
also offered under a separate commercial license. To keep both possible, every
contribution is made under our [Contributor License Agreement](CLA.md): by opening
a pull request you agree to it. You keep ownership of your work; you grant us the
right to ship it under AGPL and under other terms.

Also sign off each commit under the [Developer Certificate of Origin](https://developercertificate.org/):

```
git commit -s -m "..."
```

which adds a `Signed-off-by:` line certifying you wrote (or may submit) the change.

## Building and testing

```
dotnet test           # from the repo root; all tests must pass
```

The suite is fast and deterministic (time is injected via `TimeProvider`). Add
tests with the change, especially for anything touching auth, sessions, tokens,
the access lists, or the durable stores — those are where a subtle bug is a
security bug. Prefer tests that assert the failure path, not only the happy one.

## Style

- Match the surrounding code: minimal dependencies, readable core over frameworks.
- Comments explain **why**, not what — in security code the "what" is usually
  obvious and the "which failure this prevents" is not.
- Keep the seams (`INotifier`, `IRequestStore`, `IReplayStore`, `ISessionStore`,
  `IAuditStore`, `IAtomicWork`) intact; extend along them rather than around them.

## Scope of changes

Open an issue first for anything that changes behaviour, a public seam, or the
security posture. Small fixes and docs can go straight to a PR.

## Security

Do not open a public issue for a vulnerability — see [SECURITY.md](SECURITY.md).

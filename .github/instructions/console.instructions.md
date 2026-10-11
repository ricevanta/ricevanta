---
applyTo: "console/**"
excludeAgent: "cloud-agent"
---

Review against [Vue rules](../../instructions/vue.md), [console foundation](../../docs/specs/console-foundation.md) and [testing rules](../../instructions/testing.md#console).

- Check exact dependency/toolchain pins, frozen installs, disabled lifecycle scripts in [pnpm-workspace.yaml](../../console/pnpm-workspace.yaml), and resolved [license evidence](../../docs/licensing.md) outside ignored `node_modules/` or build output.
- Check TypeScript coverage of application, tooling and tests, allowed declaration files, validated `unknown` inputs, component ownership and disposal of listeners. Check English/Vietnamese keys and accessible names, focus and keyboard behavior together.
- Verify axe and other tool calls against the pinned API. Ensure axe scans the mounted component iframe and its negative control detects a known violation; a scan of an empty host cannot establish accessibility.
- Check CSP and Trusted Types against the production build and exact header contract. Require effective negative controls and the specified rejecting directive; never weaken the production policy for axe or test instrumentation.
- Match cache headers to the serving contract: HTML, manifest-declared assets, other assets, brand files and compressed variants. A filename that looks hashed does not establish manifest membership.
- Check every required command in [console.yml](../workflows/console.yml) against the testing instructions. Browser and extended checks use CI evidence, not local review requirements.

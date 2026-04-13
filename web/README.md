# audit-checklist web explorer

A static, zero-build companion site to the Foundry library. One page per
check showing:

- What it detects.
- How the check runs internally.
- The hooks you need to implement.
- The actual bug in `VulnerableVault` that it flags.
- A one-liner to run that check against the shipped demo.

## Run locally

```bash
python3 -m http.server -d web 8080
# open http://localhost:8080
```

## Deploy

Pure static files — no build, no JS dependencies. Works unchanged on
GitHub Pages, Cloudflare Pages, or any static host.

## Adding a check

When you add a new check to `src/checks/`, also add an entry to the
`CHECKS` array in `index.html`. Each entry needs:

```js
{
  id: 'your-id',              // kebab-case, used in the URL hash
  name: 'YourCheck',          // matches the Solidity contract name
  blurb: 'One-line summary',  // shown in the sidebar
  severity: 'high',           // 'high' | 'med' | 'low'
  file: 'YourCheck.sol',
  detects: '...',
  how: '...',
  hooks: [[signature, description], ...],
  bug: { title: '...', code: '<html-escaped solidity>' },
}
```

Keep it in the same order as the README's "Vulnerability classes covered"
table.

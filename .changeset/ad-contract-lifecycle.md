---
"@sesamy/capsule": minor
---

Add ad-contract lifecycle to the client: `dca:rendered` / `dca:locked` / `dca:error` DOM events (with a monotonic per-`contentId` `emission` counter) emitted from content placement, the paywall path, and decrypt failures, plus a `window.dcaAds` replay global (`subscribe`, `whenRendered`) so a publisher ad adapter can bind ad demand to locked-content placement without racing it.

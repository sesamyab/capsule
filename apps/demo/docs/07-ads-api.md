# Ads API

Run dynamic ads **inside** Capsule-locked content without breaking them. This is an optional
extension on top of the core encrypt/unlock flow — reach for it only when a publisher needs ads in
premium articles. If you're not doing ads in locked content, you can skip this page.

The problem it solves: locked content is decrypted and inserted into the page *after* the entitlement
check. If an ad is requested before its slot exists (or the slot is later moved), the ad `<iframe>`
reloads and the rendered creative — plus all header-bidding and viewability state — is destroyed. The
Ads API gives you a reliable signal for *when* a slot is in its final position so your ad code runs at
exactly the right moment.

It is built from three pieces you author, plus one event stream Capsule emits:

1. **Ad markers** — inert `<div>`s inside the content that mark where ads go.
2. **An ad manifest** — cleartext JSON describing each slot (ad unit, sizes, targeting).
3. **An adapter** — your ad code, bound to Capsule's lifecycle via `window.dcaAds`.

> Capsule never calls an ad library. It provides the markers, the manifest plumbing, and the timing
> signal; your adapter owns ad demand. One orchestrator owns timing, so the races don't come back.

See it running: **[/article/ad-supported-news](/article/ad-supported-news)** has a page ad above the
lock and two ads authored inside the locked content.

---

## How it works

When the reader unlocks, Capsule decrypts the content and writes it into its **final** DOM position in
one operation, then emits a `dca:rendered` event listing the ad slots it contains. Capsule never moves
that content again, so once you've requested an ad into a marker it stays put — no iframe reload.

Because ads are requested only *after* `dca:rendered`, the slot always has real geometry. And for
readers who aren't entitled, the locked markers never exist, so their ads simply never load — no
wasted requests, no viewability burn. You get correct behaviour by construction.

---

## Quickstart

### 1. Author ad markers in the content

A marker is an inert placeholder — just a `<div>` with a slot id. It carries no ad code and no
`<iframe>`; it's a position, nothing more. Author it into the content in reading order. It travels
inside the encrypted payload and is decrypted into place on unlock.

```html
<div data-dca-ad="in-article-1"
     data-dca-ad-size="300x250"
     style="min-height:280px"></div>
```

Reserve the height (`min-height`) so the slot doesn't shift the page when the ad loads.

### 2. Publish the ad manifest

The manifest is **cleartext** JSON in the page, outside the encrypted payload — your adapter needs it
whether or not the reader is entitled, and it must be identical for every visitor so full-page caching
keeps working. Add it as a data block:

```html
<script type="application/json" class="dca-ad-manifest">
{
  "version": "1.0",
  "page": { "contentId": "post-39920" },
  "slots": [
    { "id": "in-article-1", "adUnitPath": "/1234/news/in_article", "sizes": [[300, 250]], "minHeight": 280 }
  ]
}
</script>
```

`contentId` is the value of the `publisher-content-id` attribute on the article element — Capsule uses
it to tie events to the right region.

### 3. Bind your ad code to the lifecycle

Subscribe to `window.dcaAds` and request each slot when its `dca:rendered` arrives:

```javascript
const manifest = JSON.parse(
  document.querySelector("script.dca-ad-manifest").textContent,
);
const byId = new Map(manifest.slots.map((s) => [s.id, s]));

window.dcaAds.subscribe((event) => {
  if (event.type !== "rendered") return;
  for (const id of event.slots) {
    const slot = byId.get(id);
    const el = document.querySelector(`[data-dca-ad="${id}"]`);
    if (slot && el) requestAd(el, slot); // your ad library call
  }
});
```

`subscribe` **replays** any events that already fired, so it's safe to attach late (e.g. on a cached
page where unlock resolves instantly) — you can't miss a render.

That's the whole contract. The rest of this page is the Google Ad Manager worked example and the
reference.

---

## Worked example: Google Ad Manager (GPT)

This is the adapter from the demo. It's ordinary Google Publisher Tag code — the only demo-specific
part is that `window.googletag` is a small fake stub that paints placeholder boxes instead of calling
Google. To go live, load the real `gpt.js` and delete the stub; the adapter below is unchanged.

```javascript
function startAdapter() {
  const manifest = JSON.parse(
    document.querySelector("script.dca-ad-manifest").textContent,
  );
  const byId = new Map(manifest.slots.map((s) => [s.id, s]));
  const defined = new Map();              // slot id -> googletag slot
  const renderedByContent = new Map();    // contentId -> Set(slot ids)

  googletag.cmd.push(() => {
    googletag.pubads().enableSingleRequest();
    googletag.enableServices();
  });

  // Page ads (outside the lock) have markers present at load — request now.
  for (const slot of manifest.slots) {
    if (document.querySelector(`[data-dca-ad="${slot.id}"]`)) request(slot);
  }

  // In-content ads: bind to the lifecycle.
  window.dcaAds.subscribe((event) => {
    if (event.type !== "rendered") return;

    // A late unlock supersedes the previous DOM — tear down before re-init.
    if (event.emission > 1) destroyForContent(event.contentId);

    const seen = renderedByContent.get(event.contentId) ?? new Set();
    for (const id of event.slots) {
      const slot = byId.get(id);
      if (!slot) continue;            // marker with no manifest entry — skip
      request(slot);
      seen.add(id);
    }
    renderedByContent.set(event.contentId, seen);
  });

  function request(slot) {
    const el = document.querySelector(`[data-dca-ad="${slot.id}"]`);
    if (!el || defined.has(slot.id)) return;
    if (!el.id) el.id = slot.id;       // GPT addresses slots by element id
    googletag.cmd.push(() => {
      const gptSlot = googletag
        .defineSlot(slot.adUnitPath, slot.sizes, el.id)
        .addService(googletag.pubads());
      googletag.display(el.id);
      defined.set(slot.id, gptSlot);
    });
  }

  function destroyForContent(contentId) {
    const ids = renderedByContent.get(contentId);
    if (!ids) return;
    const slots = [...ids].map((id) => defined.get(id)).filter(Boolean);
    googletag.cmd.push(() => googletag.destroySlots(slots));
    ids.forEach((id) => defined.delete(id));
    renderedByContent.set(contentId, new Set());
  }
}
```

Two things make this robust:

- **Page ads vs in-content ads** fall out naturally. A page ad's marker exists at load, so it's
  requested immediately. An in-content marker doesn't exist until unlock, so it's requested when
  `dca:rendered` reports it. No `placement` flag needed in the manifest.
- **Late unlock** (a reader who subscribes in-page) fires `dca:rendered` again with `emission > 1`.
  The adapter calls `destroySlots` for that region before re-defining, so GPT's slot state is clean and
  no iframe is orphaned.

---

## Reference

### Marker

```html
<div data-dca-ad="in-article-1" data-dca-ad-size="300x250" style="min-height:280px"></div>
```

| Attribute            | Required | Meaning |
| -------------------- | -------- | ------- |
| `data-dca-ad`        | yes      | Slot id. Unique on the page, matches a manifest `slots[].id`. |
| `data-dca-ad-size`   | no       | Size hint for CLS reservation: `"fluid"`, `"300x250"`, or a comma list. The manifest's `sizes` is authoritative. |
| `style="min-height"` | recommended | Reserved height so the ad doesn't shift layout. |

The marker element must stay inert — no `<iframe>` and no ad-request script baked in; the adapter
requests the ad *into* it after `dca:rendered`. (The locked content elsewhere may contain scripts; this
rule is only about the ad markers.) Never move a marker after its ad initializes.

### Manifest

Cleartext, cache-stable, entitlement-independent. Inline `<script type="application/json"
class="dca-ad-manifest">` is recommended (no extra request, CSP-friendly since it's data, not script).

| Field                | Required | Meaning |
| -------------------- | -------- | ------- |
| `version`            | yes      | `"1.0"`. |
| `page.contentId`     | yes      | The page's `publisher-content-id`. |
| `slots[].id`         | yes      | Matches a marker's `data-dca-ad`. |
| `slots[].sizes`      | yes      | Creative sizes as `[w, h]` pairs. |
| `slots[].adUnitPath` | —        | Demand id for your ad stack (opaque to Capsule). |
| `slots[].minHeight`  | rec.     | Reserved height (px). |
| `slots[].lazy`       | no       | Request near the viewport instead of immediately. |
| `slots[].contentId`  | no       | The locked region a slot belongs to; defaults to `page.contentId`. Use it on pages with more than one locked region. |
| `slots[].targeting`  | no       | Key/values passed through to your ad stack. |

Fields other than the above are passed through untouched, so vendor-specific keys are fine — keep them
cache-stable.

### Lifecycle events

Capsule dispatches DOM `CustomEvent`s on the `publisher-content-id` element (bubbling, so a page-level
listener works), and mirrors them through `window.dcaAds`.

```
dca:rendered  → detail: { contentId, emission, slots }
dca:locked    → detail: { contentId, reason }
dca:error     → detail: { contentId, stage, message }
```

- **`dca:rendered`** — content placed and final; request ads now. `slots` are the `data-dca-ad` ids in
  the placed content. `emission` starts at `1`; `emission > 1` means a re-render (e.g. late unlock)
  that supersedes the prior DOM — tear down that region's slots first. `contentId` is `null` when the
  page has no `publisher-content-id`.
- **`dca:locked`** — reader not entitled; locked-region markers won't exist. Do nothing for them.
  `reason` is `"no-access"` or `"no-content-id"`.
- **`dca:error`** — decrypt/fetch failed; content didn't render. `stage` is `"parse" | "unlock" |
  "decrypt" | "render"`.

### `window.dcaAds`

```javascript
// Primary integration point. Replays missed events, then forwards new ones.
const unsubscribe = window.dcaAds.subscribe((event) => { /* ... */ });

// First-render-only convenience. Cannot model re-emission — use subscribe if you
// need to handle late unlock.
await window.dcaAds.whenRendered("post-39920");
```

---

## Rules your adapter must follow

- **Request only after `dca:rendered`** (or at load for markers already present). Never request into a
  hidden or zero-area element.
- **Never move a marker** after its ad loads — re-parenting an `<iframe>` reloads it and destroys the
  creative.
- **Reserve height** (`minHeight` / the marker's `min-height`) so the decrypt-and-expand reflow doesn't
  spike layout shift.
- **On `emission > 1`, destroy the region's slots before re-initializing.** The prior DOM is gone;
  leaving slots defined orphans them.
- **Tolerate mismatches.** Initialize only ids present in *both* `event.slots` and the manifest. A
  marker with no manifest entry: skip. A manifest entry with no marker: skip until a later render
  includes it.

---

## Try it

Open **[/article/ad-supported-news](/article/ad-supported-news)** and watch the flow:

- The **leaderboard above the paywall** fills immediately — it's a normal page ad, outside the lock.
- The **in-article slots don't exist** while the content is locked (no wasted requests).
- **Unlock** → the content is placed → `dca:rendered` fires → the in-article ads fill. Open the
  console to see the adapter and the fake GPT log each step.

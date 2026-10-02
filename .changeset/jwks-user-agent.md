---
"@sesamy/capsule-server": patch
---

Send a `User-Agent` header (`Sesamy-Capsule (+https://sesamy.com)`) when fetching publisher JWKS. Some publishers (e.g. subjekt.no) return 403 to requests without one. (SES-1375)

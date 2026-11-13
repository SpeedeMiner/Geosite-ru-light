# GeoSite RU Light v11.6 — exact ALT Linux infrastructure coverage

This release adds six exact hostname matches to RU. No apex or wildcard
coverage of `altlinux.org` is added, and the three already approved ALT
Linux exact names remain unchanged.

| Host | Purpose and first-party evidence |
|---|---|
| `bugzilla.altlinux.org` | [ALT Linux bug tracker linked from the errata index](https://errata.altlinux.org/branches/) |
| `bugs.altlinux.org` | [Documented bug reporting entry point](https://docs.altlinux.org/ru-RU/platform/10.1/html-single/alt-platform/) |
| `errata.altlinux.org` | [Package fixes and security bulletins](https://errata.altlinux.org/branches/) |
| `forum.altlinux.org` | [Community forum](https://docs.altlinux.org/ru-RU/platform/10.1/html-single/alt-platform/) |
| `git.altlinux.org` | [Build system and Git interface](https://docs.altlinux.org/ru-RU/platform/10.1/html-single/alt-platform/) |
| `lists.altlinux.org` | [Community mailing lists](https://docs.altlinux.org/ru-RU/platform/10.1/html-single/alt-platform/) |

Compared with v11.5, RU grows from 3,086 to 3,092 rules, with no
removals. BLOCK and all 16 Hydra categories are unchanged. The DAT is
83,092 bytes, SHA-256
`b0be3f70f8a4950fde0aec2d237d8af5bbfc156c99079ac11cfb41f386d74107`.
The numbered release is published from the verified bundle and is not
rewritten by subsequent rolling updates. v11.5 remains the pinned
comparison floor.

The local Server projection gains exactly six RU rules, retains 29
exact names, and contains only the RU category. Expected Server
DAT SHA-256:
`261ab10e1492c406d472610ce2bc7f34f4d4aa2e0f94e869dfaf899ae93da4d6`.

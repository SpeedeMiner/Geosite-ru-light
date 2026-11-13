# GeoSite RU Light v11.10 — functional SDK routing

Route documented SDK endpoints with user-facing functions through RU/DIRECT rather than blocking a vendor zone. RU is a routing exception, not a claim about network ownership or hosting location. Shared SDK endpoints can still send analytics and expose the direct connection’s public IP.

Ten exact hosts plus the single Branch App Links suffix are added. Existing BLOCK, Hydra, and other categories are unchanged. In particular, the Crashlytics report upload host remains an exact BLOCK rule and its settings endpoint remains RU.

## Approved additions

Public, anonymous HEAD requests on November 13, 2026 reached each endpoint with valid TLS from three Russian ASN vantage points. A 403, 404, or 405 on a bare API URL establishes reachability only. Authenticated API calls, push delivery and app flows were not exercised.

| Rule | Purpose and first-party reference | Public observations |
|---|---|---|
| `full:api-eu.mixpanel.com` | [Mixpanel SDK API and feature flags (EU)](https://mixpanel.github.io/mixpanel-react-native/Mixpanel.html) | [api-eu.mixpanel.com — 405](https://api.globalping.io/v1/measurements/28jbCcNIcthP3MD4k00021Upi) |
| `full:api-in.mixpanel.com` | [Mixpanel SDK API and feature flags (India)](https://mixpanel.github.io/mixpanel-react-native/Mixpanel.html) | [api-in.mixpanel.com — 405](https://api.globalping.io/v1/measurements/2zy0sCuWYZqmXrwVM00021Upi) |
| `full:api.lab.amplitude.com` | [Amplitude Experiment remote evaluation (US)](https://www.amplitude.com/docs/sdks/experiment-sdks/experiment-android) | [api.lab.amplitude.com — 404](https://api.globalping.io/v1/measurements/2qZxHiUIAXTENXy8b00021Upi) |
| `full:api.lab.eu.amplitude.com` | [Amplitude Experiment remote evaluation (EU)](https://www.amplitude.com/docs/sdks/experiment-sdks/experiment-evaluation-proxy) | [api.lab.eu.amplitude.com — 404](https://api.globalping.io/v1/measurements/25KKkmiQcDedHm23700021Upi) |
| `full:api.onesignal.com` | [OneSignal SDK initialization and push configuration](https://github.com/OneSignal/OneSignal-Android-SDK/issues/2722) | [api.onesignal.com — 403](https://api.globalping.io/v1/measurements/2TziTGze94E2TmzDz00021Upi) |
| `full:api2.branch.io` | [Branch SDK and deep-link API](https://help.branch.io/apidocs/deep-linking/overview) | [api2.branch.io — 301](https://api.globalping.io/v1/measurements/2QzP4TzkpYOvZ3g8J00021Upi) |
| `domain:app.link` | [Branch per-app and alternate App Links](https://help.branch.io/developer-hub/android-app-links) | [branch.app.link — 307](https://api.globalping.io/v1/measurements/2YaSvlrlycsRrmbTp00021Upi), [branch-alternate.app.link — 307](https://api.globalping.io/v1/measurements/2KTB6nh9jUc40ghOR00021Upi) |
| `full:cdn.onesignal.com` | [OneSignal Web SDK delivery](https://github.com/OneSignal/react-onesignal/blob/main/index.ts) | [cdn.onesignal.com — 200](https://api.globalping.io/v1/measurements/27lvPUhbuh0sZQmGB00021Upi) |
| `full:flag.lab.amplitude.com` | [Amplitude Experiment flag configurations (US)](https://amplitude.com/docs/web-experiment/proxy) | [flag.lab.amplitude.com — 404](https://api.globalping.io/v1/measurements/2mhQHeXif12LVy1pZ00021Upi) |
| `full:flag.lab.eu.amplitude.com` | [Amplitude Experiment flag configurations (EU)](https://amplitude.com/docs/web-experiment/proxy) | [flag.lab.eu.amplitude.com — 404](https://api.globalping.io/v1/measurements/2rW4ngVmT2tu6TUA800021Upi) |
| `full:onesignal.com` | [OneSignal Web SDK service worker on the apex](https://github.com/OneSignal/onesignal-ngx/blob/main/MigrationGuide.md) | [onesignal.com — 200](https://api.globalping.io/v1/measurements/2pmjaoaUVkkkz9kqa00021Upi) |

## Not changed

- Sentry ingestion and Google client metrics are not needed for the functional paths evidenced here. No new BLOCK decision is taken for them.
- The Mixpanel US API host did not complete TLS across six tested Russian ASNs in the sampled checks. This is not proof of a nationwide block. It and the legacy decide host are not added.
- No vendor-wide wildcard for OneSignal, Branch, Amplitude, Mixpanel or Google APIs. The Branch App Links suffix is needed for per-application and alternate link domains. Branch corporate pages and Amplitude/Mixpanel corporate or analytics-only hosts are not added.
- The Happ profile is not edited. Its routing priority and DNS setup remain independent of the DAT.

## Build results

- Light: 3,131 RU rules (+11, −0), 44 unchanged BLOCK rules and 18 categories. DAT SHA-256: `8fc2cf9c2b3196a0f62dce1948858ac8798309ed0328fb75e9a56fcd590b9bb2`.
- Server projection: 3,019 RU rules (+11, −0) in its single category. DAT SHA-256: `21dcc114c0ac8ca16e647d0cdb6e2733c5580c6087c7e09abd72b311ab96e997`.

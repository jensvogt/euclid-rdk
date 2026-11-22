# Changelog

## [0.1.5](https://github.com/jensvogt/euclid-rdk/compare/euclid-rdk-v0.1.4...euclid-rdk-v0.1.5) (2026-11-22)


### Features

* **eag:** route match types, is_upload_route, absent route type reads as PROXY ([8537fcb](https://github.com/jensvogt/euclid-rdk/commit/8537fcbd960302c48c77cf0d803b1a0a70d15a09))
* **eam:** OIDC/SAML browser login, listing match types, describe_permissions ([f0a82fb](https://github.com/jensvogt/euclid-rdk/commit/f0a82fba737eee4956b15eb2d9b98420410e7129))
* **eap:** node draining, instance assignment, topic/secret grants, limits, forced redeploy, match types ([92e2a76](https://github.com/jensvogt/euclid-rdk/commit/92e2a768fea459b1d03fc5b6c29d9d79a19f1e5c))
* EDS domain name service module ([3695266](https://github.com/jensvogt/euclid-rdk/commit/369526602efd6559c0e034f59faa9b33317b34cf))
* EDS module and sync with euclid-jdk 0.1.61 ([ae3f867](https://github.com/jensvogt/euclid-rdk/commit/ae3f867023dcfc9b67d2ae53cc382e4026f43d14))
* **ekv:** list-tables match type, explicit unnarrowed scan ([2948e7c](https://github.com/jensvogt/euclid-rdk/commit/2948e7c17639fd69e4a10289afaa60bafa17bf5e))
* **emo:** align series queries and dashboards with the JDK ([8c55668](https://github.com/jensvogt/euclid-rdk/commit/8c55668d2dfd6c8d09ff41ae4911c73992d89c8e))
* **ens:** list-topics match type, empty purge-topic answers read as done ([baf6efe](https://github.com/jensvogt/euclid-rdk/commit/baf6efe0d25a71fb68cf1141c58a80dd11c0b567))
* **eqs:** list-queues match type, system attributes on send, empty purge answers ([cbe887e](https://github.com/jensvogt/euclid-rdk/commit/cbe887e8fef14b446c68e2464e1524fed34e2c70))
* **esm:** match types, one-level listings, internal buckets, delete-if-empty and delete by prefix ([3fa6d55](https://github.com/jensvogt/euclid-rdk/commit/3fa6d552ddfeec825d924a1b4365d47d63f8b4a4))
* **ess,ekm:** match type for list-secrets, list-keys and list-certificates ([9c4c026](https://github.com/jensvogt/euclid-rdk/commit/9c4c0267be26e98d2185846801a6ddc99fb2d1c3))
* **ets:** list servers by match type ([d414e42](https://github.com/jensvogt/euclid-rdk/commit/d414e42d3315aebf3977bfb5184a3eaadf7c5934))

## [0.1.4](https://github.com/jensvogt/euclid-rdk/compare/euclid-rdk-v0.1.3...euclid-rdk-v0.1.4) (2026-11-07)


### Features

* EAD and EMM modules ([e94e08d](https://github.com/jensvogt/euclid-rdk/commit/e94e08d612a661a656c4bc471db4998d1d895bc3))
* EAG upload routes, EKV scan filters, ETS user count ([81707c2](https://github.com/jensvogt/euclid-rdk/commit/81707c2e73a13daabfcf6b84ecafbef9e930c15a))
* **eam:** change-userid, change-email, account switching and session refresh ([d9e34c3](https://github.com/jensvogt/euclid-rdk/commit/d9e34c3ae26adda206259f0cd2541612896871bb))
* **eap:** set-application-limits and resource fields ([508c1cc](https://github.com/jensvogt/euclid-rdk/commit/508c1cca44ccbb6c987ed4d9d91d9ba49bcac33e))
* EES module with WebSocket event stream ([f2fbaa2](https://github.com/jensvogt/euclid-rdk/commit/f2fbaa2cb5e220b8c3f6f809cc7b1eaffeb8cce0))
* EMO queries, alert rules and dashboards ([8c2862a](https://github.com/jensvogt/euclid-rdk/commit/8c2862abc414c93e92b7fc4bd6f85da4503d86a9))
* ENS delete-after-delivery and EQS max retries ([1ea3970](https://github.com/jensvogt/euclid-rdk/commit/1ea3970c644f5fce3d4d3f8ce7f4646e7cfae3fc))
* ESM versioning, lifecycle, archive/restore and verify-objects ([d074e58](https://github.com/jensvogt/euclid-rdk/commit/d074e58ec9fcdc61cc706f9d8d7a78e01404e0dd))
* sync with the Euclid backend (ESM versioning, EMO alerts, EAD, EMM, ...) ([e9de9be](https://github.com/jensvogt/euclid-rdk/commit/e9de9be2915e7ce6c22c69bc689ab4431db3b832))

## [0.1.3](https://github.com/jensvogt/euclid-rdk/compare/euclid-rdk-v0.1.2...euclid-rdk-v0.1.3) (2026-11-02)


### Bug Fixes

* complete EAP (missing egress limiter) and add the EMO metrics recorder ([94c5c86](https://github.com/jensvogt/euclid-rdk/commit/94c5c86f60c5e9345df3d1f3f2ab8120f36df7e4))

## [0.1.2](https://github.com/jensvogt/euclid-rdk/compare/euclid-rdk-v0.1.1...euclid-rdk-v0.1.2) (2026-11-02)


### Features

* add all other modules ([b3196fa](https://github.com/jensvogt/euclid-rdk/commit/b3196fa199e17d5a77447d123f0666a02c01f4c6))
* EKM module ([733b1d4](https://github.com/jensvogt/euclid-rdk/commit/733b1d4ac3b527c13fafb070423ad9dd87e6ffad))
* ESS, EKM, ETS and EAG modules ([d745e8e](https://github.com/jensvogt/euclid-rdk/commit/d745e8e8cb2437c0f7816ef6debe104152be21fb))
* ESS, ETS and EAG modules ([0e413d2](https://github.com/jensvogt/euclid-rdk/commit/0e413d2745705bd10d961d6b2cc04e11eebef374))

## [0.1.1](https://github.com/jensvogt/euclid-rdk/compare/euclid-rdk-v0.1.0...euclid-rdk-v0.1.1) (2026-11-02)


### Features

* ENS and EKV modules ([bd9c58e](https://github.com/jensvogt/euclid-rdk/commit/bd9c58ef8372586b5b79dbdb13d66119377b6eeb))

## 0.1.0 (2026-11-02)


### Features

* Rust SDK for euclid with EAM, EQS and ESM modules ([f685c39](https://github.com/jensvogt/euclid-rdk/commit/f685c39cef7b229a5b0b1c9724f474272b1dbb7f))

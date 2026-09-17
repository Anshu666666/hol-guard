# Expiry qualification preserves acknowledged command authority

The installed candidate on all four targets at PR2970 head `107606388ad55f924a4e2924b4ff84e5fa08e6ff` failed while authenticating the short-lived expiry fixture publication. The fixture rebuilt its snapshot without the acknowledged `command_extensions`. The current native command-control floor rejects removal of established command authority; expiry must renew that same authority before testing its expiration.

The fixture now carries the command extensions from the acknowledged snapshot into the renewal. The frozen `2e672d2` builder has no such keyword, so the fixture omits it when the legacy snapshot has no extensions. It does not retry a rejected candidate as legacy. The received ACK and authenticated on-disk binding must agree on generation, policy digest, runtime identity and command-extension presence before any raw expiry probe runs.

The original three-second expiry, two-second publication attempt, one-second raw probe and 400 ms workspace preparation bounds are unchanged. The helper does not manufacture an ACK, change authority files directly, relax native policy, or count an unavailable response as proof of expiry.

Nine source tests pass. They cover both exact builder profiles and reject incomplete/retry ACKs, missing bindings and changes to generation, policy digest, runtime identity or command binding before the raw probe. Independent review found and closed the legacy-keyword issue. These tests use controlled transport responses; actual installed acceptance and the native `snapshot_expired` result still require the next CI run. The earlier installed failures remain recorded under their original source.

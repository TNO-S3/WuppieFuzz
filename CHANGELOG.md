# v1.x (in progress)

## Highlights

## Features

- Added unit tests for mutators in
  [#100](https://github.com/TNO-S3/WuppieFuzz/pull/100)
- Adds support for overriding the target server from the CLI in
  [#111](https://github.com/TNO-S3/WuppieFuzz/pull/111)
- Generate example parameters for the OpenAPI `allOf` keyword with just a
  single schema in [#118](https://github.com/TNO-S3/WuppieFuzz/pull/118)
- Support logging in the output-corpus subcommand in
  [#121](https://github.com/TNO-S3/WuppieFuzz/pull/121)
- Exit and notify user when instrumentation is not working in
  [#145](https://github.com/TNO-S3/WuppieFuzz/pull/145)

## Fixes

- Updated [LibAFL](https://github.com/AFLplusplus/LibAFL) to 0.15.3 in
  [#107](https://github.com/TNO-S3/WuppieFuzz/pull/107)
- Use a single file to store Jacoco exec data in
  [#114](https://github.com/TNO-S3/WuppieFuzz/pull/114).
- Fix a bug in corpus generation when no examples were found for a
  request body in [#137](https://github.com/TNO-S3/WuppieFuzz/pull/137)
- Parameter matching for corpus generation now detects resource-id and
  resourceId in addition to resource_id in [#143](https://github.com/TNO-S3/WuppieFuzz/pull/143)
- Consider AnyOf and AllOf schemas for parameter backreferences if they
  have exactly one element in [#144](https://github.com/TNO-S3/WuppieFuzz/pull/144)
- Improved corpus loading and fixed fallback when corpus loading fails in
  [#147](https://github.com/TNO-S3/WuppieFuzz/pull/147)

# v1.2.0 (2025-02-21)

## Highlights

## Features

- Adds support for setting power schedules for seed scheduling in
  [#73](https://github.com/TNO-S3/WuppieFuzz/pull/73)
- Adds custom executor enabling proper timeout kill and removing unsafe code in
  [#49](https://github.com/TNO-S3/WuppieFuzz/pull/49)
- Implement support for access and refresh tokens for OAuth in
  [#70](https://github.com/TNO-S3/WuppieFuzz/pull/70)

## Fixes

- Updated [LibAFL](https://github.com/AFLplusplus/LibAFL) to 0.15.0 in
  [#65](https://github.com/TNO-S3/WuppieFuzz/pull/65) thanks to
  [@tokatoka](https://github.com/tokatoka)
- Sqlite reporting: save body contents as text (instead of `&[u8]`) in
  [#76](https://github.com/TNO-S3/WuppieFuzz/pull/76/)

# v1.1.2 (2025-01-16)

## Highlights

## Features

## Fixes

- Removed `libssl` from installation prerequisites and added `build-essential`
  in [#45](https://github.com/TNO-S3/WuppieFuzz/pull/45)
- Temporary workaround for ctrl+c behaviour in
  [#47](https://github.com/TNO-S3/WuppieFuzz/pull/47)
- Update to LibAFL 0.14.1 in [#52](https://github.com/TNO-S3/WuppieFuzz/pull/52)

# v1.1.1 (2024-11-06)

## Highlights

## Features

## Fixes

- Split `LICENSE` into `LICENSE` and `LICENSE.THIRDPARTY` in
  [#18](https://github.com/TNO-S3/WuppieFuzz/pull/18)
- Use `unicode_truncate` crate instead of `String::truncate` to make sure we cut
  strings at a character boundary in
  [#29](https://github.com/TNO-S3/WuppieFuzz/pull/29)
- Added support for all remaining HTTP methods (options, connect) in
  [#32](https://github.com/TNO-S3/WuppieFuzz/pull/32)
- Support `text/plain` bodies when replacing backreference-type parameter values
  by actual values in [#40](https://github.com/TNO-S3/WuppieFuzz/pull/40)
- Fixes missing OpenSSL dependency by static compilation in
  [#43](https://github.com/TNO-S3/WuppieFuzz/pull/43)
- Added support for Regex anchors in
  [#35](https://github.com/TNO-S3/WuppieFuzz/pull/35)

# v1.1.0 (2024-09-17)

## Highlights

- Updated [LibAFL](https://github.com/AFLplusplus/LibAFL) from 0.11.2 to 0.13.2,
  special thanks to [@domenukk](https://github.com/domenukk) for initiating the
  update and thinking along.

## Features

## Fixes

- Bug in filtering of code coverage for JaCoCo (Java-based instrumentation) in
  [#9](https://github.com/TNO-S3/WuppieFuzz/pull/9)
- Endpoint coverage should be used as fallback guidance when fuzzing in black
  box setting in [#5](https://github.com/TNO-S3/WuppieFuzz/pull/5)
- Tweaks in logging in [#5](https://github.com/TNO-S3/WuppieFuzz/pull/5)
- Update to LibAFL 0.13.2 in [#5](https://github.com/TNO-S3/WuppieFuzz/pull/5)
- Add a multimap observer to let the scheduler use both endpoint coverage and
  line coverage when both are available in
  [#5](https://github.com/TNO-S3/WuppieFuzz/pull/5)
- Updated compatible dependencies releases
  [#4](https://github.com/TNO-S3/WuppieFuzz/pull/4)

# v1.0.0 (2024-09-12)

First release of WuppieFuzz.

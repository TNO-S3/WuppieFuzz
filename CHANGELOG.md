# v1.x (in progress)

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

# v1.x (in progress)

## Highlights

## Features

## Fixes

- Split `LICENSE` into `LICENSE` and `LICENSE.THIRDPARTY` in
  [#18](https://github.com/TNO-S3/WuppieFuzz/pull/18)

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

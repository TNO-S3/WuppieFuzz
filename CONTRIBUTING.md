# Contributing to WuppieFuzz

Thanks for taking the time to contribute! 🎉

This document intends to provide help to get started contributing to WuppieFuzz.
Please also feel free to help us improve it - you, as a new developer, are the
expert on what is difficult and unclear when starting out!

## Documentation

For a high-level overview of the project, please see the design overview in the
directory `design` in this repository. Its `README.md` file should get you
started.

To understand the internal workings of WuppieFuzz, you can use Rustdoc, which
generates documentation automatically from the doc comments in the code.

To view these, run `cargo doc` in the main repository directory. This generates
the HTML documentation in the `target/doc/wuppiefuzz` directory.

## Pull requests

If you find an opportunity for improvement and make changes to the code
accordingly, we would be delighted if you share those with us, so we can improve
the fuzzer. To that end, you can fork the repository, make changes in a new Git
branch, and submit a pull request for your branch to this repository. This allows
us to see the changes, make suggestions where applicable, and merge your changes
into our repository.

In the description of your pull request, please mention what issue it addresses,
and give a high-level overview of the changes. This allows us to understand your
proposal more easily.

Please keep in mind that we use the Apache 2.0 license for this repository. If
you contribute code, it will be made available under the same license.

## Issues

If you find a bug, but won't fix it yourself, we do still appreciate if you tell
us about it. You can file an issue in this repository to do so. Please use the
issue's description to specify

- the version of the fuzzer you are using
- what you're doing with it, e.g. the command line you used
- the behaviour you see
- the behaviour you would expect

This allows us to more easily understand the problem, and to reproduce it. If we
can't reproduce a problem, it's much harder to find out what's going on. This
means we might also ask you for (a minimized version of) the API specification
you are using, for instance.

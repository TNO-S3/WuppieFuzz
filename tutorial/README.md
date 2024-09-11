# The WuppieFuzz Beginner Tutorials

WuppieFuzz has multiple follow-along tutorials to get you acquanted with the tool. These tutorials hold your hand as we setup an API target, perform a fuzz test, and proceed to analyze the results. During this process, the various features of WuppieFuzz will be introduced and explained.

The tutorial consists of two parts, which should be followed in this order:
1. [Black-box fuzzing](01_blackbox/README.md): this tutorial demonstrates the use of WuppieFuzz in black-box mode to fuzz the Appwrite API. Black-box mode is simple because it does not require a coverage-based feedback loop from the target to the fuzzer.
2. [White-box fuzzing](02_whitebox/README.md): this tutorial uses white-box mode to perform coverage-guided fuzzing. This requires a few more steps on top of the black-box setup.

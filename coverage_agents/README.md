# Coverage Agents

WuppieFuzz enables you to run your PUT with a coverage agent. Such an agent
tracks coverage in the PUT and interacts with the fuzzer to provide this
coverage information as feedback. We currently support two types of coverage
agents:

1. **Java through JaCoCo**: this takes into account both the transport (over
   TCP) protocol and the actual coverage information format used by JaCoCo.
2. We are developing **NodeJS** coverage agents using either the **Istanbul**
   library or **V8's built-in** coverage. These communicate over TCP using a
   very simple protocol and send coverage information in the **LCOV** format.
3. Python code coverage based on coverage.py. These communicate over TCP using a
   very simple protocol and send coverage information in the **LCOV** format.

This directory contains code for coverage agents.

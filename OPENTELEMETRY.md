# OpenTelemetry coverage

WuppieFuzz can use [OpenTelemetry](https://opentelemetry.io/) (OTel) traces as a coverage
signal instead of a language-specific code coverage agent (Jacoco, LCOV, Coverband). This is
useful when:

- the target is composed of multiple services/languages and you want coverage across the
  whole call chain, not just one process;
- the target already has OTel auto-instrumentation (or can easily get it), but has no
  Jacoco/LCOV/Coverband agent available;
- you are fuzzing a black-box or closed-source component that only exposes tracing.

Instead of reading a line/branch coverage bitmap from an agent, WuppieFuzz injects a W3C
`traceparent` header into every request it sends, runs its own built-in OTLP receivers, and
turns the spans the target reports back into a coverage bitmap keyed by span type and
parent/child span edges. See the "How it works" section below for details.

## 1. Instrument your target with OpenTelemetry

Your application needs to export traces via OTLP (either OTLP/HTTP or OTLP/gRPC) and must
propagate the incoming `traceparent` header to any spans it creates, including spans for
calls to other services. This is the default behavior of OpenTelemetry SDKs and
auto-instrumentation agents, so in most cases no additional code changes are required, only
configuration.

For example, for a Java target using the OpenTelemetry Java agent:

```sh
java -javaagent:opentelemetry-javaagent.jar \
  -Dotel.traces.exporter=otlp \
  -Dotel.metrics.exporter=none \
  -Dotel.logs.exporter=none \
  -Dotel.exporter.otlp.traces.endpoint=http://<wuppiefuzz-host>:4319/v1/traces \
  -Dotel.exporter.otlp.traces.protocol=http/protobuf \
  -jar your-service.jar
```

Point the exporter at whichever WuppieFuzz OTLP receiver you enable (HTTP defaults to port
`4319`, gRPC to `4317`; see below). If the target runs in a container, make sure it can reach
the host WuppieFuzz runs on — the receivers refuse to bind usefully to loopback-only
addresses from inside a container, so use a routable IP, `host.docker.internal`, or a shared
Docker network.

Other languages/frameworks work the same way: any OpenTelemetry SDK or auto-instrumentation
agent that exports traces over OTLP/HTTP or OTLP/gRPC and propagates the W3C trace context
will work.

## 2. Configure WuppieFuzz

Set `coverage_format: otel` in your configuration file (or `--coverage-format otel` on the
command line). No `coverage_host` is needed for OTel coverage: WuppieFuzz doesn't connect out
to an agent, it listens for spans the target pushes to it.

```yaml
coverage_format: otel

openapi_spec: openapi_spec.yaml
target: http://localhost:8080

# Optional: override where WuppieFuzz's built-in OTLP receivers listen.
# Accepts "IP:PORT", "off" (disable that receiver), or omit for the default.
otel_http_receiver_bind: 0.0.0.0:4319   # default when omitted
otel_grpc_receiver_bind: 0.0.0.0:4317   # default when omitted
```

At least one of the two receivers must remain enabled. Notes on the bind options:

- `otel_http_receiver_bind` defaults to `0.0.0.0:4319` and serves OTLP/HTTP at `/v1/traces`.
- `otel_grpc_receiver_bind` defaults to the HTTP receiver's IP on port `4317`.
- Set either one to `off` to disable that protocol (e.g. `otel_grpc_receiver_bind: off` if
  your target only exports OTLP/HTTP).
- `otel_receiver_bind` is a legacy alias for `otel_http_receiver_bind`, kept for backwards
  compatibility.
- The equivalent CLI flags are `--otel-http-receiver-bind`, `--otel-grpc-receiver-bind`, and
  the legacy `--otel-receiver-bind`.

Run the fuzzer as usual:

```sh
wuppiefuzz fuzz --config wuppiefuzz-otel.yaml
```

WuppieFuzz logs the addresses its receivers actually bound to on startup, e.g.:

```
Started built-in OTLP/HTTP receiver on 0.0.0.0:4319; point target auto-instrumentation at http://<this-host>:4319/v1/traces
Started built-in OTLP/gRPC receiver on 0.0.0.0:4317; point target auto-instrumentation at grpc://<this-host>:4317
```

### Verifying instrumentation

Coverage guidance from OTel is delayed and asynchronous: spans arrive after the HTTP response
and are matched to the request sequence that produced them, so it can take a few seconds after
startup before non-zero coverage shows up. If coverage stays at zero for longer than that,
check that:

- the target's OTLP exporter endpoint matches the address WuppieFuzz logged above;
- the target is actually receiving and propagating the `traceparent` header WuppieFuzz sends
  on each request (some frameworks require an OTel instrumentation package for the specific
  HTTP server/client library in use);
- nothing (a proxy, firewall, container network) is blocking traffic from the target to the
  WuppieFuzz host on the receiver port.

### Coverage reports

With `report: true`, WuppieFuzz writes `otel_coverage.txt` to the report directory, listing
every distinct span type and span-to-span edge observed during the run.

## How it works

- WuppieFuzz never parses source code or reads a coverage agent's bitmap for OTel coverage.
  Instead, for each request it sends, it generates a random trace ID and injects a
  `traceparent: 00-<trace-id>-<span-id>-01` header (per the
  [W3C Trace Context spec](https://www.w3.org/TR/trace-context/)).
- The target's own OpenTelemetry instrumentation continues that trace and exports the
  resulting spans to WuppieFuzz's built-in OTLP/HTTP or OTLP/gRPC receiver.
- Each span is reduced to a key of `(service, span kind, operation)`, where the operation
  prefers a normalized HTTP route template or RPC method name over the raw span name so that
  path parameters (e.g. `/users/123` vs `/users/456`) don't create spurious new coverage.
  New span keys, and new parent → child span key edges, each set a bit in the coverage
  bitmap — this gives coverage over which operations and call paths were exercised across the
  whole distributed system, not just line/branch coverage inside a single process.
- Because spans can arrive well after the HTTP response, novel coverage is detected
  asynchronously and the corresponding input is promoted into the fuzzer's corpus after the
  fact, rather than being scored synchronously like other coverage clients.

## Comparison to other coverage clients

OTel coverage is coarser-grained than Jacoco/LCOV/Coverband (it can't see individual lines or
branches inside a handler), and its feedback is noisier and slower due to the asynchronous,
best-effort nature of trace export. Its advantage is that it works across service and language
boundaries without needing a language-specific coverage agent in every component, so it's best
used for multi-service or black-box targets rather than as a strict replacement where
fine-grained code coverage is already available.

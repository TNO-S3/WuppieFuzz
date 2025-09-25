# The WuppieFuzz beginner tutorial

## Contents

- [The WuppieFuzz beginner tutorial](#the-wuppiefuzz-beginner-tutorial)
  - [Contents](#contents)
  - [Introduction](#introduction)
  - [Environment](#environment)
  - [Cloning WuppieFuzz](#cloning-wuppiefuzz)
  - [Building WuppieFuzz](#building-wuppiefuzz)
    - [Recommended: Add WuppieFuzz to the PATH](#recommended-add-wuppiefuzz-to-the-path)
  - [Running our target: Appwrite](#running-our-target-appwrite)
    - [Start the vulnerable version server](#start-the-vulnerable-version-server)
    - [Create a project through the Appwrite web interface](#create-a-project-through-the-appwrite-web-interface)
    - [Getting the OpenAPI specification](#getting-the-openapi-specification)
  - [Preparing for a fuzzing campaign](#preparing-for-a-fuzzing-campaign)
    - [Generate an initial corpus](#generate-an-initial-corpus)
  - [Setting up authentication](#setting-up-authentication)
    - [Creating an authentication file](#creating-an-authentication-file)
    - [Creating a header file](#creating-a-header-file)
    - [Verifying that authentication is successful](#verifying-that-authentication-is-successful)
  - [Run WuppieFuzz to fuzz this target](#run-wuppiefuzz-to-fuzz-this-target)
    - [Set the logging mode](#set-the-logging-mode)
    - [Enabling reporting mode](#enabling-reporting-mode)
  - [Visualizing fuzzing data](#visualizing-fuzzing-data)
    - [Requirements](#requirements)
    - [Starting Grafana](#starting-grafana)
  - [Interpreting results](#interpreting-results)
    - [Incorrect OpenAPI Specification](#incorrect-openapi-specification)
    - [Server side errors](#server-side-errors)
      - [Visualizing the results](#visualizing-the-results)
      - [View raw request and response data](#view-raw-request-and-response-data)
      - [Extracting useful information](#extracting-useful-information)
      - [Finding vulnerabilities in the web interface](#finding-vulnerabilities-in-the-web-interface)
    - [Leaks of sensitive data](#leaks-of-sensitive-data)

## Introduction

This tutorial is aimed at (first-time) beginner users of WuppieFuzz.

In this tutorial you will learn about Windows Subsystem for Linux (WSL2), Git,
Rust programming, Web APIs, fuzzing Web APIs, how to interpret fuzzing results,
and how to use a fuzzer to find an exploitable CVE.

## Environment

This tutorial has the following dependencies:

- A Linux machine (or WSL on Windows)
- Git
- Docker

## Cloning WuppieFuzz

First you have to decide where you want your WuppieFuzz source files to live on
the local machine. Change your working directory to the folder where you want
the source code to be downloaded and run the following command to clone the
WuppieFuzz repository:

```sh
git clone https://github.com/TNO-S3/WuppieFuzz.git
```

## Building WuppieFuzz

Inside of the `wuppiefuzz` folder,
[use cargo to build the source](https://doc.rust-lang.org/cargo/commands/cargo-build.html)
using this command:

```rust
cargo build --release
```

Since this is the first time this command is run, it should take a while. It
should finish successfully with a built `wuppiefuzz` application here:

```sh
./target/release/wuppiefuzz
```

To check if WuppieFuzz was built successfully, try asking it for help:

```sh
./target/release/wuppiefuzz --help
```

If WuppieFuzz was built successfully, the output should give you an idea of all
of the options you can provide to WuppieFuzz. Reading through this can give you
a good idea of what WuppieFuzz is capable of.

### Recommended: Add WuppieFuzz to the PATH

In order to make it easier to use WuppieFuzz in the future, you can add it to
the PATH by running the following command in a shell:

```sh
export PATH=$PATH:<WuppieFuzz directory>/target/release
```

If you want this to be persistent after rebooting, add this last command to your
`~/.bashrc` file.

## Running our target: Appwrite

For this tutorial we have chosen Appwrite v0.9.3 as a target for demonstrating
our fuzzer because it has multiple known vulnerabilities with associated CVEs.
[This paper](https://www.usenix.org/system/files/sec24summer-prepub-572-du.pdf)
by Du et al. claims to have found several vulnerabilities in Appwrite v0.9.3, so
it seems like a good candidate for a target.

Appwrite has a web interface and an API that perform similar functions.

### Start the vulnerable version server

We can get Appwrite version 0.9.3 from
[here](https://github.com/appwrite/appwrite/tree/8ce48c1f47a3ebf37c5ad9828d51d85b98c57fb3)
by cloning it with `git`. Once cloned, we can run it according to the README
file found in the repository, which gives us the following command:

```sh
docker run -it --rm \
    --volume /var/run/docker.sock:/var/run/docker.sock \
    --volume "$(pwd)"/appwrite:/usr/src/code/appwrite:rw \
    --entrypoint="install" \
    appwrite/appwrite:0.9.3
```

This command will launch multiple Docker containers, consisting of a database, a
web interface, and more. During this process, the installer will ask for a port
on which to run the web interface. In this tutorial we assume that port 80 is
chosen for this.

### Create a project through the Appwrite web interface

Before fuzzing our target we need to do some initial setup of Appwrite,
otherwise we have nothing to fuzz. Go to the web interface at
`http://localhost:80`. The first time you visit this page Appwrite will ask you
to create an admin account. Create an admin user on this page and write down the
username and password, which may be useful later. After creating an admin user
we need to create a new Appwrite project with any name. When the project has
been created, the ID of the project is found in the URL, or it can be found in
the project settings on the web interface. Note down this ID because we will
need it later when we fuzz this project.

### Getting the OpenAPI specification

The API specification can be found
[here](https://github.com/appwrite/appwrite/tree/8ce48c1f47a3ebf37c5ad9828d51d85b98c57fb3/app/config/specs),
where multiple specs are listed. We are testing the Appwrite console, so we need
the `0.9.x.console.json`.

The listed specs, however, are in the Swagger 2.x format. We convert these to
our desired OpenAPI v3 format using the following tool:
[Swagger to OpenAPI converter](https://converter.swagger.io/#/Converter/convertByContent).

> [!NOTE]  
> Conversion to OpenAPI v3 format is optional. WuppieFuzz support both v2 and v3
> specifications.

Once we have our specification in OpenAPI v3 format we must make a final change
whereby we set the address of the target server. To do this we change the server
entry to the following:

```sh
"servers": [
    {
      "url": "http://localhost/v1"
    }
]
```

This change tells WuppieFuzz that the server is located at this address on
port 80.

The converted OpenAPI specification with the updated server url used for this
tutorial has been added to the tutorial folder [here](openapi.json) and renamed
to `openapi.json`.

> [|NOTE]  
> The target server can also be specified using the `--target` flag.

## Preparing for a fuzzing campaign

### Generate an initial corpus

To fuzz a new target, an initial corpus must first be generated from the OpenAPI
specification. For a complex API this step can be quite time consuming. If an
initial corpus is not supplied to the fuzzer, it will generate one before it
starts. Unfortunately that makes it more time-consuming to start fuzzing.

The recommended solution is to generate an initial corpus one time before
fuzzing a target, and save this corpus. In that way, each subsequent fuzz can
make use of this initial corpus without having to regenerate it. To create such
a corpus and save it in a directory `corpus_directory`, run the following
command:

```sh
wuppiefuzz output-corpus --openapi-spec openapi.json corpus_directory
```

## Setting up authentication

The process of setting up authentication is unfortunately not standardised and
differs per target.

### Creating an authentication file

Authentication in Appwrite is done through cookies, whereby a JWT token is
supplied. To obtain such a token, login to the locally hosted Appwrite web
interface. Once logged in, run "Inspect" in your browser. Find where cookies are
stored in your browser (commonly the "network" tab of the page inspector) and
look for the cookie called `a_session_console_legacy`. Copy this value, but
ensure that it is URL decoded (it should not contain a %-symbol at the end). In
case it is URL-encoded, use a URL decoder such as a web-based one to decode it.
Paste the decoded value into a file called `login.yaml` similar to this:

```yaml
mode: cookie
configuration:
  set_cookie:
    a_session_console_legacy: <Cookie value>
```

### Creating a header file

While the above steps will be sufficient for most API targets, the Appwrite API
works on a project basis. This means that a project ID must be supplied for each
HTTP request to the backend. This project ID is given as an HTTP header called
`X-Appwrite-Project`. Additionally, most endpoints for Appwrite require an admin
mode which is set by `X-Appwrite-Mode`. This means that we want to supply
additional custom headers which will be do in a file `header.yaml`:

```yaml
X-Appwrite-Project: <PROJECT ID>
X-Appwrite-Mode: admin
```

This header file can be supplied to WuppieFuzz to provide it with static headers
that will not be mutated during the fuzzing campaign.

### Verifying that authentication is successful

Due to the inconsistency of authentication methods for different APIs, it is
crucial to verify if the authentication setup is valid. Without authentication,
access to an API is often very limited. WuppieFuzz has a module to verify the
authentication, as done with the following command:

```sh
wuppiefuzz verify-auth --authentication login.yaml --header header.yaml --openapi-spec openapi.json
```

If the authentication is successful, this should print a large number of debug
statements. To reduce this logging, run the above command with the
`--log-level=warn` parameter.

The `verify-auth` module will verify authentication by trying all endpoints and
methods described in the OpenAPI spec. It will consider the authentication
attempt successful if it does not return a `403 Forbidden` HTTP status code for
any of the endpoints. Depending on how well an API is designed, however, this
feature may not always be reliable if an API does not return 403 codes for
failed authentication.

See the documentation for setting up authentication [here](../authentication.md)
for more info.

## Run WuppieFuzz to fuzz this target

After starting the Appwrite target and configuring WuppieFuzz, we are ready to
start fuzzing.

Navigate to the tutorial folder and issue the following command:

```sh
wuppiefuzz fuzz --report --log-level info --initial-corpus corpus_directory --timeout 60 --authentication login.yaml openapi.json
```

Alternatively, use the following command to use our [config file](config.yaml)
that has the fuzzing parameters pre-configured:

```sh
wuppiefuzz --config config.yaml
```

This command contains a few commands described below.

### Set the logging mode

To get more verbose output a user can set the logging mode using the `LOG_LEVEL`
environment variable or the `--log-level` command line argument. The log level
can have the following values: off, error, warn, debug, info, trace. Trace will
provide the most verbose logging output.

### Enabling reporting mode

The reporting mode can be set using `--report` which will generate a database
file in the `reports/grafana/report.db` file. As will be described later, this
database contains the results and insights into our fuzzing data.

## Visualising fuzzing data

A long fuzzing campaign can generate large amounts of data. One of the main
challenges of fuzzing is how to make sense of this data and to use it
effectively. To improve this process, WuppieFuzz makes use of Grafana to
visualise the fuzzing data in a user-friendly dashboard.

Below we will describe the steps for using this dashboard.

### Requirements

Docker is required to use the Grafana dashboard.

The dashboard will look for the coverage database generated by the fuzzer.
WuppieFuzz places this database in its working directory, in
`reports/grafana/report.db`. To make sure the dashboard can find it, go to the
file `/dashboard/compose.yaml` and change the lines

```docker
    volumes:
      - type: bind
        source: ../reports/grafana/report.db
```

so that the `source` is the actual location of your `report.db` file.

### Starting Grafana

Go to the `/dashboard` directory and run the following command:

```sh
docker compose up -d
```

This will create a Docker container which will host the Grafana dashboard on
port 3000. In case another service is already running on port 3000, go to the
file `/dashboard/compose.yaml` and change the lines

```docker
ports:
  - "3000:3000"
```

to

```docker
ports:
  - "<YOUR PORT>:3000"
```

To view the dashboard, open a web browser and visit the URL
`http://localhost:3000`, or replace 3000 by the alternative port you chose.

## Interpreting results

An essential part of fuzz-testing is to understand how to interpret the data
obtained from a fuzzing campaign. The goal of fuzzing a REST API is to discover
issues which have an impact on the security and usability of the API. Below, we
describe several aspects of the results that should be considered:

1. **Incorrect OpenAPI specification**: It is common, yet undesired, for an API
   to differ from its spec, which can result in undocumented return codes. This
   is undesirable for an API because it brings ambiguity and makes it
   unpredictable, possibly resulting in security issues down the line.
2. **Leaking of sensitive data**: Responses from an API may unintentionally leak
   sensitive information in their error messages, as described by
   `CWE-209: Generation of Error Message Containing Sensitive Information` .
   Consider the examples given
   [here](https://cwe.mitre.org/data/definitions/209.html).
3. **Server side errors**: A server side error is indicated by a 5XX status code
   from an HTTP response. For a well-configured API this return code should only
   be returned in case there is an actual error on the server, and should never
   be returned in a normal situation. For such a well-configured API, a 5XX
   return code would imply a bug in the server, which could indicate a possible
   security vulnerability. Ideally, 5XX return codes should not be present in
   the OpenAPI spec because they are undesired and unexpected. If a particular
   response is expected, then the error should be handled properly and be
   returned as a different type of return code.

### Incorrect OpenAPI Specification

This section explains how to find and interpret incorrect parts of an OpenAPI
specification. An OpenAPI specification is considered incorrect if status codes
for an endpoint are detected during the fuzz which are not written in the spec.
For example, suppose that an OpenAPI specification describes an endpoint
`/users` which should return either a 200 or a 400 status code. If a fuzzing
campaign reveals another status code, such as 401, it may indicate that a
situation is occurring which is unexpected for the API. Such unexpected
situations can lead to security problems.

To see whether a fuzzing campaign has revealed an incorrect OpenAPI
specification, go to the `/reports/` directory and open the folder with the
timestamp `<TIMESTAMP>` corresponding to the fuzzing campaign that was
conducted. There will be an html file at the location
`/reports/<TIMESTAMP>/endpointcoverage/index.html`. Open this file in a web
browser to see the list of all API endpoints and the status codes found for
each.

This overview shows which status codes were found for each endpoint, as well as
the missed status codes. The misses are status codes that are documented in the
OpenAPI spec, but the fuzzer was unable to elicit such a response from the
server. If a large number of status codes are missed there are several possible
reasons. One such reason is that the fuzzing campaign was simply too short, and
the fuzzer did not have enough time to explore all of the endpoints in detail.
The solution for this is simple: run a longer fuzzing campaign. Another possible
reason is related to the structure of the API, specifically if it has a lot of
complex states that require a very specific sequence or requests. This makes
some endpoints and their status codes unreachable without elaborate knowledge of
the relation of all endpoints. In the current state of WuppieFuzz only simple
state-based testing is supported whereby relations between endpoints are learned
over time. However, this is insufficient for very complicated APIs.

### Server side errors

This section shows the process of using the results from a fuzzing campaign to
detect a potential security vulnerability.

#### Visualising the results

To visualise the results we open the dashboard in Grafana. Select "500" in de
legend to show the endpoints which have responses with a 500 status code: these
are the endpoints of interest. Select one of the endpoints to inspect further.
For the version of Appwrite that has been selected for this tutorial the
`/storage/files` endpoint appears to have the greatest number of 500 status
codes, which makes it an interesting candidate to explore further.

#### View raw request and response data

At the top-right of the Grafana dashboard, press the the "Requests and
Responses" button which switches to a dashboard containing a table. At the top
of this page, select the `/storage/files` endpoint in the filter. Also select
"500" in the filter for "Status Code". The table will now display requests and
the corresponding responses of interest.

To verify the error that we see in the Grafana dashboard we can reproduce a
crash. This can be done by looking for the value of the "Crash File" column for
a row of interest. This will contain the filename of a crash file which can be
found in the `/crashes` folder of WuppieFuzz. We can reproduce this crash file
by running the following command:

```sh
wuppiefuzz reproduce --config config.yaml <CRASH FILE>
```

From the response of this command we can see that the server error does in fact
occur.

#### Extracting useful information

For a GET request we are interested in the contents of the "URL" field because
it displays the values of the URL parameters that were supplied which caused a
server error. For a POST request we are interested in the contents of the "Body"
field. In our current example, the `/storage/files` endpoint encounters a server
error for a GET request. We take a look at a row with the following URL value:

```
http://localhost/v1/storage/files?search=%255BSEARCH%255D&limit=0&offset=0&orderType=ASC
```

The URL contains URL-encoded characters, so to display the URL parameters more
clearly we use any website to decode this URL. This gives the following output:

```
http://localhost/v1/storage/files?search=%5BSEARCH%5D&limit=0&offset=0&orderType=ASC
```

Another row gives the following URL:

```
http://localhost/v1/storage/files?limit=1&offset=0&orderType=ASC&search=some5555555%EF%BF%BD55555g
```

By looking at a few of such rows we see that a trend among these requests is
that they have a percentage symbol in the `search` parameter value.

#### Finding vulnerabilities in the web interface

The objective when looking for 500 status codes is to find server errors which
have potential security vulnerabilities. We therefore want to further inspect
any type of input that results in such an error. In our case we would like to
determine if we can exploit this version of Appwrite by exploiting the web
interface or the API. The `/storage/files` endpoint described above shows
interesting behaviour and from inspection we can see that this endpoint can be
accessed using the web interface. We visit the web interface at `localhost:80`
and select the project that we created earlier. After selecting the project we
see a "Storage" button in the left side-bar which brings us to a "Files"
dashboard. We can add files here or search for existing files. The GET method
that returned a 500 status code was for the search feature of the files, so we
can try to copy one of these crashed search parameters in the web interface. The
first of these was `%5BSEARCH%5D` as we could see from our URL parameters. If we
insert this in the search box we don't see very much happening. However, if we
use an HTTP proxy server, such as Burpsuite, we can intercept the responses.
From this we can see that the response has a 200 status code, but the body of
the response contains the message "500 Internal Server Error". This tells us
that something is clearly going wrong on the server side.

We have now found a vulnerable point of the program which we found through the
web interface. Due to improper parsing of input values, there appear to be
errors occurring on the database side. An experienced pen tester may be able to
perform an SQL Injection through this interface due to improper input
sanitization.

### Leaks of sensitive data

Responses from an API may unintentionally leak sensitive information in their
error messages, as described by
`CWE-209: Generation of Error Message Containing Sensitive Information` .
Consider the examples given
[here](https://cwe.mitre.org/data/definitions/209.html).

To determine if the API is leaking sensitive data, manual inspection is
required. An effective way of doing this is to use the "Requests and Responses"
dashboard in Grafana which shows a table of the requests and responses data. In
this table we can inspect the contents of the response body to determine if
there is interesting information which is leaked.

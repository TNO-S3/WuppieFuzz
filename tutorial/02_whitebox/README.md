# Tutorial #2: Whitebox Fuzzing

## Contents
- [Tutorial #2: Whitebox Fuzzing](#tutorial-2-whitebox-fuzzing)
  - [Contents](#contents)
  - [Introduction](#introduction)
  - [Setting up our target](#setting-up-our-target)
    - [Running our target: Swagger Petstore](#running-our-target-swagger-petstore)
    - [Setting up a coverage agent](#setting-up-a-coverage-agent)
    - [Dockerfile: running our target with Jacoco](#dockerfile-running-our-target-with-jacoco)
  - [Preparing for a fuzzing campaign](#preparing-for-a-fuzzing-campaign)
  - [Setting up authentication](#setting-up-authentication)

## Introduction 

## Setting up our target
### Running our target: Swagger Petstore

```docker
docker pull swaggerapi/petstore:latest
```

### Get the source code of the target
To determine code coverage of our fuzzer it is necessary to have the source code. 

### Setting up a coverage agent 
The Swagger Petstore is an API writen in Java which allows us to retrieve code coverage using [Jacoco](https://www.jacoco.org/jacoco/trunk/index.html). For this tutorial we used Jacoco version 0.8.12 which can be downloaded [here](https://github.com/jacoco/jacoco/releases/download/v0.8.12/jacoco-0.8.12.zip). Alternatively, a specific version can be downloaded from the Jacoco releases on Github [here](https://github.com/jacoco/jacoco/releases), where the file `jacoco-<version>.zip` should be downloaded.

Upon unzipping the downloaded zip file to the folder `jacoco-<version>`, we want to copy the file `jacoco-<version>/lib/jacocoagent.jar`. 

### Dockerfile: running our target with Jacoco
As an alternative to running our target and the coverage agent separately, we can create a Dockerfile to do both if our target is available as a Docker image. Because the Swagger Petstore has a Docker image available, it is easier to create a Docker compose file to do the work for us.

## Preparing for a fuzzing campaign

## Setting up authentication



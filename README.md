# keycloak_examples
Collection of scripts to test/validate keycloak apps

The goal of this repo is to demonstrate how to use keycloak as an authentication/authorization provider for various workflows, including:
* user to app
* app to app
* on behalf of

While there exists some existing python SDKs for keycloaks, this repo uses raw HTTP API endpoints to avoid hiding anything from potential users that want to start using Keycloak. With that in mind, there might be shortcuts taken that you'd likely want in a production environment (http retries for rate limiting, timeoutes, ex.)



## Using this repo

This repo uses `uv` to manage python and dependencies.

The code is broken into the following sections:

examples/ - individual exmaples (with their own README)
pycloak/ - Keycloak library (and related utilities like an http client) Provides Sync and Async methods to talk to the Keycloak API. All strings (endpoints, methods, etc) are available as an openapi document

All env vars are in .env (with through explanations)



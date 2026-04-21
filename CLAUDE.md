# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Java 21 / Spring Boot 3.5.5 multi-module Maven project implementing two FIDO authentication standards:
- **fido-uaf-server** — FIDO UAF 1.0 protocol server (port 8081)
- **webauthn-app** — WebAuthn/FIDO2 implementation using Yubico's library (port 8080)

Both modules use H2 in-memory databases for development.

## Build & Run Commands

```bash
# Build all modules
./mvnw clean install

# Run FIDO UAF server (port 8081)
./mvnw -pl fido-uaf-server spring-boot:run

# Run WebAuthn app (port 8080)
./mvnw -pl webauthn-app spring-boot:run

# Run all tests
./mvnw test

# Run tests for a specific module
./mvnw -pl webauthn-app test

# Run a specific test class
./mvnw test -Dtest=AppApplicationTests
```

API docs (Swagger UI) are available at `/swagger-ui.html` when either server is running.  
H2 console is at `/h2-console` on both servers.

## Architecture

### FIDO UAF Server (`fido-uaf-server`)

REST API base path: `/fidouaf/v1/`

**Request flow:**
1. Client calls `/public/regRequest/{username}` or `/public/authRequest/{username}` → server returns a challenge
2. Client signs the challenge on-device and returns an assertion
3. Server processes the assertion through `RegistrationResponseProcessing` or `AuthenticationResponseProcessing`

**Key packages:**

| Package | Role |
|---|---|
| `...server.api` | Spring REST controllers (`UAFController`) |
| `...server.config` | `UafServerConfig` — endpoint URL, facetId, trustedFacets |
| `...server.infrastructure` | JPA entities, repositories, mappers |
| `...core.ops` | Core protocol logic: `RegistrationResponseProcessing`, `AuthenticationResponseProcessing`, `DeregRequestProcessor` |
| `...core.crypto` | Cryptographic operations: `KeyCodec`, `NamedCurve`, `CertificateValidatorImpl`, `SignCounterValidator` |
| `...core.msg` | FIDO UAF message POJOs (request/response/assertion types) |
| `...core.tlv` | TLV (Tag-Length-Value) parser for UAF assertions |
| `...core.storage` | `AuthenticatorRecord`, `RegistrationRecord` data models |

### WebAuthn App (`webauthn-app`)

Uses Yubico `webauthn-server-core` 2.7.0. Services in `com.webauthn.app.service` handle credential registration and authentication. REST endpoints in `com.webauthn.app.web`.

## Configuration

Both modules require updating `application.yml` before testing with real devices:

- **fido-uaf-server**: `uaf.server.endpoint` must point to the server's reachable IP/hostname; `uaf.server.facetId` must match the Android APK key hash.
- **webauthn-app**: `authn.origin` must match the client origin (default `http://localhost:4200`).

## Key Dependencies

- **BouncyCastle 1.78** — all low-level crypto (EC key generation, ASN.1 parsing, certificate validation)
- **Gson 2.13.2** — JSON serialization of UAF protocol messages
- **Yubico webauthn-server-core 2.7.0** — WebAuthn attestation and assertion validation
- **SpringDoc OpenAPI 2.8.13** — Swagger UI generation
- **Lombok** — used throughout for boilerplate reduction

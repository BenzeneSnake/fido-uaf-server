# FIDO UAF Server Integration with Spring Boot

## Overview

This project implements the FIDO UAF and WebAuthn/FIDO2 authentication standards using Spring Boot and Java 21.
It builds upon and improves several open-source projects.

## Attribution

This project is based on and incorporates code from:

1. **webauthn_java_spring_demo** by jgrams
    - Original repository: https://github.com/jgrams/webauthn_java_spring_demo
    - Copyright (c) 2022 jgrams
    - Licensed under the Apache License 2.0
    - This serves as the base architecture for our WebAuthn implementation

2. **eBay UAF (Universal Authentication Framework)**
    - Original repository: https://github.com/eBay/UAF
    - Copyright (c) 2015 eBay Inc.
    - Licensed under the Apache License, Version 2.0
    - Provides the reference implementation of the FIDO UAF protocol.
    - Portions of this project are derived from or based on the original eBay UAF implementation.

All original works are used in accordance with their respective Apache 2.0 licenses.

**Prerequisites:**

**Java 21**: This project uses Java 21. If you don't have Java 21, you can install OpenJDK. Instructions are found on
the [OpenJDK website](https://aws.amazon.com/tw/corretto/).

* [Getting Started](#getting-started)
* [Start the Apps](#start-the-apps)
* [Links](#links)
* [Help](#help)
* [License](#license)

## Key Modifications

This derivative work includes the following enhancements:

* **Upgraded to Java 21** and **Spring Boot 3.5.5**
* **Keycloak integration** for centralized identity management
* **Dual protocol support** for both WebAuthn (FIDO2) and UAF (FIDO UAF 1.0)
* **Modern architecture** with improved security and performance
* **Enhanced API** with OpenAPI/Swagger documentation
* **H2 database integration** for development and testing

---

## 🧩 Configuration Before Testing

Before running the FIDO UAF Server or mobile client, you must update the configuration in application.yml:

| Setting        | Description                                                                                                                                                             | Example                                 |
|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------|
| **`endpoint`** | The base URL of your FIDO UAF Server. <br>When testing on a mobile device, replace `localhost` with your **computer’s IPv4 address** so the phone can reach the server. | `http://xx.xx.xxx.xx:8081`              |
| **`facetId`**  | The unique Facet ID that identifies your mobile app. <br>For testing, you can set it to your **phone model name** or any unique identifier.                             | `android:apk-key-hash:YOUR_PHONE_MODEL` |

---

## Getting Started

To install this example application, run the following commands:

```bash
git clone https://github.com/BenzeneSnake/fido-uaf-server
cd fido-uaf-server
```

## Related Repositories

This project is the backend server. The full system consists of the following components:

| Repository | Description | Protocol |
|---|---|---|
| **[fido-uaf-server](https://github.com/BenzeneSnake/fido-uaf-server)** *(this repo)* | Spring Boot backend for both FIDO UAF and WebAuthn | UAF + WebAuthn |
| **[fido-uaf-client](https://github.com/BenzeneSnake/fido-uaf-client)** | Android mobile client that performs UAF registration and authentication | FIDO UAF 1.0 |
| **[angular-frontend](https://github.com/BenzeneSnake/angular-frontend)** | Angular web frontend for WebAuthn passkey registration and login | WebAuthn / FIDO2 |

### How They Fit Together

```
┌─────────────────────────┐        ┌──────────────────────────────────────┐
│  Android App            │        │  fido-uaf-server (this repo)         │
│  fido-uaf-client        │◄──────►│  FIDO UAF Server  (port 8081)        │
│  (FIDO UAF 1.0)         │        │                                      │
└─────────────────────────┘        │  WebAuthn Backend (port 8080)        │
                                   └──────────────────────────────────────┘
┌─────────────────────────┐                          ▲
│  Browser / Web App      │                          │
│  angular-frontend       │◄─────────────────────────┘
│  (WebAuthn / FIDO2)     │
└─────────────────────────┘
```

**FIDO UAF flow:** The Android client (`fido-uaf-client`) communicates with the UAF Server on port 8081 to register and authenticate using device biometrics or PIN. Make sure to configure `endpoint` and `facetId` in `application.yml` before testing with a real device.

**WebAuthn flow:** The Angular frontend (`angular-frontend`) communicates with the WebAuthn backend on port 8080 to register and authenticate using passkeys (platform authenticators or security keys).

---

## Start the Apps

This project contains two modules. Start each one in a separate terminal:

**FIDO UAF Server** (port 8081):

```bash
./mvnw -pl fido-uaf-server spring-boot:run
```

API docs available at http://localhost:8081/swagger-ui.html

**FIDO WebAuthn** (port 8080):

```bash
./mvnw -pl webauthn-app spring-boot:run
```

API docs available at http://localhost:8080/swagger-ui.html

Then clone and start the corresponding client for end-to-end testing:

- **UAF mobile client:** see [fido-uaf-client](https://github.com/BenzeneSnake/fido-uaf-client) for Android setup instructions
- **WebAuthn frontend:** see [angular-frontend](https://github.com/BenzeneSnake/angular-frontend) for Angular setup instructions

## Dependencies

This project uses the following key open-source libraries:

* [Spring Boot](https://spring.io/projects/spring-boot) - Application framework
* [Yubico WebAuthn Server Core](https://developers.yubico.com/java-webauthn-server/) - WebAuthn/FIDO2 implementation
* [eBay UAF](https://github.com/eBay/UAF) - FIDO UAF protocol implementation
* [H2 Database](https://www.h2database.com/) - In-memory database for development
* [Lombok](https://projectlombok.org/) - Code generation
* [SpringDoc OpenAPI](https://springdoc.org/) - API documentation

For a complete list of dependencies, see [pom.xml](pom.xml).

## License

This project includes code derived from [eBay UAF](https://github.com/eBay/UAF),
which is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

All modifications made to the original source are noted within the code and documentation.
© 2025 YourName. Licensed under the Apache License, Version 2.0.

### Important License Information

This is a derivative work incorporating code from:

- **jgrams/webauthn_java_spring_demo** (Apache 2.0)
- **eBay/UAF** (Apache 2.0)

All modifications and enhancements are also released under Apache 2.0. When using this code, you must:

1. Retain all copyright notices from original works
2. Include a copy of the Apache License 2.0
3. State any significant modifications made to the original code
4. Ensure compliance with the Apache License 2.0 terms

For detailed attribution and third-party notices, see the [LICENSE](LICENSE) file.

## Disclaimer

This software is provided "AS IS" without warranty of any kind. The authors and contributors are not liable for any
damages arising from the use of this software. See the LICENSE file for complete terms and conditions.

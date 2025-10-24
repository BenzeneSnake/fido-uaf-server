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

**Java 21**: This project uses Java 21. If you don't have Java 21, you can install OpenJDK. Instructions are found on the [OpenJDK website](https://aws.amazon.com/tw/corretto/).

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

## Getting Started

To install this example application, run the following commands:

```bash
git clone https://github.com/BenzeneSnake/fido-uaf-server
cd fido-uaf-server
```

## Start the Apps

To install all of its dependencies and the app, run:

```bash
./mvnw spring-boot:run
```

You can now test the application by opening http://localhost:8080

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

This software is provided "AS IS" without warranty of any kind. The authors and contributors are not liable for any damages arising from the use of this software. See the LICENSE file for complete terms and conditions.

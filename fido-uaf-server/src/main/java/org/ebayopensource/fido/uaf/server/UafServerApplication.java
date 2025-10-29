package org.ebayopensource.fido.uaf.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * FIDO UAF Server Application
 *
 * This is the main Spring Boot application class for the FIDO UAF (Universal Authentication Framework) server.
 * It provides authentication services using the FIDO UAF protocol.
 */
@SpringBootApplication(scanBasePackages = "org.ebayopensource.fido.uaf")
public class UafServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(UafServerApplication.class, args);
    }
}

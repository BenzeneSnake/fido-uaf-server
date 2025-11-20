package org.ebayopensource.fido.uaf.server.infrastructure.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * UAF Registration Record JPA Entity
 * Stores complete FIDO UAF registration information
 */
@Entity
@Table(name = "uaf_registration_record", indexes = {
        @Index(name = "idx_reg_record_username", columnList = "username"),
        @Index(name = "idx_reg_record_aaid_keyid", columnList = "aaid, key_id", unique = true),
        @Index(name = "idx_reg_record_device_id", columnList = "device_id")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UAFRegistrationRecordEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // AuthenticatorRecord fields
    @Column(name = "aaid", nullable = false, length = 100)
    private String aaid;

    @Column(name = "key_id", nullable = false, length = 512)
    private String keyId;

    @Column(name = "device_id", length = 255)
    private String deviceId;

    @Column(name = "username", nullable = false, length = 255)
    private String username;

    @Column(name = "status", length = 50)
    private String status;

    // RegistrationRecord fields
    @Lob
    @Column(name = "public_key", columnDefinition = "TEXT")
    private String publicKey;

    @Column(name = "sign_counter", length = 50)
    private String signCounter;

    @Column(name = "authenticator_version", length = 50)
    private String authenticatorVersion;

    @Lob
    @Column(name = "tc_display_png_characteristics", columnDefinition = "TEXT")
    private String tcDisplayPNGCharacteristics;

    @Column(name = "user_id", length = 255)
    private String userId;

    @Column(name = "time_stamp", length = 50)
    private String timeStamp;

    @Lob
    @Column(name = "attest_cert", columnDefinition = "TEXT")
    private String attestCert;

    @Lob
    @Column(name = "attest_data_to_sign", columnDefinition = "TEXT")
    private String attestDataToSign;

    @Lob
    @Column(name = "attest_signature", columnDefinition = "TEXT")
    private String attestSignature;

    @Column(name = "attest_verified_status", length = 50)
    private String attestVerifiedStatus;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}

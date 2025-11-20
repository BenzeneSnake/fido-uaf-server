package org.ebayopensource.fido.uaf.server.infrastructure.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * UAF Server Data JPA Entity
 * for H2
 */
@Entity
@Table(name = "uaf_server_data", indexes = {
        @Index(name = "idx_server_data_username", columnList = "username"),
        @Index(name = "idx_server_data_expires_at", columnList = "expires_at")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UAFServerDataEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", nullable = false, length = 255)
    private String username;

    @Lob
    @Column(name = "server_data_string", nullable = false, columnDefinition = "TEXT")
    private String serverDataString;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}

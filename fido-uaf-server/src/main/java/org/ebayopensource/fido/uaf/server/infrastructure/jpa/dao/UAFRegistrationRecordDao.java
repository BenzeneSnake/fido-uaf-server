package org.ebayopensource.fido.uaf.server.infrastructure.jpa.dao;

import org.ebayopensource.fido.uaf.server.infrastructure.entity.UAFRegistrationRecordEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * JPA DAO for UAF Registration Records
 */
public interface UAFRegistrationRecordDao extends JpaRepository<UAFRegistrationRecordEntity, Long> {

    /**
     * Find registration record by AAID and KeyID (unique authenticator identifier)
     */
    Optional<UAFRegistrationRecordEntity> findByAaidAndKeyId(String aaid, String keyId);

    /**
     * Find all registration records for a specific username
     */
    List<UAFRegistrationRecordEntity> findByUsername(String username);

    /**
     * Find by authenticator key (AAID#KeyID format)
     */
    @Query("SELECT r FROM UAFRegistrationRecordEntity r WHERE CONCAT(r.aaid, '#', r.keyId) = :key")
    Optional<UAFRegistrationRecordEntity> findByAuthenticatorKey(@Param("key") String key);

    /**
     * Delete all registration records for a specific username
     */
    void deleteByUsername(String username);

    /**
     * Check if a registration record exists by AAID and KeyID
     */
    boolean existsByAaidAndKeyId(String aaid, String keyId);

    /**
     * Find all registration records by device ID
     */
    List<UAFRegistrationRecordEntity> findByDeviceId(String deviceId);

    /**
     * Update sign counter by authenticator key (AAID#KeyID format)
     * Uses direct UPDATE SQL to avoid Entity conversion issues
     *
     * @param key         the authenticator key in format "AAID#KeyID"
     * @param signCounter the new sign counter value
     * @param updatedAt   the update timestamp
     */
    @Modifying
    @Query("UPDATE UAFRegistrationRecordEntity r SET r.signCounter = :signCounter, r.updatedAt = :updatedAt " +
            "WHERE CONCAT(r.aaid, '#', r.keyId) = :key")
    void updateSignCounterByAuthenticatorKey(@Param("key") String key,
                                             @Param("signCounter") String signCounter,
                                             @Param("updatedAt") LocalDateTime updatedAt);
}

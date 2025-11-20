package org.ebayopensource.fido.uaf.server.infrastructure.jpa.dao;

import org.ebayopensource.fido.uaf.server.infrastructure.entity.UAFRegistrationRecordEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

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
}

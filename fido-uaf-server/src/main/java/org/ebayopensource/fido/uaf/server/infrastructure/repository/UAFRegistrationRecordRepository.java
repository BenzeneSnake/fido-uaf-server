package org.ebayopensource.fido.uaf.server.infrastructure.repository;

import org.ebayopensource.fido.uaf.core.storage.RegistrationRecord;

import java.util.List;
import java.util.Optional;

/**
 * Repository interface for UAF Registration Records
 * Handles persistence of FIDO UAF registration data
 */
public interface UAFRegistrationRecordRepository {

    /**
     * Save a registration record
     *
     * @param record the registration record to save
     * @return the saved registration record
     */
    RegistrationRecord save(RegistrationRecord record);

    /**
     * Find registration record by authenticator key (AAID#KeyID)
     *
     * @param key the authenticator key in format "AAID#KeyID"
     * @return Optional containing the registration record if found
     */
    Optional<RegistrationRecord> findByAuthenticatorKey(String key);

    /**
     * Find all registration records for a username
     *
     * @param username the username
     * @return list of registration records
     */
    List<RegistrationRecord> findByUsername(String username);

    /**
     * update a registration record
     *
     * @param record RegistrationRecord
     * @return the saved registration record
     */
    boolean updateSignCounterByAuthenticatorKey(RegistrationRecord record) throws Exception;

    /**
     * Delete registration record by authenticator key
     *
     * @param key the authenticator key in format "AAID#KeyID"
     */
    void deleteByAuthenticatorKey(String key);

    /**
     * Delete all registration records for a username
     *
     * @param username the username
     */
    void deleteByUsername(String username);

    /**
     * Check if a registration record exists by AAID and KeyID
     *
     * @param aaid  the AAID
     * @param keyId the KeyID
     * @return true if exists, false otherwise
     */
    boolean existsByAaidAndKeyId(String aaid, String keyId);
}

package org.ebayopensource.fido.uaf.server.infrastructure.repository.repositoryImpl;

import org.ebayopensource.fido.uaf.core.storage.DuplicateKeyException;
import org.ebayopensource.fido.uaf.core.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.core.storage.StorageInterface;
import org.ebayopensource.fido.uaf.core.storage.SystemErrorException;
import org.ebayopensource.fido.uaf.server.infrastructure.model.UAFServerData;
import org.ebayopensource.fido.uaf.server.infrastructure.repository.UAFRegistrationRecordRepository;
import org.ebayopensource.fido.uaf.server.infrastructure.repository.UAFServerDataRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Optional;

@Component
public class UAFStorageImpl implements StorageInterface {
    private static final Logger logger = LoggerFactory.getLogger(UAFStorageImpl.class);

    // ServerData 默認過期時間：5分鐘
    private static final int SERVER_DATA_EXPIRATION_MINUTES = 5;

    private final UAFServerDataRepository serverDataRepository;
    private final UAFRegistrationRecordRepository registrationRecordRepository;

    @Autowired
    public UAFStorageImpl(
            UAFServerDataRepository serverDataRepository,
            UAFRegistrationRecordRepository registrationRecordRepository) {

        this.serverDataRepository = serverDataRepository;
        this.registrationRecordRepository = registrationRecordRepository;
    }

    @Override
    public void storeServerDataString(String username, String serverDataString) {
        logger.debug("Storing server data for username: {}", username);

        try {
            UAFServerData serverData = UAFServerData.builder()
                    .username(username)
                    .serverDataString(serverDataString)
                    .createdAt(LocalDateTime.now())
                    .expiresAt(LocalDateTime.now().plusMinutes(SERVER_DATA_EXPIRATION_MINUTES))
                    .build();

            serverDataRepository.save(serverData);
            logger.debug("Successfully stored server data for username: {}", username);
        } catch (Exception e) {
            logger.error("Failed to store server data for username: {}", username, e);
            throw new RuntimeException("Failed to store server data", e);
        }
    }

    @Override
    public String getUsername(String serverDataString) {
        logger.debug("Retrieving username for server data string");

        try {
            // 查找所有用户的 server data，找到匹配的 serverDataString
            // TODO：可考慮添加索引或其他方法提升效率
            Optional<UAFServerData> serverData = serverDataRepository.findValidByUsername(serverDataString);

            if (serverData.isPresent()) {
                String username = serverData.get().getUsername();
                logger.debug("Found username: {}", username);
                return username;
            }

            logger.warn("No username found for the given server data string");
            return null;
        } catch (Exception e) {
            logger.error("Failed to retrieve username for server data string", e);
            return null;
        }
    }

    @Override
    public void store(RegistrationRecord[] records) throws DuplicateKeyException, SystemErrorException {
        logger.debug("Storing {} registration records", records != null ? records.length : 0);

        if (records == null || records.length == 0) {
            logger.warn("No registration records to store");
            return;
        }

        try {
            for (RegistrationRecord record : records) {
                if (record == null || record.authenticator == null) {
                    logger.warn("Skipping null record or record with null authenticator");
                    continue;
                }

                // Check for duplicate key (AAID + KeyID combination)
                String aaid = record.authenticator.AAID;
                String keyId = record.authenticator.KeyID;

                if (registrationRecordRepository.existsByAaidAndKeyId(aaid, keyId)) {
                    logger.error("Duplicate key detected: AAID={}, KeyID={}", aaid, keyId);
                    throw new DuplicateKeyException();
                }

                // Save the registration record
                registrationRecordRepository.save(record);
                logger.info("Successfully stored registration record: username={}, AAID={}, KeyID={}",
                        record.username, aaid, keyId);
            }
        } catch (DuplicateKeyException e) {
            // Re-throw DuplicateKeyException as-is
            throw e;
        } catch (Exception e) {
            logger.error("System error while storing registration records", e);
            throw new SystemErrorException();
        }
    }

    @Override
    public RegistrationRecord readRegistrationRecord(String key) {
        logger.debug("Reading registration record by key: {}", key);

        try {
            Optional<RegistrationRecord> record = registrationRecordRepository.findByAuthenticatorKey(key);
            if (record.isPresent()) {
                logger.info("Found registration record for key: {}", key);
                return record.get();
            } else {
                logger.warn("No registration record found for key: {}", key);
                return null;
            }
        } catch (Exception e) {
            logger.error("Failed to read registration record for key: {}", key, e);
            return null;
        }
    }

    @Override
    public void update(RegistrationRecord[] records) {
        logger.debug("Updating {} registration records", records != null ? records.length : 0);

        if (records == null || records.length == 0) {
            logger.warn("No registration records to update");
            return;
        }

        try {
            for (RegistrationRecord record : records) {
                if (record == null || record.authenticator == null) {
                    logger.warn("Skipping null record or record with null authenticator");
                    continue;
                }
                //update SignCounter
                registrationRecordRepository.updateSignCounterByAuthenticatorKey(record);
                logger.info("Successfully updated registration record: username={}, AAID={}, KeyID={}",
                        record.username, record.authenticator.AAID, record.authenticator.KeyID);
            }
        } catch (Exception e) {
            logger.error("Failed to update registration records", e);
            throw new RuntimeException("Failed to update registration records", e);
        }
    }

    /**
     * Delete registration record by authenticator key
     * This method is used by DeregRequestProcessor
     *
     * @param key the authenticator key in format "AAID#KeyID"
     */
    public void deleteRegistrationRecord(String key) {
        logger.debug("Deleting registration record by key: {}", key);

        try {
            registrationRecordRepository.deleteByAuthenticatorKey(key);
            logger.info("Successfully deleted registration record: {}", key);
        } catch (Exception e) {
            logger.error("Failed to delete registration record by key: {}", key, e);
            throw new RuntimeException("Failed to delete registration record", e);
        }
    }
}

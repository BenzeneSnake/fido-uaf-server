package org.ebayopensource.fido.uaf.server.infrastructure.repository.repositoryImpl;

import org.ebayopensource.fido.uaf.core.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.server.infrastructure.entity.UAFRegistrationRecordEntity;
import org.ebayopensource.fido.uaf.server.infrastructure.jpa.dao.UAFRegistrationRecordDao;
import org.ebayopensource.fido.uaf.server.infrastructure.mapper.UAFRegistrationRecordMapper;
import org.ebayopensource.fido.uaf.server.infrastructure.repository.UAFRegistrationRecordRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository
public class UAFRegistrationRecordRepositoryImpl implements UAFRegistrationRecordRepository {

    private static final Logger logger = LoggerFactory.getLogger(UAFRegistrationRecordRepositoryImpl.class);

    private final UAFRegistrationRecordDao dao;
    private final UAFRegistrationRecordMapper mapper;

    @Autowired
    public UAFRegistrationRecordRepositoryImpl(
            UAFRegistrationRecordDao dao,
            UAFRegistrationRecordMapper mapper) {
        this.dao = dao;
        this.mapper = mapper;
    }

    @Override
    @Transactional
    public RegistrationRecord save(RegistrationRecord record) {
        logger.debug("Saving registration record for username: {}", record.username);

        try {
            UAFRegistrationRecordEntity entity = mapper.toEntity(record);
            UAFRegistrationRecordEntity savedEntity = dao.save(entity);
            RegistrationRecord savedRecord = mapper.toModel(savedEntity);

            logger.info("Successfully saved registration record: AAID={}, KeyID={}",
                    savedRecord.authenticator.AAID, savedRecord.authenticator.KeyID);

            return savedRecord;
        } catch (Exception e) {
            logger.error("Failed to save registration record for username: {}", record.username, e);
            throw new RuntimeException("Failed to save registration record", e);
        }
    }

    @Override
    public Optional<RegistrationRecord> findByAuthenticatorKey(String key) {
        logger.debug("Finding registration record by authenticator key: {}", key);

        try {
            return dao.findByAuthenticatorKey(key)
                    .map(mapper::toModel);
        } catch (Exception e) {
            logger.error("Failed to find registration record by key: {}", key, e);
            return Optional.empty();
        }
    }

    @Override
    public List<RegistrationRecord> findByUsername(String username) {
        logger.debug("Finding registration records for username: {}", username);

        try {
            List<UAFRegistrationRecordEntity> entities = dao.findByUsername(username);
            return mapper.toModelList(entities);
        } catch (Exception e) {
            logger.error("Failed to find registration records for username: {}", username, e);
            return List.of();
        }
    }

    @Override
    @Transactional
    public void deleteByAuthenticatorKey(String key) {
        logger.debug("Deleting registration record by authenticator key: {}", key);

        try {
            Optional<UAFRegistrationRecordEntity> entity = dao.findByAuthenticatorKey(key);
            entity.ifPresent(e -> {
                dao.delete(e);
                logger.info("Successfully deleted registration record: {}", key);
            });
        } catch (Exception e) {
            logger.error("Failed to delete registration record by key: {}", key, e);
            throw new RuntimeException("Failed to delete registration record", e);
        }
    }

    @Override
    @Transactional
    public void deleteByUsername(String username) {
        logger.debug("Deleting all registration records for username: {}", username);

        try {
            dao.deleteByUsername(username);
            logger.info("Successfully deleted all registration records for username: {}", username);
        } catch (Exception e) {
            logger.error("Failed to delete registration records for username: {}", username, e);
            throw new RuntimeException("Failed to delete registration records", e);
        }
    }

    @Override
    public boolean existsByAaidAndKeyId(String aaid, String keyId) {
        logger.debug("Checking if registration record exists: AAID={}, KeyID={}", aaid, keyId);

        try {
            return dao.existsByAaidAndKeyId(aaid, keyId);
        } catch (Exception e) {
            logger.error("Failed to check existence: AAID={}, KeyID={}", aaid, keyId, e);
            return false;
        }
    }
}

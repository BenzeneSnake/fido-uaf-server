package org.ebayopensource.fido.uaf.server.infrastructure.mapper;

import org.ebayopensource.fido.uaf.core.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.core.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.server.infrastructure.entity.UAFRegistrationRecordEntity;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class UAFRegistrationRecordMapper {

    /**
     * Convert RegistrationRecord domain model to JPA Entity
     */
    public UAFRegistrationRecordEntity toEntity(RegistrationRecord record) {
        if (record == null) {
            return null;
        }

        UAFRegistrationRecordEntity.UAFRegistrationRecordEntityBuilder builder = UAFRegistrationRecordEntity.builder()
                .publicKey(record.PublicKey)
                .signCounter(record.SignCounter)
                .authenticatorVersion(record.AuthenticatorVersion)
                .tcDisplayPNGCharacteristics(record.tcDisplayPNGCharacteristics)
                .username(record.username)
                .userId(record.userId)
                .deviceId(record.deviceId)
                .timeStamp(record.timeStamp)
                .status(record.status)
                .attestCert(record.attestCert)
                .attestDataToSign(record.attestDataToSign)
                .attestSignature(record.attestSignature)
                .attestVerifiedStatus(record.attestVerifiedStatus);

        // Map AuthenticatorRecord fields
        if (record.authenticator != null) {
            builder.aaid(record.authenticator.AAID)
                   .keyId(record.authenticator.KeyID)
                   .deviceId(record.authenticator.deviceId);

            // Use authenticator's username if record's username is null
            if (record.username == null && record.authenticator.username != null) {
                builder.username(record.authenticator.username);
            }
        }

        return builder.build();
    }

    /**
     * Convert JPA Entity to RegistrationRecord domain model
     */
    public RegistrationRecord toModel(UAFRegistrationRecordEntity entity) {
        if (entity == null) {
            return null;
        }

        RegistrationRecord record = new RegistrationRecord();

        // Map basic fields
        record.PublicKey = entity.getPublicKey();
        record.SignCounter = entity.getSignCounter();
        record.AuthenticatorVersion = entity.getAuthenticatorVersion();
        record.tcDisplayPNGCharacteristics = entity.getTcDisplayPNGCharacteristics();
        record.username = entity.getUsername();
        record.userId = entity.getUserId();
        record.deviceId = entity.getDeviceId();
        record.timeStamp = entity.getTimeStamp();
        record.status = entity.getStatus();
        record.attestCert = entity.getAttestCert();
        record.attestDataToSign = entity.getAttestDataToSign();
        record.attestSignature = entity.getAttestSignature();
        record.attestVerifiedStatus = entity.getAttestVerifiedStatus();

        // Map AuthenticatorRecord
        AuthenticatorRecord authenticator = new AuthenticatorRecord();
        authenticator.AAID = entity.getAaid();
        authenticator.KeyID = entity.getKeyId();
        authenticator.deviceId = entity.getDeviceId();
        authenticator.username = entity.getUsername();
        authenticator.status = entity.getStatus();

        record.authenticator = authenticator;

        return record;
    }

    /**
     * Convert list of entities to list of models
     */
    public List<RegistrationRecord> toModelList(List<UAFRegistrationRecordEntity> entities) {
        if (entities == null) {
            return null;
        }
        return entities.stream()
                .map(this::toModel)
                .collect(Collectors.toList());
    }
}

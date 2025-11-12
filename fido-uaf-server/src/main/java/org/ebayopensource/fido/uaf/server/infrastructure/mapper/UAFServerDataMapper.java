package org.ebayopensource.fido.uaf.server.infrastructure.mapper;

import org.ebayopensource.fido.uaf.server.infrastructure.entity.UAFServerDataEntity;
import org.ebayopensource.fido.uaf.server.infrastructure.model.UAFServerData;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

/**
 * UAF Server Data Mapper
 * Used for converting between Entity and VO
 */
@Component
public class UAFServerDataMapper {

    /**
     * Entity to VO
     */
    public UAFServerData toModel(UAFServerDataEntity entity) {
        if (entity == null) {
            return null;
        }

        return UAFServerData.builder()
                .id(entity.getId())
                .username(entity.getUsername())
                .serverDataString(entity.getServerDataString())
                .createdAt(entity.getCreatedAt())
                .expiresAt(entity.getExpiresAt())
                .build();
    }

    /**
     * VO to Entity
     */
    public UAFServerDataEntity toEntity(UAFServerData model) {
        if (model == null) {
            return null;
        }

        return UAFServerDataEntity.builder()
                .id(model.getId())
                .username(model.getUsername())
                .serverDataString(model.getServerDataString())
                .createdAt(model.getCreatedAt())
                .expiresAt(model.getExpiresAt())
                .build();
    }

    public List<UAFServerData> toModelList(List<UAFServerDataEntity> entities) {
        if (entities == null) {
            return null;
        }

        return entities.stream()
                .map(this::toModel)
                .collect(Collectors.toList());
    }
    
    public List<UAFServerDataEntity> toEntityList(List<UAFServerData> models) {
        if (models == null) {
            return null;
        }

        return models.stream()
                .map(this::toEntity)
                .collect(Collectors.toList());
    }
}

package org.ebayopensource.fido.uaf.server.infrastructure.repository.repositoryImpl;

import org.ebayopensource.fido.uaf.server.infrastructure.entity.UAFServerDataEntity;
import org.ebayopensource.fido.uaf.server.infrastructure.mapper.UAFServerDataMapper;
import org.ebayopensource.fido.uaf.server.infrastructure.model.UAFServerData;
import org.ebayopensource.fido.uaf.server.infrastructure.repository.UAFServerDataJpaRepository;
import org.ebayopensource.fido.uaf.server.infrastructure.repository.UAFServerDataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public class UAFServerDataJpaRepositoryImpl implements UAFServerDataRepository {

    private final UAFServerDataMapper mapper;
    private final UAFServerDataJpaRepository jpaRepository;

    @Autowired
    public UAFServerDataJpaRepositoryImpl(UAFServerDataMapper mapper, UAFServerDataJpaRepository jpaRepository) {
        this.mapper = mapper;
        this.jpaRepository = jpaRepository;
    }

    @Override
    public UAFServerData save(UAFServerData serverData) {
        UAFServerDataEntity entity = mapper.toEntity(serverData);
        UAFServerDataEntity savedEntity = jpaRepository.save(entity);
        return mapper.toModel(savedEntity);
    }

    @Override
    public Optional<UAFServerData> findValidByUsername(String username) {
        LocalDateTime now = LocalDateTime.now();
        return jpaRepository.findValidByUsername(username, now).map(mapper::toModel);
    }

    @Override
    public Optional<UAFServerData> findLatestByUsername(String username) {
        return jpaRepository.findFirstByUsernameOrderByCreatedAtDesc(username)
                .map(mapper::toModel);
    }

    @Override
    public List<UAFServerData> findAllByUsername(String username) {
        List<UAFServerDataEntity> entities = jpaRepository.findByUsername(username);
        return mapper.toModelList(entities);
    }

    @Override
    public void deleteByUsername(String username) {
        jpaRepository.deleteByUsername(username);
    }

    @Override
    public int deleteExpiredData() {
        LocalDateTime now = LocalDateTime.now();
        return jpaRepository.deleteExpiredData(now);
    }
}

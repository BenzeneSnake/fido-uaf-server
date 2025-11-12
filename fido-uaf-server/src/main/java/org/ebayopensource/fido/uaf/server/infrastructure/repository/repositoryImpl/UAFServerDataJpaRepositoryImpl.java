package org.ebayopensource.fido.uaf.server.infrastructure.repository.repositoryImpl;

import org.ebayopensource.fido.uaf.server.infrastructure.entity.UAFServerDataEntity;
import org.ebayopensource.fido.uaf.server.infrastructure.jpa.dao.UAFServerDataDao;
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
    private final UAFServerDataDao serverDataDao;

    @Autowired
    public UAFServerDataJpaRepositoryImpl(UAFServerDataMapper mapper, UAFServerDataDao serverDataDao) {
        this.mapper = mapper;
        this.serverDataDao = serverDataDao;
    }

    @Override
    public UAFServerData save(UAFServerData serverData) {
        UAFServerDataEntity entity = mapper.toEntity(serverData);
        UAFServerDataEntity savedEntity = serverDataDao.save(entity);
        return mapper.toModel(savedEntity);
    }

    @Override
    public Optional<UAFServerData> findValidByUsername(String username) {
        LocalDateTime now = LocalDateTime.now();
        return serverDataDao.findValidByUsername(username, now).map(mapper::toModel);
    }

    @Override
    public Optional<UAFServerData> findLatestByUsername(String username) {
        return serverDataDao.findFirstByUsernameOrderByCreatedAtDesc(username)
                .map(mapper::toModel);
    }

    @Override
    public List<UAFServerData> findAllByUsername(String username) {
        List<UAFServerDataEntity> entities = serverDataDao.findByUsername(username);
        return mapper.toModelList(entities);
    }

    @Override
    public void deleteByUsername(String username) {
        serverDataDao.deleteByUsername(username);
    }

    @Override
    public int deleteExpiredData() {
        LocalDateTime now = LocalDateTime.now();
        return serverDataDao.deleteExpiredData(now);
    }
}

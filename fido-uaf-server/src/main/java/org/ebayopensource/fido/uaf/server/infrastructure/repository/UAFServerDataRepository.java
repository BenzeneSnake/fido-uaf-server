package org.ebayopensource.fido.uaf.server.infrastructure.repository;

import org.ebayopensource.fido.uaf.server.infrastructure.model.UAFServerData;

import java.util.List;
import java.util.Optional;

public interface UAFServerDataRepository {

    UAFServerData save(UAFServerData serverData);

    Optional<UAFServerData> findValidByUsername(String username);

    Optional<UAFServerData> findLatestByUsername(String username);

    List<UAFServerData> findAllByUsername(String username);

    void deleteByUsername(String username);
    
    int deleteExpiredData();
}

package org.ebayopensource.fido.uaf.server.infrastructure.jpa.dao;

import org.ebayopensource.fido.uaf.server.infrastructure.entity.UAFServerDataEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UAFServerDataDao extends JpaRepository<UAFServerDataEntity, Long> {

    Optional<UAFServerDataEntity> findFirstByUsernameOrderByCreatedAtDesc(String username);

    List<UAFServerDataEntity> findByUsername(String username);


    @Query("SELECT s FROM UAFServerDataEntity s WHERE s.username = :username " +
            "AND (s.expiresAt IS NULL OR s.expiresAt > :now) " +
            "ORDER BY s.createdAt DESC LIMIT 1")
    Optional<UAFServerDataEntity> findValidByUsername(@Param("username") String username,
                                                      @Param("now") LocalDateTime now);

    void deleteByUsername(String username);

    @Modifying
    @Query("DELETE FROM UAFServerDataEntity s WHERE s.expiresAt IS NOT NULL AND s.expiresAt < :now")
    int deleteExpiredData(@Param("now") LocalDateTime now);


}

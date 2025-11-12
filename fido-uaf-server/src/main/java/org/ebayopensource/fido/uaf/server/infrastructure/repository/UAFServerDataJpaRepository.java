package org.ebayopensource.fido.uaf.server.infrastructure.repository;

import org.ebayopensource.fido.uaf.server.infrastructure.entity.UAFServerDataEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * UAF Server Data Repository H2 Implementation
 * Uses JPA and H2 Database
 */
@Repository
public interface UAFServerDataJpaRepository {

    /**
     * 根據用戶名查找最新的 server data
     */
    Optional<UAFServerDataEntity> findFirstByUsernameOrderByCreatedAtDesc(String username);

    /**
     * 根據用戶名查找所有 server data
     */
    List<UAFServerDataEntity> findByUsername(String username);
    
    /**
     * 根據用戶名和未過期條件查找
     */
    Optional<UAFServerDataEntity> findValidByUsername(@Param("username") String username,
                                                      @Param("now") LocalDateTime now);

    /**
     * 根據用戶名刪除資料
     */
    void deleteByUsername(String username);

    /**
     * 刪除過期的資料
     */
    @Modifying
    @Query("DELETE FROM UAFServerDataEntity s WHERE s.expiresAt IS NOT NULL AND s.expiresAt < :now")
    int deleteExpiredData(@Param("now") LocalDateTime now);

}

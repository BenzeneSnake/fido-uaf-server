package org.ebayopensource.fido.uaf.server.infrastructure.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UAFServerData {

    private Long id;

    private String username;

    private String serverDataString;

    private LocalDateTime createdAt;
    
    private LocalDateTime expiresAt;
}

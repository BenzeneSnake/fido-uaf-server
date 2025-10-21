# eBay UAF 程式碼整合步驟文件

## 專案概述

本文件說明如何將 eBay UAF (Universal Authentication Framework) 的原始碼直接整合到現有的 WebAuthn Spring Boot 專案中，而非透過 Maven 依賴的方式。

---

## 一、專案結構分析

### eBay UAF 專案組成

eBay UAF 專案位於 `C:\side_project\UAF`，包含以下模組：

#### 1. **fido-uaf-core** (核心協議實作)
- **路徑**: `UAF/fido-uaf-core`
- **功能**: FIDO UAF 協議的核心實作
- **主要包結構**:
  ```
  org.ebayopensource.fido.uaf
  ├── crypto/         - 加密相關工具 (RSA, SHA, HMAC, X509, Notary 等)
  ├── msg/            - UAF 協議訊息模型 (Request/Response)
  ├── ops/            - 核心操作處理 (註冊/認證處理)
  ├── storage/        - 儲存介面定義 (StorageInterface, RegistrationRecord)
  ├── tlv/            - TLV (Type-Length-Value) 編碼處理
  └── ri/client/      - 參考實作客戶端工具
  ```

#### 2. **fidouaf** (伺服器參考實作)
- **路徑**: `UAF/fidouaf`
- **功能**: Jersey 服務應用，展示 UAF 協議的伺服器端實作
- **主要包結構**:
  ```
  org.ebayopensource.fidouaf
  ├── res/            - REST 資源 (FidoUafResource - 主要端點)
  ├── res/util/       - 處理工具 (ProcessResponse, FetchRequest, StorageImpl)
  ├── RPserver/msg/   - RP Server 訊息模型
  ├── facets/         - Trusted Facets 管理
  └── stats/          - 統計與監控 (Dash, Info)
  ```

---

## 二、依賴分析

### fido-uaf-core 依賴
```xml
<dependencies>
    <!-- JSON 處理 -->
    <dependency>
        <groupId>com.google.code.gson</groupId>
        <artifactId>gson</artifactId>
        <version>2.8.9</version>
    </dependency>

    <!-- 編碼工具 -->
    <dependency>
        <groupId>commons-codec</groupId>
        <artifactId>commons-codec</artifactId>
        <version>1.9</version>
    </dependency>

    <!-- 加密庫 -->
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk15on</artifactId>
        <version>1.51</version>
    </dependency>
</dependencies>
```

### fidouaf 依賴
```xml
<dependencies>
    <!-- Jersey REST 框架 -->
    <dependency>
        <groupId>com.sun.jersey</groupId>
        <artifactId>jersey-server</artifactId>
        <version>1.8</version>
    </dependency>
    <dependency>
        <groupId>com.sun.jersey</groupId>
        <artifactId>jersey-json</artifactId>
        <version>1.8</version>
    </dependency>

    <!-- fido-uaf-core (內部依賴) -->
    <dependency>
        <groupId>org.ebayopensource</groupId>
        <artifactId>fido-uaf-core</artifactId>
        <version>0.0.1-SNAPSHOT</version>
    </dependency>
</dependencies>
```

---

## 三、整合策略

### 目標架構

```
fido-uaf-server (現有專案)
├── src/main/java/
│   ├── com.webauthn.app/           (現有 WebAuthn 代碼)
│   │   ├── authenticator/
│   │   ├── service/
│   │   ├── web/
│   │   └── ...
│   └── org.ebayopensource.fido.uaf/ (新增 UAF 代碼)
│       ├── crypto/                  (從 fido-uaf-core 複製)
│       ├── msg/                     (從 fido-uaf-core 複製)
│       ├── ops/                     (從 fido-uaf-core 複製)
│       ├── storage/                 (從 fido-uaf-core 複製)
│       ├── tlv/                     (從 fido-uaf-core 複製)
│       └── server/                  (從 fidouaf 改造)
│           ├── resource/            (REST 控制器)
│           ├── service/             (UAF 業務邏輯)
│           └── storage/             (儲存實作 - 整合到現有 DB)
```

### 整合原則

1. **包名保持一致**: 保留 eBay UAF 的原始包名 `org.ebayopensource.fido.uaf`，避免大量修改
2. **框架轉換**: 將 Jersey (JAX-RS) 轉換為 Spring MVC
3. **儲存整合**: 實作 `StorageInterface`，整合到現有的 H2 資料庫
4. **雙協議並存**: WebAuthn 和 UAF 獨立運作，互不干擾

---

## 四、整合步驟

### **第一階段：複製 fido-uaf-core 核心代碼**

#### 步驟 1.1：建立 UAF 包目錄結構

```bash
# 在現有專案中建立目錄
mkdir -p src/main/java/org/ebayopensource/fido/uaf/crypto
mkdir -p src/main/java/org/ebayopensource/fido/uaf/msg
mkdir -p src/main/java/org/ebayopensource/fido/uaf/ops
mkdir -p src/main/java/org/ebayopensource/fido/uaf/storage
mkdir -p src/main/java/org/ebayopensource/fido/uaf/tlv
```

#### 步驟 1.2：複製核心包代碼

**優先順序**：從低依賴到高依賴

1. **msg 包** (訊息模型 - 無外部依賴)
   ```bash
   cp -r C:/side_project/UAF/fido-uaf-core/src/main/java/org/ebayopensource/fido/uaf/msg/* \
         src/main/java/org/ebayopensource/fido/uaf/msg/
   ```

   **檔案清單**:
   - `AuthenticationRequest.java`
   - `AuthenticationResponse.java`
   - `RegistrationRequest.java`
   - `RegistrationResponse.java`
   - `OperationHeader.java`
   - `Policy.java`
   - `Version.java`
   - `Extension.java`
   - 等 20 個訊息模型類別

2. **crypto 包** (加密工具 - 依賴 BouncyCastle)
   ```bash
   cp -r C:/side_project/UAF/fido-uaf-core/src/main/java/org/ebayopensource/fido/uaf/crypto/* \
         src/main/java/org/ebayopensource/fido/uaf/crypto/
   ```

   **檔案清單**:
   - `Notary.java` (介面 - 重要)
   - `RSA.java`
   - `SHA.java`
   - `HMAC.java`
   - `KeyCodec.java`
   - `X509.java`
   - `BCrypt.java`
   - `NamedCurve.java`
   - `CertificateValidator.java` (介面)
   - `CertificateValidatorImpl.java`

3. **storage 包** (儲存介面 - 依賴 msg)
   ```bash
   cp -r C:/side_project/UAF/fido-uaf-core/src/main/java/org/ebayopensource/fido/uaf/storage/* \
         src/main/java/org/ebayopensource/fido/uaf/storage/
   ```

   **檔案清單**:
   - `StorageInterface.java` (介面 - 重要)
   - `RegistrationRecord.java`
   - `AuthenticatorRecord.java`
   - `DuplicateKeyException.java`
   - `SystemErrorException.java`

4. **tlv 包** (TLV 編碼處理)
   ```bash
   cp -r C:/side_project/UAF/fido-uaf-core/src/main/java/org/ebayopensource/fido/uaf/tlv/* \
         src/main/java/org/ebayopensource/fido/uaf/tlv/
   ```

5. **ops 包** (核心操作 - 依賴前面所有包)
   ```bash
   cp -r C:/side_project/UAF/fido-uaf-core/src/main/java/org/ebayopensource/fido/uaf/ops/* \
         src/main/java/org/ebayopensource/fido/uaf/ops/
   ```

   **檔案清單**:
   - `RegistrationRequestGeneration.java`
   - `RegistrationResponseProcessing.java`
   - `AuthenticationRequestGeneration.java`
   - `AuthenticationResponseProcessing.java`
   - `ServerDataExpiredException.java`
   - `ServerDataSignatureNotMatchException.java`

#### 步驟 1.3：更新 pom.xml 添加依賴

```xml
<!-- 在現有專案的 pom.xml 中添加 -->
<dependencies>
    <!-- Gson (如果尚未添加) -->
    <dependency>
        <groupId>com.google.code.gson</groupId>
        <artifactId>gson</artifactId>
        <version>2.8.9</version>
    </dependency>

    <!-- Apache Commons Codec -->
    <dependency>
        <groupId>commons-codec</groupId>
        <artifactId>commons-codec</artifactId>
        <version>1.15</version>
    </dependency>

    <!-- BouncyCastle Crypto -->
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk15on</artifactId>
        <version>1.70</version>
    </dependency>
</dependencies>
```

#### 步驟 1.4：編譯驗證

```bash
./mvnw clean compile
```

**預期結果**: 所有 UAF 核心代碼編譯成功

---

### **第二階段：改造 fidouaf Server 代碼**

#### 步驟 2.1：建立 UAF Server 包結構

```bash
mkdir -p src/main/java/org/ebayopensource/fido/uaf/server/resource
mkdir -p src/main/java/org/ebayopensource/fido/uaf/server/service
mkdir -p src/main/java/org/ebayopensource/fido/uaf/server/storage
mkdir -p src/main/java/org/ebayopensource/fido/uaf/server/model
```

#### 步驟 2.2：複製並改造核心資源

**不直接複製的檔案** (需要從 Jersey 轉換為 Spring MVC):
- `FidoUafResource.java` → 需要改造為 Spring `@RestController`

**可直接複製的工具類**:

1. **複製處理工具**
   ```bash
   cp C:/side_project/UAF/fidouaf/src/main/java/org/ebayopensource/fidouaf/res/util/ProcessResponse.java \
      src/main/java/org/ebayopensource/fido/uaf/server/service/

   cp C:/side_project/UAF/fidouaf/src/main/java/org/ebayopensource/fidouaf/res/util/FetchRequest.java \
      src/main/java/org/ebayopensource/fido/uaf/server/service/

   cp C:/side_project/UAF/fidouaf/src/main/java/org/ebayopensource/fidouaf/res/util/DeregRequestProcessor.java \
      src/main/java/org/ebayopensource/fido/uaf/server/service/
   ```

2. **複製訊息模型**
   ```bash
   cp -r C:/side_project/UAF/fidouaf/src/main/java/org/ebayopensource/fidouaf/RPserver/msg/* \
         src/main/java/org/ebayopensource/fido/uaf/server/model/
   ```

3. **複製 Facets 相關**
   ```bash
   mkdir -p src/main/java/org/ebayopensource/fido/uaf/server/facets
   cp -r C:/side_project/UAF/fidouaf/src/main/java/org/ebayopensource/fidouaf/facets/* \
         src/main/java/org/ebayopensource/fido/uaf/server/facets/
   ```

#### 步驟 2.3：修改包引用

在複製的檔案中，需要更新以下引用：

```java
// 舊引用
import org.ebayopensource.fidouaf.res.util.*;
import org.ebayopensource.fidouaf.RPserver.msg.*;
import org.ebayopensource.fidouaf.facets.*;

// 新引用
import org.ebayopensource.fido.uaf.server.service.*;
import org.ebayopensource.fido.uaf.server.model.*;
import org.ebayopensource.fido.uaf.server.facets.*;
```

---

### **第三階段：實作 Spring MVC 控制器**

#### 步驟 3.1：建立 UAFController

**參考**: `FidoUafResource.java` (Jersey) → `UAFController.java` (Spring MVC)

```java
package com.webauthn.app.web;

import org.ebayopensource.fido.uaf.msg.*;
import org.ebayopensource.fido.uaf.storage.*;
import org.ebayopensource.fido.uaf.server.service.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/uaf/v1")
public class UAFController {

    private final UAFRegistrationService registrationService;
    private final UAFAuthenticationService authenticationService;
    private final UAFStorageService storageService;

    // 建構子注入
    public UAFController(UAFRegistrationService registrationService,
                         UAFAuthenticationService authenticationService,
                         UAFStorageService storageService) {
        this.registrationService = registrationService;
        this.authenticationService = authenticationService;
        this.storageService = storageService;
    }

    // 註冊請求
    @GetMapping("/public/regRequest/{username}")
    public RegistrationRequest[] getRegistrationRequest(@PathVariable String username) {
        return registrationService.generateRegistrationRequest(username);
    }

    // 註冊回應
    @PostMapping("/public/regResponse")
    public RegistrationRecord[] processRegistrationResponse(@RequestBody String payload) {
        return registrationService.processRegistrationResponse(payload);
    }

    // 認證請求
    @GetMapping("/public/authRequest")
    public AuthenticationRequest[] getAuthenticationRequest() {
        return authenticationService.generateAuthenticationRequest();
    }

    // 認證回應
    @PostMapping("/public/authResponse")
    public AuthenticatorRecord[] processAuthenticationResponse(@RequestBody String payload) {
        return authenticationService.processAuthenticationResponse(payload);
    }

    // 註銷
    @PostMapping("/public/deregRequest")
    public String deregister(@RequestBody String payload) {
        return registrationService.processDeregistration(payload);
    }

    // Facets
    @GetMapping("/public/uaf/facets")
    @ResponseBody
    public Facets getFacets() {
        return storageService.getTrustedFacets();
    }
}
```

#### 步驟 3.2：建立 Service 層

**UAFRegistrationService.java**:
```java
package com.webauthn.app.service;

import org.ebayopensource.fido.uaf.msg.*;
import org.ebayopensource.fido.uaf.storage.*;
import org.ebayopensource.fido.uaf.server.service.*;
import org.springframework.stereotype.Service;

@Service
public class UAFRegistrationService {

    private final UAFStorageService storageService;
    private final FetchRequest fetchRequest;
    private final ProcessResponse processResponse;

    public UAFRegistrationService(UAFStorageService storageService) {
        this.storageService = storageService;
        // 初始化處理器 (從 fidouaf 複製的工具)
        this.fetchRequest = new FetchRequest(getAppId(), getAllowedAaids());
        this.processResponse = new ProcessResponse();
    }

    public RegistrationRequest[] generateRegistrationRequest(String username) {
        RegistrationRequest[] regReq = new RegistrationRequest[1];
        regReq[0] = fetchRequest.getRegistrationRequest(username);
        return regReq;
    }

    public RegistrationRecord[] processRegistrationResponse(String payload) {
        // 使用 ProcessResponse 處理
        // 整合到 storageService
        return processResponse.processRegResponse(...);
    }

    // 其他方法...
}
```

---

### **第四階段：整合儲存層**

#### 步驟 4.1：實作 StorageInterface

**UAFStorageImpl.java**:
```java
package com.webauthn.app.storage;

import org.ebayopensource.fido.uaf.storage.*;
import org.springframework.stereotype.Component;
import javax.persistence.*;

@Component
public class UAFStorageImpl implements StorageInterface {

    private final UAFRegistrationRecordRepository repository;

    public UAFStorageImpl(UAFRegistrationRecordRepository repository) {
        this.repository = repository;
    }

    @Override
    public void store(RegistrationRecord[] records)
            throws DuplicateKeyException, SystemErrorException {
        // 轉換為 JPA Entity 並儲存
        for (RegistrationRecord record : records) {
            UAFRegistrationEntity entity = convertToEntity(record);
            repository.save(entity);
        }
    }

    @Override
    public RegistrationRecord readRegistrationRecord(String key) {
        UAFRegistrationEntity entity = repository.findByAuthenticatorPublicKeyId(key);
        return convertToRecord(entity);
    }

    @Override
    public void storeServerDataString(String username, String serverDataString) {
        // 實作伺服器資料儲存
    }

    @Override
    public String getUsername(String serverDataString) {
        // 實作查詢邏輯
        return null;
    }

    @Override
    public void update(RegistrationRecord[] records) {
        // 實作更新邏輯
    }
}
```

#### 步驟 4.2：建立 JPA Entity

**UAFRegistrationEntity.java**:
```java
package com.webauthn.app.entity;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "uaf_registration")
public class UAFRegistrationEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", nullable = false)
    private String username;

    @Column(name = "authenticator_pub_key_id", unique = true, nullable = false)
    private String authenticatorPublicKeyId;

    @Lob
    @Column(name = "public_key", nullable = false)
    private String publicKey;

    @Column(name = "device_id")
    private String deviceId;

    @Column(name = "sign_counter")
    private Long signCounter;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    // Getters & Setters
}
```

#### 步驟 4.3：建立 Repository

```java
package com.webauthn.app.repository;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UAFRegistrationRecordRepository extends JpaRepository<UAFRegistrationEntity, Long> {
    UAFRegistrationEntity findByAuthenticatorPublicKeyId(String keyId);
    List<UAFRegistrationEntity> findByUsername(String username);
}
```

---

### **第五階段：實作 Notary (伺服器簽章)**

#### 步驟 5.1：建立 Notary 實作

**參考**: `fidouaf/res/util/NotaryImpl.java`

```java
package com.webauthn.app.crypto;

import org.ebayopensource.fido.uaf.crypto.Notary;
import org.springframework.stereotype.Component;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
public class UAFNotaryImpl implements Notary {

    private static final String SECRET_KEY = "your-secret-key-here";
    private static final String ALGORITHM = "HmacSHA256";

    @Override
    public String sign(String dataToSign) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), ALGORITHM);
            mac.init(keySpec);
            byte[] signature = mac.doFinal(dataToSign.getBytes());
            return Base64.getUrlEncoder().encodeToString(signature);
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign data", e);
        }
    }

    @Override
    public boolean verify(String dataToSign, String signature) {
        String computed = sign(dataToSign);
        return computed.equals(signature);
    }
}
```

---

### **第六階段：配置與測試**

#### 步驟 6.1：更新 application.yml

```yaml
uaf:
  enabled: true
  app-id: http://localhost:8080/api/uaf/v1/public/uaf/facets
  facet-ids:
    - http://localhost:8080
    - http://localhost:4200
  allowed-aaids:
    - EBA0#0001
    - 0015#0001
    - 0012#0002
```

#### 步驟 6.2：建立配置類

```java
package com.webauthn.app.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "uaf")
public class UAFProperties {
    private boolean enabled;
    private String appId;
    private List<String> facetIds;
    private List<String> allowedAaids;

    // Getters & Setters
}
```

#### 步驟 6.3：編譯與測試

```bash
# 編譯
./mvnw clean compile

# 運行
./mvnw spring-boot:run

# 測試端點
curl http://localhost:8080/api/uaf/v1/public/regRequest/testuser
```

---

## 五、需要特別注意的檔案

### 高優先級 (必須複製並理解)

| 檔案 | 路徑 | 用途 |
|------|------|------|
| `StorageInterface.java` | `fido-uaf-core/storage/` | 儲存介面定義 |
| `Notary.java` | `fido-uaf-core/crypto/` | 簽章介面 |
| `RegistrationResponseProcessing.java` | `fido-uaf-core/ops/` | 註冊處理核心 |
| `AuthenticationResponseProcessing.java` | `fido-uaf-core/ops/` | 認證處理核心 |
| `ProcessResponse.java` | `fidouaf/res/util/` | 回應處理工具 |
| `FetchRequest.java` | `fidouaf/res/util/` | 請求生成工具 |

### 中優先級 (可直接複製)

| 包 | 用途 |
|----|------|
| `msg/` | 所有訊息模型 |
| `crypto/` | 加密工具 (除 Notary 實作外) |
| `tlv/` | TLV 編碼 |

### 低優先級 (可選)

| 包/檔案 | 用途 |
|---------|------|
| `stats/Dash.java` | 統計監控 (僅供測試) |
| `ri/client/` | 客戶端參考實作 (不需要) |

---

## 六、Jersey 到 Spring MVC 轉換對照表

| Jersey (JAX-RS) | Spring MVC | 說明 |
|-----------------|------------|------|
| `@Path("/v1")` | `@RequestMapping("/api/uaf/v1")` | 路徑映射 |
| `@GET` | `@GetMapping` | GET 請求 |
| `@POST` | `@PostMapping` | POST 請求 |
| `@PathParam("id")` | `@PathVariable("id")` | 路徑參數 |
| `@Consumes(MediaType.APPLICATION_JSON)` | `@RequestBody` | 消費 JSON |
| `@Produces(MediaType.APPLICATION_JSON)` | `@ResponseBody` | 產生 JSON |
| `@Context UriInfo` | `ServletUriComponentsBuilder` | URI 資訊 |

---

## 七、整合檢查清單

### 第一階段檢查
- [ ] `fido-uaf-core/msg` 包複製完成
- [ ] `fido-uaf-core/crypto` 包複製完成
- [ ] `fido-uaf-core/storage` 包複製完成
- [ ] `fido-uaf-core/ops` 包複製完成
- [ ] `fido-uaf-core/tlv` 包複製完成
- [ ] Maven 依賴添加完成 (Gson, Commons-Codec, BouncyCastle)
- [ ] 編譯成功，無錯誤

### 第二階段檢查
- [ ] `fidouaf` 工具類複製完成
- [ ] `fidouaf` 訊息模型複製完成
- [ ] `fidouaf` Facets 相關複製完成
- [ ] 包引用更新完成

### 第三階段檢查
- [ ] `UAFController` 建立完成
- [ ] `UAFRegistrationService` 建立完成
- [ ] `UAFAuthenticationService` 建立完成
- [ ] Spring MVC 端點測試通過

### 第四階段檢查
- [ ] `UAFStorageImpl` 實作完成
- [ ] `UAFRegistrationEntity` 建立完成
- [ ] `UAFRegistrationRecordRepository` 建立完成
- [ ] 資料庫整合測試通過

### 第五階段檢查
- [ ] `UAFNotaryImpl` 實作完成
- [ ] 簽章驗證測試通過

### 第六階段檢查
- [ ] `application.yml` 配置完成
- [ ] `UAFProperties` 建立完成
- [ ] 端到端測試通過
- [ ] API 文件更新完成

---

## 八、常見問題

### Q1: 為什麼不直接使用 Maven 依賴？
**A**: eBay UAF 專案較舊，可能不在公開的 Maven 倉庫中，且需要自訂修改以整合到 Spring Boot 環境。

### Q2: Jersey 和 Spring MVC 能共存嗎？
**A**: 可以，但不建議。建議全部改為 Spring MVC 以保持專案一致性。

### Q3: 如何處理 BouncyCastle 版本衝突？
**A**: 使用較新的 BouncyCastle 版本 (1.70+)，並確保所有加密代碼相容。

### Q4: UAF 和 WebAuthn 能同時運行嗎？
**A**: 可以，它們是獨立的協議，透過不同的 API 端點暴露 (`/api/webauthn/*` vs `/api/uaf/*`)。

---

## 九、參考資源

- **eBay UAF GitHub**: https://github.com/eBay/UAF
- **FIDO UAF Specification**: https://fidoalliance.org/specs/fido-uaf-v1.1-ps-20170202/
- **Spring Boot 文件**: https://spring.io/projects/spring-boot
- **BouncyCastle 文件**: https://www.bouncycastle.org/java.html

---

## 十、下一步行動

1. **立即開始**: 執行第一階段步驟 1.1 - 建立目錄結構
2. **按順序進行**: 嚴格按照第一階段 → 第六階段的順序執行
3. **每階段驗證**: 完成每個階段後立即編譯測試
4. **保留原始碼**: 保留 eBay UAF 原始專案作為參考

---

**文件版本**: 1.0
**建立日期**: 2025-10-21
**適用專案**: fido-uaf-server (WebAuthn + UAF 整合)

# eBay UAF 整合規劃文件

## 專案背景

本專案目前基於 **FIDO2/WebAuthn** 標準實現無密碼認證系統，並與 Keycloak 整合進行身份管理。為了擴展支援更多 FIDO 認證場景，計劃整合 **eBay UAF (Universal Authentication Framework)** 核心邏輯，以支援 FIDO UAF 1.0 協議。

---

## 現有架構分析

### 技術棧
- **框架**: Spring Boot 3.5.5
- **Java 版本**: Java 17
- **WebAuthn 函式庫**: Yubico WebAuthn Server Core 2.7.0
- **資料庫**: H2 (開發環境)
- **身份管理**: Keycloak
- **API 文件**: SpringDoc OpenAPI

### 核心組件

#### 1. 認證流程 (WebAuthn)
- **RegistrationService**: 處理註冊邏輯，包含 WebAuthn 驗證、Keycloak 用戶建立
- **AuthController**: 提供 REST API 端點
  - `/api/register` - 註冊階段一 (暫存用戶)
  - `/api/finishauth` - 註冊階段二 (完成認證並建立 Keycloak 用戶)
  - `/api/login` - 登入起始
  - `/api/welcome` - 完成登入

#### 2. 資料層
- **UserRepository**: AppUser 管理
- **AuthenticatorRepository**: Authenticator 憑證管理
- **RegistrationRepository**: 整合 User 和 Authenticator 儲存庫

#### 3. 快取層
- **WebAuthnRequestCache**: 暫存 PublicKeyCredentialCreationOptions 和 AssertionRequest

#### 4. 安全性設計
- 兩階段註冊流程 (PENDING → COMPLETED)
- 交易一致性保證 (DB + Keycloak 同步)
- Rollback 機制處理失敗情況

---

## eBay UAF 架構分析

### 核心組件

#### 1. fido-uaf-core (核心函式庫)
提供 FIDO UAF 協議的實作基礎：

```xml
<dependency>
    <groupId>org.ebayopensource</groupId>
    <artifactId>fido-uaf-core</artifactId>
</dependency>
```

**主要介面**:
- `StorageInterface` - 儲存抽象層，允許自訂儲存實作
- `Notary` - 伺服器資料簽章與驗證介面

#### 2. fidouaf (參考伺服器實作)
提供 Jersey 服務範例，展示 UAF 協議端點：

**API 端點結構**:
```
註冊流程:
  GET  /v1/public/regRequest/{username}  - 取得註冊請求
  POST /v1/public/regResponse            - 提交註冊回應

認證流程:
  GET  /v1/public/authRequest            - 取得認證請求
  POST /v1/public/authResponse           - 提交認證回應

註銷流程:
  POST /v1/public/deregRequest           - 註銷裝置
```

**工具端點**:
- `/v1/registrations` - 查看註冊記錄
- `/v1/stats` - 統計資訊
- `/v1/history` - 歷史紀錄

---

## 整合策略

### 目標
1. 在現有 WebAuthn 系統基礎上，增加對 FIDO UAF 1.0 的支援
2. 保持與 Keycloak 的整合
3. 實現統一的認證入口，支援多種 FIDO 協議

### 整合方案

#### 選項 A: 雙協議並存 (推薦)
```
/api/webauthn/*  - WebAuthn (FIDO2) 端點
/api/uaf/*       - UAF (FIDO UAF 1.0) 端點
```

**優點**:
- 清晰的職責分離
- 易於維護和測試
- 支援不同客戶端需求

**缺點**:
- 需要維護兩套認證流程

#### 選項 B: 整合適配層
建立統一的認證抽象層，內部根據協議類型路由：

```java
public interface AuthenticationProtocol {
    RegistrationChallenge startRegistration(String username);
    RegistrationResult finishRegistration(String credential);
    AuthenticationChallenge startAuthentication(String username);
    AuthenticationResult finishAuthentication(String credential);
}

// WebAuthn 實作
public class WebAuthnProtocol implements AuthenticationProtocol { ... }

// UAF 實作
public class UAFProtocol implements AuthenticationProtocol { ... }
```

**優點**:
- 統一的業務邏輯處理
- 容易擴展新協議

**缺點**:
- 增加抽象層複雜度
- 需要重構現有代碼

---

## 實作步驟規劃

### 第一階段: 環境準備與依賴整合
1. **添加 Maven 依賴**
   ```xml
   <dependency>
       <groupId>org.ebayopensource</groupId>
       <artifactId>fido-uaf-core</artifactId>
       <version>0.0.1-SNAPSHOT</version>
   </dependency>
   ```

2. **研究 eBay UAF 原始碼結構**
   - Clone eBay UAF repository
   - 分析 StorageInterface 實作範例
   - 理解 Notary 簽章機制

### 第二階段: 儲存層設計
1. **實作 UAF StorageInterface**
   ```java
   public class H2UAFStorage implements StorageInterface {
       // 使用現有的 H2 資料庫
       // 整合 RegistrationRepository
   }
   ```

2. **設計資料庫 Schema**
   ```sql
   CREATE TABLE uaf_registration (
       id BIGINT AUTO_INCREMENT PRIMARY KEY,
       username VARCHAR(255) NOT NULL,
       key_id VARCHAR(512) NOT NULL,
       public_key TEXT NOT NULL,
       app_id VARCHAR(512),
       counter BIGINT,
       created_at TIMESTAMP,
       UNIQUE(username, key_id)
   );
   ```

### 第三階段: UAF 端點實作
1. **建立 UAFController**
   ```java
   @RestController
   @RequestMapping("/api/uaf")
   public class UAFController {
       // 註冊流程
       @GetMapping("/regRequest/{username}")
       public UafResponse getRegistrationRequest(@PathVariable String username);

       @PostMapping("/regResponse")
       public UafResponse processRegistrationResponse(@RequestBody String uafResponse);

       // 認證流程
       @GetMapping("/authRequest")
       public UafResponse getAuthenticationRequest();

       @PostMapping("/authResponse")
       public UafResponse processAuthenticationResponse(@RequestBody String uafResponse);
   }
   ```

2. **整合 Keycloak 流程**
   - UAF 註冊成功後建立 Keycloak 用戶
   - 保持與現有 WebAuthn 流程一致的交易管理

### 第四階段: 安全性與配置
1. **實作 Notary 介面**
   ```java
   public class AppNotary implements Notary {
       // 實作伺服器資料簽章
       // 使用 JWK/JWT 或其他簽章方案
   }
   ```

2. **添加配置項**
   ```yaml
   uaf:
     enabled: true
     app-id: https://localhost:8080
     facet-id: https://localhost:8080
     trusted-facets:
       - https://localhost:8080
   ```

### 第五階段: 測試與驗證
1. 單元測試
   - UAF 註冊流程測試
   - UAF 認證流程測試
   - 儲存層測試

2. 整合測試
   - 與 Keycloak 整合測試
   - 交易回滾測試

3. 端到端測試
   - 使用 FIDO UAF 客戶端測試完整流程

---

## 技術挑戰與風險

### 1. 協議版本差異
- **問題**: WebAuthn (FIDO2) 與 UAF 1.0 在資料結構和流程上有差異
- **解決方案**: 建立明確的協議抽象層，避免混淆

### 2. eBay UAF 專案維護狀態
- **問題**: eBay UAF 專案可能已停止維護
- **解決方案**:
  - 評估是否自行維護 fork 版本
  - 考慮僅使用核心邏輯，自行實作周邊功能

### 3. Keycloak 整合複雜度
- **問題**: 需要同時支援兩種協議與 Keycloak 同步
- **解決方案**:
  - 統一用戶管理介面
  - 使用策略模式處理不同協議

### 4. 測試覆蓋率
- **問題**: UAF 客戶端實作較少，測試困難
- **解決方案**:
  - 使用 eBay UAF 提供的測試工具
  - 建立模擬客戶端進行測試

---

## 時程規劃

| 階段 | 預估時間 | 交付物 |
|------|---------|--------|
| 環境準備與依賴整合 | 1-2 天 | Maven 依賴配置、原始碼分析報告 |
| 儲存層設計 | 2-3 天 | StorageInterface 實作、資料庫 Schema |
| UAF 端點實作 | 3-5 天 | UAFController、核心業務邏輯 |
| 安全性與配置 | 2-3 天 | Notary 實作、配置文件 |
| 測試與驗證 | 3-4 天 | 測試套件、測試報告 |
| **總計** | **11-17 天** | 完整的 UAF 整合系統 |

---

## 成功指標

1. 能夠透過 UAF 協議完成裝置註冊
2. 能夠透過 UAF 協議完成使用者認證
3. UAF 用戶資料正確同步至 Keycloak
4. 測試覆蓋率達到 80% 以上
5. API 文件完整且準確
6. 與現有 WebAuthn 流程互不干擾

---

## 參考資源

### 官方文件
- [FIDO UAF Specification](https://fidoalliance.org/specs/fido-uaf-v1.1-ps-20170202/fido-uaf-overview-v1.1-ps-20170202.html)
- [eBay UAF GitHub Repository](https://github.com/eBay/UAF)
- [FIDO UAF Protocol](https://fidoalliance.org/specifications/)

### 現有專案文件
- `README.md` - 專案說明
- `WebAuthn註冊流程分析.md` - WebAuthn 流程分析
- `Keycloak整合精進計畫.md` - Keycloak 整合計畫

---

## 附錄

### A. WebAuthn vs UAF 對照表

| 特性 | WebAuthn (FIDO2) | UAF (FIDO UAF 1.0) |
|------|------------------|---------------------|
| 標準版本 | FIDO2 | FIDO UAF 1.0 |
| 瀏覽器支援 | 廣泛支援 | 需要專用客戶端 |
| 平台支援 | Web、Android、iOS | 主要為 Android |
| 協議複雜度 | 較簡單 | 較複雜 |
| 認證器類型 | Platform + Roaming | 主要為 Platform |
| 使用場景 | 現代 Web 應用 | 企業行動應用 |

### B. 整合檢查清單

- [ ] eBay UAF 依賴添加完成
- [ ] StorageInterface 實作完成
- [ ] Notary 介面實作完成
- [ ] UAF 資料庫 Schema 建立
- [ ] UAFController 端點實作
- [ ] Keycloak 整合測試通過
- [ ] 單元測試覆蓋率 > 80%
- [ ] API 文件更新
- [ ] 安全性審查完成
- [ ] 效能測試通過

---

**文件版本**: 1.0
**最後更新**: 2025-10-21
**負責人**: [待填寫]
**審核人**: [待填寫]

package com.webauthn.app.web;

import com.webauthn.app.common.api.RestResult;
import com.webauthn.app.common.api.RestStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * UAF 測試控制器
 *
 * 提供 UAF 整合過程中的測試端點和測試頁面
 * 這個控制器僅供開發和測試使用，生產環境應該移除或禁用
 *
 * 測試階段：
 * 1. 基礎 API 測試 - 確認端點可訪問
 * 2. 資料庫整合測試 - 確認資料持久化
 * 3. UAF 流程模擬 - 測試完整認證流程
 */
@Slf4j
@Controller
@RequestMapping("/uaf-test")
public class UAFTestController {

    /**
     * 顯示 UAF 測試頁面（手機友善版）
     *
     * 訪問路徑: http://localhost:8080/uaf-test
     *
     * @return 測試頁面模板
     */
    @GetMapping
    public String showTestPage() {
        log.info("UAF test page accessed");
        return "uaf-test";
    }

    /**
     * Phase 1: 測試 Facets 端點
     *
     * GET /api/uaf/v1/public/facets
     *
     * 這是 UAF 協議中用於定義受信任應用程式的端點
     * 測試此端點可以確認基礎 UAF 端點設定正確
     */
    @GetMapping("/api/uaf/v1/public/facets")
    @ResponseBody
    public RestResult<Map<String, Object>> getFacets() {
        log.info("Testing facets endpoint");

        try {
            // 模擬 Facets 資料
            Map<String, Object> facets = new HashMap<>();

            List<Map<String, Object>> trustedFacets = new ArrayList<>();
            Map<String, Object> facetGroup = new HashMap<>();
            facetGroup.put("version", Map.of("major", 1, "minor", 0));

            List<String> ids = new ArrayList<>();
            ids.add("http://localhost:8080");
            ids.add("https://localhost:8080");
            ids.add("android:apk-key-hash:your-app-hash");

            facetGroup.put("ids", ids);
            trustedFacets.add(facetGroup);

            facets.put("trustedFacets", trustedFacets);

            log.info("Facets endpoint test successful");
            return new RestResult<>(RestStatus.SUCCESS,facets);

        } catch (Exception e) {
            log.error("Facets endpoint test failed", e);
            return  new RestResult<>(RestStatus.UNKNOWN.CODE, RestStatus.UNKNOWN.MESSAGE, e.getMessage());
        }
    }

    /**
     * Phase 1: 測試註冊請求生成
     *
     * GET /api/uaf/v1/public/regRequest/{username}
     *
     * 生成 UAF 註冊請求，這是 UAF 註冊流程的第一步
     *
     * @param username 要註冊的用戶名稱
     * @return UAF RegistrationRequest 陣列
     */
    @GetMapping("/api/uaf/v1/public/regRequest/{username}")
    @ResponseBody
    public RestResult<List<Map<String, Object>>> getRegistrationRequest(@PathVariable String username) {
        log.info("Testing registration request generation for user: {}", username);

        try {
            // 模擬 UAF RegistrationRequest
            List<Map<String, Object>> requests = new ArrayList<>();
            Map<String, Object> request = new HashMap<>();

            // Header
            Map<String, Object> header = new HashMap<>();
            header.put("upv", Map.of("major", 1, "minor", 0));
            header.put("op", "Reg");
            header.put("appID", "http://localhost:8080");
            header.put("serverData", generateServerData(username));

            request.put("header", header);

            // Challenge
            request.put("challenge", generateChallenge());

            // Username
            request.put("username", username);

            // Policy
            Map<String, Object> policy = new HashMap<>();
            policy.put("accepted", List.of(
                List.of(Map.of("aaid", "EBA0#0001")),
                List.of(Map.of("aaid", "0015#0001"))
            ));
            request.put("policy", policy);

            requests.add(request);

            log.info("Registration request generated successfully for user: {}", username);
            return new RestResult<>(RestStatus.SUCCESS);

        } catch (Exception e) {
            log.error("Failed to generate registration request for user: {}", username, e);
            return new RestResult<>(RestStatus.UNKNOWN.CODE, RestStatus.UNKNOWN.MESSAGE, e.getMessage());
        }
    }

    /**
     * Phase 1: 測試認證請求生成
     *
     * GET /api/uaf/v1/public/authRequest
     *
     * @return UAF AuthenticationRequest 陣列
     */
    @GetMapping("/api/uaf/v1/public/authRequest")
    @ResponseBody
    public RestResult<List<Map<String, Object>>> getAuthenticationRequest() {
        log.info("Testing authentication request generation");

        try {
            List<Map<String, Object>> requests = new ArrayList<>();
            Map<String, Object> request = new HashMap<>();

            // Header
            Map<String, Object> header = new HashMap<>();
            header.put("upv", Map.of("major", 1, "minor", 0));
            header.put("op", "Auth");
            header.put("appID", "http://localhost:8080");
            header.put("serverData", generateServerData("authUser"));

            request.put("header", header);
            request.put("challenge", generateChallenge());

            // Policy
            Map<String, Object> policy = new HashMap<>();
            policy.put("accepted", List.of(
                List.of(Map.of("aaid", "EBA0#0001"))
            ));
            request.put("policy", policy);

            requests.add(request);

            log.info("Authentication request generated successfully");
            return new RestResult<>(RestStatus.SUCCESS);

        } catch (Exception e) {
            log.error("Failed to generate authentication request", e);
            return new RestResult<>(RestStatus.UNKNOWN.CODE, RestStatus.UNKNOWN.MESSAGE, e.getMessage());
        }
    }

    /**
     * Phase 3: 處理註冊回應（簡化版）
     *
     * POST /api/uaf/v1/public/regResponse
     *
     * @param payload UAF 註冊回應 JSON
     * @return 處理結果
     */
    @PostMapping("/api/uaf/v1/public/regResponse")
    @ResponseBody
    public RestResult<Map<String, Object>> processRegistrationResponse(@RequestBody String payload) {
        log.info("Testing registration response processing");
        log.debug("Received payload: {}", payload);

        try {
            // 這裡暫時只是記錄並返回成功
            // 實際實作需要：
            // 1. 解析 UAF 回應
            // 2. 驗證簽章
            // 3. 儲存註冊記錄到資料庫

            Map<String, Object> result = new HashMap<>();
            result.put("status", "pending_implementation");
            result.put("message", "Registration response received");
            result.put("timestamp", LocalDateTime.now().toString());
            result.put("note", "需要實作完整的 RegistrationResponseProcessing 邏輯");

            log.info("Registration response processing test completed (mock)");
            return new RestResult<>(RestStatus.SUCCESS,result);

        } catch (Exception e) {
            log.error("Failed to process registration response", e);
            return new RestResult<>(RestStatus.UNKNOWN.CODE, RestStatus.UNKNOWN.MESSAGE, e.getMessage());
        }
    }

    /**
     * Phase 3: 處理認證回應（簡化版）
     *
     * POST /api/uaf/v1/public/authResponse
     *
     * @param payload UAF 認證回應 JSON
     * @return 處理結果
     */
    @PostMapping("/api/uaf/v1/public/authResponse")
    @ResponseBody
    public RestResult<Map<String, Object>> processAuthenticationResponse(@RequestBody String payload) {
        log.info("Testing authentication response processing");
        log.debug("Received payload: {}", payload);

        try {
            Map<String, Object> result = new HashMap<>();
            result.put("status", "pending_implementation");
            result.put("message", "Authentication response received");
            result.put("timestamp", LocalDateTime.now().toString());
            result.put("note", "需要實作完整的 AuthenticationResponseProcessing 邏輯");

            log.info("Authentication response processing test completed (mock)");
            return new RestResult<>(RestStatus.SUCCESS,result);

        } catch (Exception e) {
            log.error("Failed to process authentication response", e);
            return new RestResult<>(RestStatus.UNKNOWN.CODE, RestStatus.UNKNOWN.MESSAGE, e.getMessage());
        }
    }

    /**
     * Phase 4: 查詢特定用戶的註冊記錄
     *
     * GET /api/uaf/v1/test/registrations/{username}
     *
     * @param username 用戶名稱
     * @return 註冊記錄列表
     */
    @GetMapping("/api/uaf/v1/test/registrations/{username}")
    @ResponseBody
    public RestResult<List<Map<String, Object>>> getRegistrationsByUsername(@PathVariable String username) {
        log.info("Testing database query for user: {}", username);

        try {
            // 這裡需要實際的資料庫查詢
            // 暫時返回模擬資料
            List<Map<String, Object>> registrations = new ArrayList<>();

            Map<String, Object> record = new HashMap<>();
            record.put("username", username);
            record.put("authenticatorPublicKeyId", "mock-key-id-" + System.currentTimeMillis());
            record.put("deviceId", "mock-device-id");
            record.put("signCounter", 0);
            record.put("createdAt", LocalDateTime.now().toString());
            record.put("note", "這是模擬資料，需要實作實際的資料庫查詢");

            registrations.add(record);

            log.info("Found {} registration records for user: {}", registrations.size(), username);
            return new RestResult<>(RestStatus.SUCCESS,registrations);

        } catch (Exception e) {
            log.error("Failed to query registrations for user: {}", username, e);
            return new RestResult<>(RestStatus.UNKNOWN.CODE, RestStatus.UNKNOWN.MESSAGE, e.getMessage());
        }
    }

    /**
     * Phase 4: 查詢所有 UAF 註冊記錄
     *
     * GET /api/uaf/v1/test/registrations
     *
     * @return 所有註冊記錄
     */
    @GetMapping("/api/uaf/v1/test/registrations")
    @ResponseBody
    public RestResult<List<Map<String, Object>>> getAllRegistrations() {
        log.info("Testing database query for all registrations");

        try {
            // 暫時返回空列表
            List<Map<String, Object>> registrations = new ArrayList<>();

            log.info("Total UAF registrations in database: {}", registrations.size());
            return new RestResult<>(RestStatus.SUCCESS,registrations);

        } catch (Exception e) {
            log.error("Failed to query all registrations", e);
            return new RestResult<>(RestStatus.UNKNOWN.CODE, RestStatus.UNKNOWN.MESSAGE, e.getMessage());
        }
    }

    /**
     * 健康檢查端點
     *
     * GET /api/uaf/v1/test/health
     *
     * @return 系統狀態
     */
    @GetMapping("/api/uaf/v1/test/health")
    @ResponseBody
    public RestResult<Map<String, Object>> healthCheck() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("timestamp", LocalDateTime.now().toString());
        health.put("uafIntegration", "in_progress");
        health.put("phase", "testing");

        return new RestResult<>(RestStatus.SUCCESS,health);
    }

    // === 輔助方法 ===

    /**
     * 生成 Server Data（用於防重放攻擊）
     */
    private String generateServerData(String username) {
        // 實際實作應該使用 Notary 簽章
        String data = username + ":" + System.currentTimeMillis();
        return java.util.Base64.getEncoder().encodeToString(data.getBytes());
    }

    /**
     * 生成隨機 Challenge
     */
    private String generateChallenge() {
        byte[] challenge = new byte[32];
        new java.security.SecureRandom().nextBytes(challenge);
        return java.util.Base64.getEncoder().encodeToString(challenge);
    }
}

package com.webauthn.app.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn.app.authenticator.Authenticator;
import com.webauthn.app.common.api.RestResult;
import com.webauthn.app.common.api.RestStatus;
import com.webauthn.app.exception.AppRegistrationException;
import com.webauthn.app.infrastructure.cache.WebAuthnRequestCache;
import com.webauthn.app.infrastructure.repository.RegistrationRepository;
import com.webauthn.app.rq.FinishLoginRequest;
import com.webauthn.app.rq.FinishRegisrationRequest;
import com.webauthn.app.rq.LoginRequest;
import com.webauthn.app.rq.RegisterRequest;
import com.webauthn.app.rs.CredentialCreateResponse;
import com.webauthn.app.rs.CredentialGetResponse;
import com.webauthn.app.rs.FinishLoginResponse;
import com.webauthn.app.rs.FinishRegistrationResponse;
import com.webauthn.app.service.RegistrationService;
import com.webauthn.app.user.AppUser;
import com.webauthn.app.user.RegistrationStatus;
import com.webauthn.app.utility.Utility;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final RelyingParty relyingParty;
    private final RegistrationRepository registrationRepository;
    private final RegistrationService registrationService;
    private final WebAuthnRequestCache webAuthnRequestCache;
    private Map<String, AssertionRequest> assertionRequestMap = new HashMap<>();

    AuthController(RegistrationRepository registrationRepository, RelyingParty relyingPary, RegistrationService registrationService, WebAuthnRequestCache webAuthnRequestCache) {
        this.relyingParty = relyingPary;
        this.registrationRepository = registrationRepository;
        this.registrationService = registrationService;
        this.webAuthnRequestCache = webAuthnRequestCache;
    }

    /**
     * 階段一：暫存註冊
     * 儲存到本地 DB
     */
    @PostMapping("/register")
    @ResponseBody
    public RestResult<CredentialCreateResponse> newUserRegistration(
            @RequestBody RegisterRequest request
    ) {
        String username = request.getUsername();
        String display = request.getDisplay();

        AppUser existingUser = registrationRepository.getUserRepo().findByUsername(username);
        if (existingUser == null) {
            log.info("Stage 1: 暫存註冊，Creating pending user in local DB: {}", username);

            UserIdentity userIdentity = UserIdentity.builder()
                    .name(username)
                    .displayName(display)
                    .id(Utility.generateRandom(32))//隨機id防止跨站攻擊
                    .build();

            AppUser saveUser = new AppUser(userIdentity);
            // 只儲存到本地 DB，狀態為 PENDING
            registrationRepository.getUserRepo().save(saveUser);

            log.info("成功暫存User: {} with userId: {}", username, saveUser.getId());

            // 返回 WebAuthn challenge (包含 userId)
            return performAuthRegistration(saveUser);

        } else {
            log.warn("User registration failed - username already exists: {}", username);
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username " + username + " already exists. Choose a new name.");
        }
    }

    @PostMapping("/registerauth")
    @ResponseBody
    public RestResult<CredentialCreateResponse> newAuthRegistration(
            @RequestParam AppUser user
    ) {
        return performAuthRegistration(user);
    }

    // 內部方法，支持直接調用
    private RestResult<CredentialCreateResponse> performAuthRegistration(AppUser user) {
        AppUser existingUser = registrationRepository.getUserRepo().findByHandle(user.getHandle());
        if (existingUser != null) {
            UserIdentity userIdentity = user.toUserIdentity();

            //加 authenticatorSelection
            AuthenticatorSelectionCriteria selection = AuthenticatorSelectionCriteria.builder()
                    .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM) // 外部裝置 (手機、YubiKey)
                    .userVerification(UserVerificationRequirement.PREFERRED)       // 可以 PIN / 生物辨識
                    .build();

            StartRegistrationOptions registrationOptions = StartRegistrationOptions.builder()
                    .user(userIdentity)
                    .authenticatorSelection(selection)  // 把設定加進來
                    .build();
            PublicKeyCredentialCreationOptions registration = relyingParty.startRegistration(registrationOptions);
            webAuthnRequestCache.put(user.getUsername(), registration);

            // 返回 註冊選項 和 userId
            return new RestResult<>(CredentialCreateResponse.from(registration, user.getId()));
        } else {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "User " + user.getUsername() + " does not exist. Please register.");
        }
    }

    /**
     * 階段二：完成認證
     * WebAuthn 驗證成功後，完成註冊流程
     */
    @PostMapping("/finishauth")
    @ResponseBody
    public RestResult<FinishRegistrationResponse> finishRegisration(
            @RequestBody FinishRegisrationRequest finishRegisrationRequest
    ) {
        try {
            FinishRegistrationResponse response = registrationService.completeRegistration(finishRegisrationRequest);
            return new RestResult<>(response);
        } catch (AppRegistrationException e) {
            log.error("Registration failed: {}", e.getMessage());
            return new RestResult<>(FinishRegistrationResponse.failure("WebAuthn 註冊失敗: " + e.getMessage()));
        } catch (Exception e) {
            log.error("Unexpected error during finishauth: {}", e.getMessage(), e);
            return new RestResult<>(RestStatus.UNKNOWN.CODE, RestStatus.UNKNOWN.MESSAGE, e.getMessage());
        }
    }

    @PostMapping("/login")
    @ResponseBody
    public RestResult<CredentialGetResponse> startLogin(
            @RequestBody LoginRequest loginRequest
    ) {
        String username = loginRequest.getUsername();
        AssertionRequest request = relyingParty.startAssertion(StartAssertionOptions.builder()
                .username(username)
                .build());
        try {
            this.assertionRequestMap.put(username, request);
            String credentialsJson = request.toCredentialsGetJson();
            ObjectMapper objectMapper = new ObjectMapper();
            CredentialGetResponse credentialsObject = objectMapper.readValue(credentialsJson, CredentialGetResponse.class);
            return new RestResult<>(credentialsObject);
        } catch (JsonProcessingException e) {
            return new RestResult<>(RestStatus.UNKNOWN, e.getMessage());
        }
    }

    @PostMapping("/welcome")
    public RestResult<FinishLoginResponse> finishLogin(
            @RequestBody FinishLoginRequest finishLoginRequest
    ) {
        try {
            //FIDO2: 驗證時: 伺服器使用公鑰，去驗證此簽章是否有效。
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc;
            pkc = PublicKeyCredential.parseAssertionResponseJson(finishLoginRequest.getCredential());
            AssertionRequest request = this.assertionRequestMap.get(finishLoginRequest.getUsername());

            // library 會自動用先前註冊時存的公鑰 去驗證簽章是否正確。
            AssertionResult result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(request) // 前端登入請求時的 challenge/credentialId 等資訊
                    .response(pkc) // 前端傳回的簽章 (AuthenticatorAssertionResponse)
                    .build());
            if (result.isSuccess()) {
                return new RestResult<>(FinishLoginResponse.success(finishLoginRequest.getUsername()));
            } else {
                return new RestResult<>(FinishLoginResponse.failure("Authentication failed"));
            }
        } catch (IOException e) {
            throw new RuntimeException("Authentication failed", e);
        } catch (AssertionFailedException e) {
            throw new RuntimeException("Authentication failed", e);
        }

    }

    /**
     * 取消註冊（刪除暫存或已完成的用戶）
     * 刪除本地 DB 的用戶資料
     *
     * 安全性考量：使用 userId 而非 username，避免用戶枚舉攻擊
     */
    @DeleteMapping("/user/{userId}")
    @ResponseBody
    public RestResult<String> deleteUser(@PathVariable Long userId) {
        log.info("User deletion requested for userId: {}", userId);

        AppUser user = registrationRepository.getUserRepo().findById(userId).orElse(null);
        if (user == null) {
            log.warn("User not found for deletion, userId: {}", userId);
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found");
        }

        String username = user.getUsername();

        try {
            registrationRepository.getUserRepo().delete(user);
            log.info("Successfully deleted user from local DB: {}", username);
            return new RestResult<>(RestStatus.SUCCESS, "User " + username + " deleted successfully");
        } catch (Exception dbException) {
            log.error("Failed to delete user from local DB: {}", username, dbException);
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    "Failed to delete user from local database",
                    dbException
            );
        }
    }
}

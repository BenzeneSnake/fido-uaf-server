package org.ebayopensource.fido.uaf.core.crypto;

import org.bouncycastle.util.encoders.Base64;
import org.ebayopensource.fido.uaf.core.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.core.storage.StorageInterface;
import org.ebayopensource.fido.uaf.core.tlv.SignCounter;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

/**
 * SignCounter 驗證器，用於防止重放攻擊
 * <p>
 * FIDO UAF 規範要求：
 * 1. 註冊時：authenticator 回傳初始 counter 值（通常為 0）
 * 2. 認證時：authenticator 回傳遞增的 counter 值
 * 3. Server 驗證：新的 counter 必須大於之前儲存的值
 */
public class SignCounterValidator {

    private static final Logger logger = Logger.getLogger(SignCounterValidator.class.getName());

    /**
     * Counter 處理流程
     *| 階段   | counterBytes        | record.SignCounter 格式 | 範例                          |
     *|-------|---------------------|------------------------|-------------------------------|
     *| 註冊   | 8 bytes (sig + reg) | "0.1"                  | 從 counterBytes 解析兩個值      |
     *| 認證 1 | 4 bytes (sig only)  | "1.1"                  | sig 從 counterBytes，reg 從 DB |
     *| 認證 2 | 4 bytes (sig only)  | "2.1"                  | sig 從 counterBytes，reg 從 DB |
     */

    /**
     * 驗證註冊階段的 counter（初始化）
     *
     * @param record 註冊記錄，其 SignCounter 應已被解析並設定
     * @return true 如果 counter 格式正確
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws Exception
     */
    public boolean validateRegistrationCounter(RegistrationRecord record)
            throws NoSuchAlgorithmException, IOException, Exception {
        if (record.SignCounter == null || record.SignCounter.isEmpty()) {
            logger.warning("Invalid registration counter: SignCounter is null or empty");
            return false;
        }

        // 註冊時的 counter 通常為 0，但也可能不為 0
        // record.SignCounter 已經在 processAssertions 中被解析並設定為 "signatureCounter.registrationCounter" 格式
        logger.info("Registration - SignCounter: " + record.SignCounter);

        return true;
    }

    /**
     * 驗證認證階段的 counter（防重放攻擊）
     *
     * @param counterBytes 認證階段：4 bytes (signature counter only)
     * @param keyId        用於查詢之前儲存的 counter
     * @param storage      資料儲存介面
     * @return true 如果新的 counter 大於舊的 counter
     * @throws Exception 如果驗證失敗
     */
    public boolean validateAuthenticationCounter(byte[] counterBytes, String keyId,
                                                 StorageInterface storage) throws Exception {
        if (counterBytes == null || counterBytes.length != 4) {
            logger.warning("Invalid authentication counter length: " +
                    (counterBytes == null ? "null" : counterBytes.length));
            throw new Exception("Invalid counter format");
        }

        // 1. 提取新的 signature counter（4 bytes，little-endian unsigned int）
        long newSignatureCounter = SignCounter.extractSignatureCounter(counterBytes);
        logger.info("New signature counter: " + newSignatureCounter);

        // 2. 從資料庫讀取之前儲存的 counter 值
        RegistrationRecord record = storage.readRegistrationRecord(keyId);
        if (record == null) {
            logger.warning("No registration record found for keyId: " + keyId);
            throw new Exception("Authenticator not registered");
        }

        long oldSignatureCounter = SignCounter.parseStoredCounter(record.SignCounter);
        logger.info("Old signature counter: " + oldSignatureCounter);

        // 3. 驗證：新的 counter 必須大於舊的 counter
        if (newSignatureCounter <= oldSignatureCounter) {
            logger.warning("Replay attack detected! New counter (" + newSignatureCounter +
                    ") is not greater than old counter (" + oldSignatureCounter + ")");
            throw new Exception("Counter validation failed - possible replay attack");
        }

        // 4. 更新DB - 保留原有的 registration counter
        // 認證階段只更新 signature counter，registration counter 維持不變
        long registrationCounter = SignCounter.parseStoredRegistrationCounter(record.SignCounter);
        record.SignCounter = newSignatureCounter + "." + registrationCounter;
        storage.update(new RegistrationRecord[]{record});

        logger.info("Counter validation successful. Updated counter to: " + record.SignCounter);
        return true;
    }
}

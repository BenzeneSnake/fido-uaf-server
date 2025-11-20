/*
 * Copyright 2015 eBay Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ebayopensource.fido.uaf.core.ops;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base64;
import org.ebayopensource.fido.uaf.core.crypto.CertificateValidator;
import org.ebayopensource.fido.uaf.core.crypto.CertificateValidatorImpl;
import org.ebayopensource.fido.uaf.core.crypto.Notary;
import org.ebayopensource.fido.uaf.core.msg.AuthenticatorRegistrationAssertion;
import org.ebayopensource.fido.uaf.core.msg.FinalChallengeParams;
import org.ebayopensource.fido.uaf.core.msg.RegistrationResponse;
import org.ebayopensource.fido.uaf.core.msg.Version;
import org.ebayopensource.fido.uaf.core.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.core.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.core.tlv.Tag;
import org.ebayopensource.fido.uaf.core.tlv.Tags;
import org.ebayopensource.fido.uaf.core.tlv.TagsEnum;
import org.ebayopensource.fido.uaf.core.tlv.TlvAssertionParser;
import org.ebayopensource.fido.uaf.core.tlv.UnsignedUtil;

import com.google.gson.Gson;
import org.ebayopensource.fido.uaf.server.config.UafServerConfig;

public class RegistrationResponseProcessing {

    private Logger logger = Logger.getLogger(this.getClass().getName());
    private long serverDataExpiryInMs = 5 * 60 * 1000;
    private Notary notary = null;
    private Gson gson = new Gson();
    private CertificateValidator certificateValidator;

    public RegistrationResponseProcessing() {
        this.certificateValidator = new CertificateValidatorImpl();
    }

    public RegistrationResponseProcessing(long serverDataExpiryInMs,
                                          Notary notary) {
        this.serverDataExpiryInMs = serverDataExpiryInMs;
        this.notary = notary;
        this.certificateValidator = new CertificateValidatorImpl();
    }

    public RegistrationResponseProcessing(long serverDataExpiryInMs,
                                          Notary notary, CertificateValidator certificateValidator) {
        this.serverDataExpiryInMs = serverDataExpiryInMs;
        this.notary = notary;
        this.certificateValidator = certificateValidator;
    }

    public RegistrationRecord[] processResponse(RegistrationResponse response)
            throws Exception {
        checkAssertions(response);
        RegistrationRecord[] records = new RegistrationRecord[response.assertions.length];

        checkVersion(response.header.upv);
        checkServerData(response.header.serverData, records);
        FinalChallengeParams fcp = getFcp(response);
        checkFcp(fcp);
        for (int i = 0; i < records.length; i++) {
            records[i] = processAssertions(response.assertions[i], records[i]);
        }

        return records;
    }

    private RegistrationRecord processAssertions(
            AuthenticatorRegistrationAssertion authenticatorRegistrationAssertion,
            RegistrationRecord record) {
        if (record == null) {
            record = new RegistrationRecord();
            record.status = "INVALID_USERNAME";
        }
        TlvAssertionParser parser = new TlvAssertionParser();
        try {
            //TLV -> Tags
            Tags tags = parser
                    .parse(authenticatorRegistrationAssertion.assertion);
            try {
                // 驗證簽名
                verifyAttestationSignature(tags, record);
            } catch (Exception e) {
                record.attestVerifiedStatus = "NOT_VERIFIED";
            }

            AuthenticatorRecord authRecord = new AuthenticatorRecord();
            authRecord.AAID = new String(tags.getTags().get(
                    TagsEnum.TAG_AAID.id).value);
            authRecord.KeyID =
                    // new String(tags.getTags().get(
                    // TagsEnum.TAG_KEYID.id).value);
                    Base64.encodeBase64URLSafeString(tags.getTags().get(
                            TagsEnum.TAG_KEYID.id).value);
            record.authenticator = authRecord;
            record.PublicKey = Base64.encodeBase64URLSafeString(tags.getTags()
                    .get(TagsEnum.TAG_PUB_KEY.id).value);
            record.AuthenticatorVersion = getAuthenticatorVersion(tags);
            String fc = Base64.encodeBase64URLSafeString(tags.getTags().get(
                    TagsEnum.TAG_FINAL_CHALLENGE.id).value);
            logger.log(Level.INFO, "FC: " + fc);
            if (record.status == null) {
                record.status = "SUCCESS";
            }
        } catch (Exception e) {
            record.status = "ASSERTIONS_CHECK_FAILED";
            logger.log(Level.INFO, "Fail to parse assertion: "
                    + authenticatorRegistrationAssertion.assertion, e);
        }
        return record;
    }

    private void verifyAttestationSignature(Tags tags, RegistrationRecord record)
            throws NoSuchAlgorithmException, IOException, Exception {
        // 1. 取得 attestation 證書（內含公鑰）
        byte[] certBytes = tags.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id).value;
        record.attestCert = Base64.encodeBase64URLSafeString(certBytes);

        // 2. 取得被簽名的數據 (KRD)
        Tag krd = tags.getTags().get(TagsEnum.TAG_UAFV1_KRD.id);
        Tag signature = tags.getTags().get(TagsEnum.TAG_SIGNATURE.id);
        // 3. 組合要驗證的數據
        byte[] signedBytes = new byte[krd.value.length + 4];
        System.arraycopy(UnsignedUtil.encodeInt(krd.id), 0, signedBytes, 0, 2);
        System.arraycopy(UnsignedUtil.encodeInt(krd.length), 0, signedBytes, 2,
                2);
        System.arraycopy(krd.value, 0, signedBytes, 4, krd.value.length);

        record.attestDataToSign = Base64.encodeBase64URLSafeString(signedBytes);
        record.attestSignature = Base64
                .encodeBase64URLSafeString(signature.value);
        record.attestVerifiedStatus = "FAILED_VALIDATION_ATTEMPT";
        // 4. 用證書驗證簽名 validate實作是用SHA256withEC，可覆寫
        if (certificateValidator.validate(certBytes, signedBytes,
                signature.value)) {
            record.attestVerifiedStatus = "VALID";
        } else {
            record.attestVerifiedStatus = "NOT_VERIFIED";
        }
    }

    private String getAuthenticatorVersion(Tags tags) {
        return "" + tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id).value[0]
                + "."
                + tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id).value[1];
    }

    /**
     * TODO:尚未檢查Assertions
     * publicKey 是合法的
     * attestation 證書有效
     * authenticator 真的可信（參照 Metadata）
     *
     * @param response
     * @throws Exception
     */
    private void checkAssertions(RegistrationResponse response)
            throws Exception {
//        if (response.assertions != null && response.assertions.length > 0) {
//            return;
//        } else {
//            throw new Exception("Missing assertions in registration response");
//        }
        if (response.assertions == null || response.assertions.length == 0) {
            throw new Exception("Missing assertions in registration response");
        }
//        for (AuthenticatorRegistrationAssertion assertion : response.assertions) {
//            //解析 assertion JSON / TLV 內容
//            //建立AuthenticatorData 物件
//            AuthenticatorData authData = parseAuthenticatorData(assertion);
//            byte[] signatureBytes = assertion.getSignature();
//            PublicKey publicKey = extractPublicKey(authData);
//            X509Certificate attestationCert = extractAttestationCert(authData);
//
//            // 驗證 attestation 是否有效
//            if (!verifyAttestation(attestationCert)) {
//                throw new Exception("Attestation validation failed");
//            }
//
//            // 驗證 signature（challenge + authenticatorData）
//            byte[] signedData = assembleSignedData(response.header.serverData, authData);
//            if (!verifySignature(signatureBytes, signedData, publicKey)) {
//                throw new Exception("Signature verification failed");
//            }
//
//            // 驗 counter / flags
//            if (!verifyCounter(authData)) {
//                throw new Exception("Counter verification failed");
//            }
//        }
    }

    private FinalChallengeParams getFcp(RegistrationResponse response) {
        String fcp = new String(Base64.decodeBase64(response.fcParams
                .getBytes()));
        return gson.fromJson(fcp, FinalChallengeParams.class);
    }

    private void checkServerData(String serverDataB64,
                                 RegistrationRecord[] records) throws Exception {
        if (notary == null) {
            return;
        }
        String serverData = new String(Base64.decodeBase64(serverDataB64));
        String[] tokens = serverData.split("\\.");
        String signature, timeStamp, username, challenge, dataToSign;
        try {
            signature = tokens[0];
            timeStamp = tokens[1];
            username = tokens[2];
            challenge = tokens[3];
            dataToSign = timeStamp + "." + username + "." + challenge;
            //serverData 由 notary 驗證
            //dataToSign = timestamp + "." + username + "." + challenge
            //signature  = Server 用 HMAC 密鑰 簽 dataToSign
            if (!notary.verify(dataToSign, signature)) {
                throw new ServerDataSignatureNotMatchException();
            }
            if (isExpired(timeStamp)) {
                throw new ServerDataExpiredException();
            }
            setUsernameAndTimeStamp(username, timeStamp, records);
        } catch (ServerDataExpiredException e) {
            setErrorStatus(records, "INVALID_SERVER_DATA_EXPIRED");
            throw new Exception("Invalid server data - Expired data");
        } catch (ServerDataSignatureNotMatchException e) {
            setErrorStatus(records, "INVALID_SERVER_DATA_SIGNATURE_NO_MATCH");
            throw new Exception("Invalid server data - Signature not match");
        } catch (Exception e) {
            setErrorStatus(records, "INVALID_SERVER_DATA_CHECK_FAILED");
            throw new Exception("Server data check failed");
        }

    }

    private boolean isExpired(String timeStamp) {
        return Long.parseLong(new String(Base64.decodeBase64(timeStamp)))
                + serverDataExpiryInMs < System.currentTimeMillis();
    }

    private void setUsernameAndTimeStamp(String username, String timeStamp,
                                         RegistrationRecord[] records) {
        if (records == null || records.length == 0) {
            return;
        }
        for (int i = 0; i < records.length; i++) {
            RegistrationRecord rec = records[i];
            if (rec == null) {
                rec = new RegistrationRecord();
            }
            rec.username = new String(Base64.decodeBase64(username));
            rec.timeStamp = new String(Base64.decodeBase64(timeStamp));
            records[i] = rec;
        }
    }

    private void setErrorStatus(RegistrationRecord[] records, String status) {
        if (records == null || records.length == 0) {
            return;
        }
        for (RegistrationRecord rec : records) {
            if (rec == null) {
                rec = new RegistrationRecord();
            }
            rec.status = status;
        }
    }

    private void checkVersion(Version upv) throws Exception {
        if (upv.major == 1 && upv.minor == 0) {
            return;
        } else {
            throw new Exception("Invalid version: " + upv.major + "."
                    + upv.minor);
        }
    }

    private void checkFcp(FinalChallengeParams fcp) throws Exception {
        // TODO Auto-generated method stub
        //FinalChallengeParams fcp 這是 RP 自行定義的安全邏輯

        validateAppId(fcp);

    }

    private void validateAppId(FinalChallengeParams fcp) throws Exception {
        // 檢查 appID
        if (fcp.appID == null || fcp.appID.isEmpty()) {
            throw new Exception("Missing appID in FinalChallengeParams");
        }

        // 驗證 appID 格式
        // 如果是url
        if (fcp.appID.startsWith("http")) {
            // 必須是 https URL
            // FOR 學習用，故註銷
//            if (!fcp.appID.startsWith("https://")) {
//                throw new Exception("Invalid appID format - must be https URL");
//            }
            if (!UafServerConfig.getAppId().equals(fcp.appID)) {
                throw new Exception("Disallowed AppID:" + fcp.appID);
            }
        }
    }
}

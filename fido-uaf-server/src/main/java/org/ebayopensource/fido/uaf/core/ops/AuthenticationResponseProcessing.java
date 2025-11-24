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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.google.gson.Gson;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.ebayopensource.fido.uaf.core.msg.AuthenticationResponse;
import org.ebayopensource.fido.uaf.core.msg.AuthenticatorSignAssertion;
import org.ebayopensource.fido.uaf.core.msg.FinalChallengeParams;
import org.ebayopensource.fido.uaf.core.msg.Version;
import org.ebayopensource.fido.uaf.core.crypto.Asn1;
import org.ebayopensource.fido.uaf.core.crypto.KeyCodec;
import org.ebayopensource.fido.uaf.core.crypto.NamedCurve;
import org.ebayopensource.fido.uaf.core.crypto.Notary;
import org.ebayopensource.fido.uaf.core.crypto.RSA;
import org.ebayopensource.fido.uaf.core.crypto.SHA;
import org.ebayopensource.fido.uaf.core.crypto.SignCounterValidator;
import org.ebayopensource.fido.uaf.core.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.core.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.core.storage.StorageInterface;
import org.ebayopensource.fido.uaf.core.tlv.AlgAndEncodingEnum;
import org.ebayopensource.fido.uaf.core.tlv.Tag;
import org.ebayopensource.fido.uaf.core.tlv.Tags;
import org.ebayopensource.fido.uaf.core.tlv.TagsEnum;
import org.ebayopensource.fido.uaf.core.tlv.TlvAssertionParser;
import org.ebayopensource.fido.uaf.server.config.UafServerConfig;

public class AuthenticationResponseProcessing {

    private Logger logger = Logger.getLogger(this.getClass().getName());
    private long serverDataExpiryInMs;
    private Notary notary;
    private Gson gson = new Gson();
    private SignCounterValidator signCounterValidator;

    public AuthenticationResponseProcessing() {
        this.signCounterValidator = new SignCounterValidator();
    }

    public AuthenticationResponseProcessing(long serverDataExpiryInMs,
                                            Notary notary) {
        this.serverDataExpiryInMs = serverDataExpiryInMs;
        this.notary = notary;
        this.signCounterValidator = new SignCounterValidator();
    }

    public AuthenticatorRecord[] verify(AuthenticationResponse response,
                                        StorageInterface serverData) throws Exception {
        AuthenticatorRecord[] result = new AuthenticatorRecord[response.assertions.length];

        checkVersion(response.header.upv);
        checkServerData(response.header.serverData, result);
        FinalChallengeParams fcp = getFcp(response);
        checkFcp(fcp);
        for (int i = 0; i < result.length; i++) {
            result[i] = processAssertions(response.assertions[i], serverData);
        }
        return result;
    }

    //TODO:CODE太亂:很多TRY CATCH之後重購
    private AuthenticatorRecord processAssertions(
            AuthenticatorSignAssertion authenticatorSignAssertion,
            StorageInterface storage) {
        TlvAssertionParser parser = new TlvAssertionParser();
        AuthenticatorRecord authRecord = new AuthenticatorRecord();
        RegistrationRecord registrationRecord = null;

        try {
            //TLV -> Tags
            Tags tags = parser.parse(authenticatorSignAssertion.assertion);
            authRecord.AAID = new String(tags.getTags().get(
                    TagsEnum.TAG_AAID.id).value);
            authRecord.KeyID = Base64.encodeBase64URLSafeString(tags.getTags()
                    .get(TagsEnum.TAG_KEYID.id).value);
            // authRecord.KeyID = new String(
            // tags.getTags().get(TagsEnum.TAG_KEYID.id).value);
            registrationRecord = getRegistration(authRecord, storage);
            Tag signnedData = tags.getTags().get(
                    TagsEnum.TAG_UAFV1_SIGNED_DATA.id);
            Tag signature = tags.getTags().get(TagsEnum.TAG_SIGNATURE.id);
            Tag info = tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id);
            AlgAndEncodingEnum algAndEncoding = getAlgAndEncoding(info);
            // 取得之前註冊時儲存的公鑰
            String pubKey = registrationRecord.PublicKey;
            try {
                // 驗證簽名
                if (!verifySignature(signnedData, signature, pubKey,
                        algAndEncoding)) {
                    logger.log(Level.INFO,
                            "Signature verification failed for authenticator: "
                                    + authRecord.toString());
                    authRecord.status = "FAILED_SIGNATURE_NOT_VALID";
                    return authRecord;
                }
            } catch (Exception e) {
                logger.log(Level.INFO,
                        "Signature verification failed for authenticator: "
                                + authRecord.toString(), e);
                authRecord.status = "FAILED_SIGNATURE_VERIFICATION";
                return authRecord;
            }

            // 驗證 counter（防止重放攻擊）
            try {
                Tag counterTag = tags.getTags().get(TagsEnum.TAG_COUNTERS.id);
                if (counterTag != null) {
                    signCounterValidator.validateAuthenticationCounter(
                            counterTag.value, authRecord.toString(), storage);
                }
            } catch (Exception e) {
                logger.log(Level.WARNING,
                        "Counter validation failed for authenticator: "
                                + authRecord.toString(), e);
                authRecord.status = "FAILED_COUNTER_VALIDATION";
                return authRecord;
            }

            authRecord.username = registrationRecord.username;
            authRecord.deviceId = registrationRecord.deviceId;
            authRecord.status = "SUCCESS";
            return authRecord;
        } catch (IOException e) {
            logger.log(Level.INFO, "Fail to parse assertion: "
                    + authenticatorSignAssertion.assertion, e);
            authRecord.status = "FAILED_ASSERTION_VERIFICATION";
            return authRecord;
        }
    }

    private AlgAndEncodingEnum getAlgAndEncoding(Tag info) {
        int id = (int) info.value[3] + (int) info.value[4] * 256;
        AlgAndEncodingEnum ret = null;
        AlgAndEncodingEnum[] values = AlgAndEncodingEnum.values();
        for (AlgAndEncodingEnum algAndEncodingEnum : values) {
            if (algAndEncodingEnum.id == id) {
                ret = algAndEncodingEnum;
                break;
            }
        }
        logger.info(" : SignatureAlgAndEncoding : " + ret);
        return ret;
    }

    private boolean verifySignature(Tag signedData, Tag signature,
                                    String pubKey, AlgAndEncodingEnum algAndEncoding)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException,
            UnsupportedEncodingException, Exception {

        byte[] dataForSigning = getDataForSigning(signedData);

        logger.info(" : pub 		   : " + pubKey);
        logger.info(" : dataForSigning : "
                + Base64.encodeBase64URLSafeString(dataForSigning));
        logger.info(" : signature 	   : "
                + Base64.encodeBase64URLSafeString(signature.value));

        // This works
        // return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(pubKey),
        // dataForSigning, Asn1.decodeToBigIntegerArray(signature.value));

        byte[] decodeBase64 = Base64.decodeBase64(pubKey);
        if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW) {
            PublicKey publicKey = KeyCodec.getRSAPublicKey(decodeBase64);
            return RSA.verifyPSS(publicKey,
                    SHA.sha(dataForSigning, "SHA-256"),
                    signature.value);
        } else if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER) {
            PublicKey publicKey = KeyCodec.getRSAPublicKey(new DEROctetString(decodeBase64).getOctets());
            return RSA.verifyPSS(publicKey,
                    SHA.sha(dataForSigning, "SHA-256"),
                    new DEROctetString(signature.value).getOctets());
        } else {
            if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER) {
                ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(
                        decodeBase64, "secp256k1");
                return NamedCurve.verifyUsingSecp256k1(
                        KeyCodec.getKeyAsRawBytes(decodedPub),
                        SHA.sha(dataForSigning, "SHA-256"),
                        Asn1.decodeToBigIntegerArray(signature.value));
            }
            if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER) {
                if (decodeBase64.length > 65) {
                    //公鑰有 extra metadata（DER/SubjectPublicKeyInfo 格式），去掉 DER header，轉成 raw key
                    return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(pubKey),
                            SHA.sha(dataForSigning, "SHA-256"),
                            Asn1.decodeToBigIntegerArray(signature.value));
                } else {
                    //ebay uaf client預設 指定金鑰使用曲線 secp256r1
                    //公鑰本來就是 raw key
                    ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(
                            decodeBase64, "secp256r1");
                    return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(decodedPub),
                            SHA.sha(dataForSigning, "SHA-256"),
                            Asn1.decodeToBigIntegerArray(signature.value));
                }
            }
            if (signature.value.length == 64) {
                ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(
                        decodeBase64, "secp256r1");
                return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(decodedPub),
                        SHA.sha(dataForSigning, "SHA-256"),
                        Asn1.transformRawSignature(signature.value));
            } else {
                return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(pubKey),
                        SHA.sha(dataForSigning, "SHA-256"),
                        Asn1.decodeToBigIntegerArray(signature.value));
            }
        }
    }

    private byte[] getDataForSigning(Tag signedData) throws IOException {
        ByteArrayOutputStream byteout = new ByteArrayOutputStream();
        byteout.write(encodeInt(signedData.id));
        byteout.write(encodeInt(signedData.length));
        byteout.write(signedData.value);
        return byteout.toByteArray();
    }

    private byte[] encodeInt(int id) {

        byte[] bytes = new byte[2];
        bytes[0] = (byte) (id & 0x00ff);
        bytes[1] = (byte) ((id & 0xff00) >> 8);
        return bytes;
    }

    private RegistrationRecord getRegistration(AuthenticatorRecord authRecord,
                                               StorageInterface serverData) {
        return serverData.readRegistrationRecord(authRecord.toString());
    }

    private FinalChallengeParams getFcp(AuthenticationResponse response) {
        String fcp = new String(Base64.decodeBase64(response.fcParams
                .getBytes()));
        return gson.fromJson(fcp, FinalChallengeParams.class);
    }

    private void checkServerData(String serverDataB64,
                                 AuthenticatorRecord[] records) throws Exception {
        if (notary == null) {
            return;
        }
        String serverData = new String(Base64.decodeBase64(serverDataB64));
        String[] tokens = serverData.split("\\.");
        String signature, timeStamp, challenge, dataToSign;
        try {
            signature = tokens[0];
            timeStamp = tokens[1];
            challenge = tokens[2];
            dataToSign = timeStamp + "." + challenge;
            if (!notary.verify(dataToSign, signature)) {
                throw new ServerDataSignatureNotMatchException();
            }
            if (isExpired(timeStamp)) {
                throw new ServerDataExpiredException();
            }
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

    private void setErrorStatus(AuthenticatorRecord[] records, String status) {
        if (records == null || records.length == 0) {
            return;
        }
        for (AuthenticatorRecord rec : records) {
            if (rec == null) {
                rec = new AuthenticatorRecord();
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

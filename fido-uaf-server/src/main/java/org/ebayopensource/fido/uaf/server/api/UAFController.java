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
 *
 * Modified by BenzeneSnake, 2025
 * - origin: FidoUafResource.java Jersey -> Spring MVC
 */

package org.ebayopensource.fido.uaf.server.api;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import com.google.gson.Gson;
import org.apache.commons.codec.binary.Base64;
import org.ebayopensource.fido.uaf.core.msg.*;
import org.ebayopensource.fido.uaf.core.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.core.storage.DuplicateKeyException;
import org.ebayopensource.fido.uaf.core.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.core.storage.SystemErrorException;
import org.ebayopensource.fido.uaf.server.RPserver.msg.*;
import org.ebayopensource.fido.uaf.server.facets.Facets;
import org.ebayopensource.fido.uaf.server.facets.TrustedFacets;
import org.ebayopensource.fido.uaf.server.res.util.DeregRequestProcessor;
import org.ebayopensource.fido.uaf.server.res.util.FetchRequest;
import org.ebayopensource.fido.uaf.server.res.util.ProcessResponse;
import org.ebayopensource.fido.uaf.server.res.util.StorageImpl;
import org.ebayopensource.fido.uaf.server.stats.Dash;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.MediaType;

@RestController
@RequestMapping("/fidouaf/v1")
public class UAFController {

    @Value("${uaf.server.endpoint}")
    private String hostname;

    @Value("${uaf.server.facetId}")
    private String facetId;

    private final Gson gson = new Gson();

    // 註冊請求
    @GetMapping("/public/regRequest/{username}")
    public RegistrationRequest[] getRegisReqPublic(@PathVariable String username) {
        // FIDO UAF 規格要求：陣列裡只放一個dictionary
        RegistrationRequest[] regReq = new RegistrationRequest[1];
        regReq[0] = new FetchRequest(getAppId(), getAllowedAaids())
                .getRegistrationRequest(username);
        Dash.getInstance().stats.put(Dash.LAST_REG_REQ, regReq);
        Dash.getInstance().history.add(regReq);
        return regReq;
    }

    @GetMapping("/regRequest/{username}/{appId}")
    public String getRegReqForAppId(
            @PathVariable String username,
            @PathVariable String appId) {

        RegistrationRequest[] regReq = getRegisReqPublic(username);
        setAppId(appId, regReq[0].header);
        return gson.toJson(regReq);
    }

    //TODO:修改方法名
    @GetMapping("/public/regRequest")
    public RegistrationRequest[] postRegisReqPublic(String username) {
        RegistrationRequest[] regReq = new RegistrationRequest[1];
        regReq[0] = new FetchRequest(getAppId(), getAllowedAaids())
                .getRegistrationRequest(username);
        Dash.getInstance().stats.put(Dash.LAST_REG_REQ, regReq);
        Dash.getInstance().history.add(regReq);
        return regReq;
    }

    /**
     * List of allowed AAID - Authenticator Attestation ID.
     * Authenticator Attestation ID / AAID.
     * A unique identifier assigned to a model, class or batch of FIDO Authenticators
     * that all share the same characteristics, and which a Relying Party can use
     * to look up an Attestation Public Key and Authenticator Metadata for the device.
     * The first 4 characters of the AAID are the vendorID.
     *
     * @return list of allowed AAID - Authenticator Attestation ID.
     */
    // 驗證伺服器（Server）端對 Authenticator 身分的驗證白名單機制
    private String[] getAllowedAaids() {
        String[] ret = {"EBA0#0001", "0015#0001", "0012#0002", "0010#0001",
                "4e4e#0001", "5143#0001", "0011#0701", "0013#0001",
                "0014#0000", "0014#0001", "53EC#C002", "DAB8#8001",
                "DAB8#0011", "DAB8#8011", "5143#0111", "5143#0120",
                "4746#F816", "53EC#3801"};
        List<String> retList = new ArrayList<String>(Arrays.asList(ret));
        retList.addAll(Dash.getInstance().uuids);
        return retList.toArray(new String[0]);
    }

    /**
     * List of trusted Application Facet ID.
     * An (application) facet is how an application is implemented on various
     * platforms. For example, the application MyBank may have an Android app,
     * an iOS app, and a Web app. These are all facets of the MyBank application.
     * <p>
     * A platform-specific identifier (URI) for an application facet.
     * For Web applications, the facet id is the RFC6454 origin [RFC6454].
     * For Android applications, the facet id is the URI
     * android:apk-key-hash:<hash-of-apk-signing-cert>
     * For iOS, the facet id is the URI ios:bundle-id:<ios-bundle-id-of-app>.
     *
     * @return List of trusted Application Facet ID.
     */
    // 取得所有Facets
    @GetMapping("/public/uaf/facets")
    public Facets facets() {
        String timestamp = new Date().toString();
        Dash.getInstance().stats.put(Dash.LAST_REG_REQ, timestamp);
        String[] trustedIds = {"https://www.head2toes.org",
                "android:apk-key-hash:Df+2X53Z0UscvUu6obxC3rIfFyk",
                "android:apk-key-hash:bE0f1WtRJrZv/C0y9CM73bAUqiI",
                "android:apk-key-hash:Lir5oIjf552K/XN4bTul0VS3GfM",
                "https://openidconnect.ebay.com"};
        List<String> trustedIdsList = new ArrayList<String>(Arrays.asList(trustedIds));
        trustedIdsList.addAll(Dash.getInstance().facetIds);
        trustedIdsList.add(readFacet());
        Facets facets = new Facets();
        facets.trustedFacets = new TrustedFacets[1];
        TrustedFacets trusted = new TrustedFacets();
        trusted.version = new Version(1, 0);
        trusted.ids = trustedIdsList.toArray(new String[0]);
        facets.trustedFacets[0] = trusted;
        return facets;
    }

    private String readFacet() {
        return facetId;
    }

    /**
     * The AppID is an identifier for a set of different Facets of a relying
     * party's application. The AppID is a URL pointing to the TrustedFacets,
     * i.e. list of FacetIDs related to this AppID.
     *
     * @return a URL pointing to the TrustedFacets
     */
    private String getAppId() {
        // You can get it dynamically.
        // It only works if your server is not behind a reverse proxy
        return hostname + "/fidouaf/v1/public/uaf/facets";
        // Or you can define it statically
//		return "https://www.head2toes.org/fidouaf/v1/public/uaf/facets";
    }

    // 註冊回應
    @PostMapping("/public/regResponse")
    public RegistrationRecord[] processRegResponse(@RequestBody String payload) {
        RegistrationRecord[] result = null;
        if (!payload.isEmpty()) {
            RegistrationResponse[] fromJson = (new Gson()).fromJson(payload,
                    RegistrationResponse[].class);
            Dash.getInstance().stats.put(Dash.LAST_REG_RES, fromJson);
            Dash.getInstance().history.add(fromJson);

            RegistrationResponse registrationResponse = fromJson[0];
            result = new ProcessResponse().processRegResponse(registrationResponse);
            if (result[0].status.equals("SUCCESS")) {
                try {
                    //TODO: 改使用DB
                    StorageImpl.getInstance().store(result);
                } catch (DuplicateKeyException e) {
                    result = new RegistrationRecord[1];
                    result[0] = new RegistrationRecord();
                    result[0].status = "Error: Duplicate Key";
                } catch (SystemErrorException e1) {
                    result = new RegistrationRecord[1];
                    result[0] = new RegistrationRecord();
                    result[0].status = "Error: Data couldn't be stored in DB";
                }
            } else {
                //TODO Could be interesting refactor this method (and its callers) and modify return type to javax.ws.rs.core.Response and send Response.Status.PRECONDITION_FAILED error code.
                result = new RegistrationRecord[1];
                result[0] = new RegistrationRecord();
                result[0].status = "Error: payload could not be empty";
            }
        }
        return result;
    }

    //取消註冊
    @PostMapping("/public/deregRequest")
    public String deregRequestPublic(@RequestBody String payload) {

        return new DeregRequestProcessor().process(payload);
    }

    @GetMapping("/public/authRequest")
    public String getAuthReq() {
        return gson.toJson(getAuthReqObj());
    }

    @GetMapping("/public/authRequest/{appId}")
    public String getAuthForAppIdReq(@PathVariable String appId) {
        AuthenticationRequest[] authReqObj = getAuthReqObj();
        setAppId(appId, authReqObj[0].header);

        return gson.toJson(authReqObj);
    }

    private void setAppId(String appId, OperationHeader header) {
        if (appId == null || appId.isEmpty()) {
            return;
        }
        String decodedAppId = new String(Base64.decodeBase64(appId));
        Facets facets = facets();
        if (facets == null || facets.trustedFacets == null || facets.trustedFacets.length == 0
                || facets.trustedFacets[0] == null || facets.trustedFacets[0].ids == null) {
            return;
        }
        String[] ids = facets.trustedFacets[0].ids;
        for (int i = 0; i < ids.length; i++) {

            if (decodedAppId.equals(ids[i])) {
                header.appID = decodedAppId;
                break;
            }
        }
    }

    @GetMapping("/public/authRequest/{appId}/{trxContent}")
    public String getAuthTrxReq(@PathVariable String appId,
                                @PathVariable String trxContent) {
        AuthenticationRequest[] authReqObj = getAuthReqObj();
        setAppId(appId, authReqObj[0].header);
        setTransaction(trxContent, authReqObj);

        return gson.toJson(authReqObj);
    }

    private void setTransaction(String trxContent, AuthenticationRequest[] authReqObj) {
        authReqObj[0].transaction = new Transaction[1];
        Transaction t = new Transaction();
        t.content = trxContent;
        t.contentType = MediaType.TEXT_PLAIN_VALUE; //JAX-RS:TEXT_PLAIN Spring 版本:TEXT_PLAIN_VALUE
        authReqObj[0].transaction[0] = t;
    }

    public AuthenticationRequest[] getAuthReqObj() {
        AuthenticationRequest[] ret = new AuthenticationRequest[1];
        ret[0] = new FetchRequest(getAppId(), getAllowedAaids())
                .getAuthenticationRequest();
        Dash.getInstance().stats.put(Dash.LAST_AUTH_REQ, ret);
        Dash.getInstance().history.add(ret);
        return ret;
    }

    // 認證回應
    @PostMapping("/public/authResponse")
    public AuthenticatorRecord[] processAuthResponse(@RequestBody String payload) {
        if (!payload.isEmpty()) {
            Dash.getInstance().stats.put(Dash.LAST_AUTH_RES, payload);
            Gson gson = new Gson();
            AuthenticationResponse[] authResp = gson.fromJson(payload,
                    AuthenticationResponse[].class);
            Dash.getInstance().stats.put(Dash.LAST_AUTH_RES, authResp);
            Dash.getInstance().history.add(authResp);
            AuthenticatorRecord[] result = new ProcessResponse()
                    .processAuthResponse(authResp[0]);
            return result;
        }
        return new AuthenticatorRecord[0];
    }

    @PostMapping("/public/uafRegRequest")
    public ReturnUAFRegistrationRequest GetUAFRegistrationRequest(String payload) {
        RegistrationRequest[] result = getRegisReqPublic("iafuser01");
        ReturnUAFRegistrationRequest uafReq = null;
        if (result != null) {
            uafReq = new ReturnUAFRegistrationRequest();
            uafReq.statusCode = 1200;
            uafReq.uafRequest = result;
            uafReq.op = Operation.Reg;
            uafReq.lifetimeMillis = 5 * 60 * 1000;
        }
        return uafReq;
    }

    @PostMapping("/public/uafAuthRequest")
    public ReturnUAFAuthenticationRequest GetUAFAuthenticationRequest(
            String payload) {
        AuthenticationRequest[] result = getAuthReqObj();
        ReturnUAFAuthenticationRequest uafReq = null;
        if (result != null) {
            uafReq = new ReturnUAFAuthenticationRequest();
            uafReq.statusCode = 1200;
            uafReq.uafRequest = result;
            uafReq.op = Operation.Auth;
            uafReq.lifetimeMillis = 5 * 60 * 1000;
        }
        return uafReq;
    }

    @PostMapping("/public/uafDeregRequest")
    public ReturnUAFDeregistrationRequest GetUAFDeregistrationRequest(
            String payload) {
        String result = deregRequestPublic(payload);
        ReturnUAFDeregistrationRequest uafReq = new ReturnUAFDeregistrationRequest();
        if (result.equalsIgnoreCase("Success")) {
            uafReq.statusCode = 1200;
        } else if (result
                .equalsIgnoreCase("Failure: Problem in deleting record from local DB")) {
            uafReq.statusCode = 1404;
        } else if (result
                .equalsIgnoreCase("Failure: problem processing deregistration request")) {
            uafReq.statusCode = 1491;
        } else {
            uafReq.statusCode = 1500;

        }
        uafReq.uafRequest = null;
        uafReq.op = Operation.Dereg;
        uafReq.lifetimeMillis = 0;
        return uafReq;
    }

    @PostMapping("/public/uafAuthResponse")
    public ServerResponse UAFAuthResponse(String payload) {
        ServerResponse servResp = new ServerResponse();
        if (!payload.isEmpty()) {
            String findOp = payload;
            findOp = findOp.substring(findOp.indexOf("op") + 6,
                    findOp.indexOf(",", findOp.indexOf("op")) - 1);
            System.out.println("findOp=" + findOp);

            AuthenticatorRecord[] result = processAuthResponse(payload);

            if (result[0].status.equals("SUCCESS")) {
                servResp.statusCode = 1200;
                servResp.Description = "OK. Operation completed";
            } else if (result[0].status.equals("FAILED_SIGNATURE_NOT_VALID")
                    || result[0].status.equals("FAILED_SIGNATURE_VERIFICATION")
                    || result[0].status.equals("FAILED_ASSERTION_VERIFICATION")) {
                servResp.statusCode = 1496;
                servResp.Description = result[0].status;
            } else if (result[0].status.equals("INVALID_SERVER_DATA_EXPIRED")
                    || result[0].status
                    .equals("INVALID_SERVER_DATA_SIGNATURE_NO_MATCH")
                    || result[0].status.equals("INVALID_SERVER_DATA_CHECK_FAILED")) {
                servResp.statusCode = 1491;
                servResp.Description = result[0].status;
            } else {
                servResp.statusCode = 1500;
                servResp.Description = result[0].status;
            }
        } else {
            servResp.Description = "Error: payload is empty";
        }

        return servResp;
    }

    @PostMapping("/public/uafRegResponse")
    public ServerResponse UAFRegResponse(String payload) {
        ServerResponse servResp = new ServerResponse();
        if (!payload.isEmpty()) {
            String findOp = payload;
            findOp = findOp.substring(findOp.indexOf("op") + 6,
                    findOp.indexOf(",", findOp.indexOf("op")) - 1);
            System.out.println("findOp=" + findOp);

            RegistrationRecord[] result = processRegResponse(payload);

            if (result[0].status.equals("SUCCESS")) {
                servResp.statusCode = 1200;
                servResp.Description = "OK. Operation completed";
            } else if (result[0].status.equals("ASSERTIONS_CHECK_FAILED")) {
                servResp.statusCode = 1496;
                servResp.Description = result[0].status;
            } else if (result[0].status.equals("INVALID_SERVER_DATA_EXPIRED")
                    || result[0].status
                    .equals("INVALID_SERVER_DATA_SIGNATURE_NO_MATCH")
                    || result[0].status.equals("INVALID_SERVER_DATA_CHECK_FAILED")) {
                servResp.statusCode = 1491;
                servResp.Description = result[0].status;
            } else {
                servResp.statusCode = 1500;
                servResp.Description = result[0].status;
            }
        } else {
            servResp.Description = "Error: payload is empty";
        }

        return servResp;
    }

    @PostMapping("/public/uafRequest")
    public String GetUAFRequest(String payload) {
        String uafReq = null;
        if (!payload.isEmpty()) {
            Gson gson = new Gson();
            GetUAFRequest req = gson.fromJson(payload, GetUAFRequest.class);

            if (req.op.name().equals("Reg")) {
                RegistrationRequest[] result = getRegisReqPublic("iafuser01");
                ReturnUAFRegistrationRequest uafRegReq = null;
                if (result != null) {
                    uafRegReq = new ReturnUAFRegistrationRequest();
                    uafRegReq.statusCode = 1200;
                    uafRegReq.uafRequest = result;
                    uafRegReq.op = Operation.Reg;
                    uafRegReq.lifetimeMillis = 5 * 60 * 1000;
                }
                uafReq = gson.toJson(uafRegReq);
            } else if (req.op.name().equals("Auth")) {
                AuthenticationRequest[] result = getAuthReqObj();
                ReturnUAFAuthenticationRequest uafAuthReq = null;
                if (result != null) {
                    uafAuthReq = new ReturnUAFAuthenticationRequest();
                    uafAuthReq.statusCode = 1200;
                    uafAuthReq.uafRequest = result;
                    uafAuthReq.op = Operation.Auth;
                    uafAuthReq.lifetimeMillis = 5 * 60 * 1000;
                }
                uafReq = gson.toJson(uafAuthReq);
            } else if (req.op.name().equals("Dereg")) {
                String result = deregRequestPublic(payload);
                ReturnUAFDeregistrationRequest uafDeregReq = new ReturnUAFDeregistrationRequest();
                if (result.equalsIgnoreCase("Success")) {
                    uafDeregReq.statusCode = 1200;
                } else if (result
                        .equalsIgnoreCase("Failure: Problem in deleting record from local DB")) {
                    uafDeregReq.statusCode = 1404;
                } else if (result
                        .equalsIgnoreCase("Failure: problem processing deregistration request")) {
                    uafDeregReq.statusCode = 1491;
                } else {
                    uafDeregReq.statusCode = 1500;

                }
                uafDeregReq.uafRequest = null;
                uafDeregReq.op = Operation.Dereg;
                uafDeregReq.lifetimeMillis = 0;
                uafReq = gson.toJson(uafDeregReq);
            }
        }
        return uafReq;
    }

    @PostMapping("/public/uafResponse")
    public ServerResponse UAFResponse(String payload) {
        ServerResponse servResp = new ServerResponse();
        if (!payload.isEmpty()) {
            String findOp = payload;
            findOp = findOp.substring(findOp.indexOf("op") + 6,
                    findOp.indexOf(",", findOp.indexOf("op")) - 1);
            System.out.println("findOp=" + findOp);

            if (findOp.equals("Reg")) {
                RegistrationRecord[] result = processRegResponse(payload);

                if (result[0].status.equals("SUCCESS")) {
                    servResp.statusCode = 1200;
                    servResp.Description = "OK. Operation completed";
                } else if (result[0].status.equals("ASSERTIONS_CHECK_FAILED")) {
                    servResp.statusCode = 1496;
                    servResp.Description = result[0].status;
                } else if (result[0].status.equals("INVALID_SERVER_DATA_EXPIRED")
                        || result[0].status
                        .equals("INVALID_SERVER_DATA_SIGNATURE_NO_MATCH")
                        || result[0].status
                        .equals("INVALID_SERVER_DATA_CHECK_FAILED")) {
                    servResp.statusCode = 1491;
                    servResp.Description = result[0].status;
                } else {
                    servResp.statusCode = 1500;
                    servResp.Description = result[0].status;
                }
            } else if (findOp.equals("Auth")) {
                AuthenticatorRecord[] result = processAuthResponse(payload);

                if (result[0].status.equals("SUCCESS")) {
                    servResp.statusCode = 1200;
                    servResp.Description = "OK. Operation completed";
                } else if (result[0].status.equals("FAILED_SIGNATURE_NOT_VALID")
                        || result[0].status.equals("FAILED_SIGNATURE_VERIFICATION")
                        || result[0].status.equals("FAILED_ASSERTION_VERIFICATION")) {
                    servResp.statusCode = 1496;
                    servResp.Description = result[0].status;
                } else if (result[0].status.equals("INVALID_SERVER_DATA_EXPIRED")
                        || result[0].status
                        .equals("INVALID_SERVER_DATA_SIGNATURE_NO_MATCH")
                        || result[0].status
                        .equals("INVALID_SERVER_DATA_CHECK_FAILED")) {
                    servResp.statusCode = 1491;
                    servResp.Description = result[0].status;
                } else {
                    servResp.statusCode = 1500;
                    servResp.Description = result[0].status;
                }
            }
        } else {
            servResp.Description = "Error: payload is empty";
        }
        return servResp;
    }
}
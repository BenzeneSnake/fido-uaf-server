package org.ebayopensource.fido.uaf.service;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * 負責 fetch stub + JWT 驗 + parse 入口
 * <p>
 * Demonstration code.
 * <p>
 * Responsible for fetching the metadata BLOB, validating the JWT, and parsing the entry.
 * <p>
 * Functionality:
 * - Download BLOB
 * - Verify JWT (RS256)
 * - Decode payload
 * - Extract AAID
 * <p>
 * References:
 * https://fidoalliance.org/metadata/
 * https://fidoalliance.org/metadata-usage-terms-for-developers/
 */
@Slf4j
@Service
public class FidoMdsService {

    private static final String MDS_URL = "https://mds3.fidoalliance.org/";

    private static final String STUB_JWT;

    static {
        Security.addProvider(new BouncyCastleProvider());
        STUB_JWT = buildStubJwt();
    }

    private final Gson gson = new Gson();


    /**
     * Step 1: Download MDS BLOB.
     * <p>
     * Production: GET {MDS_URL}?token={token}, returns a compact JWS (header.payload.signature).
     * <p>
     * Demo: returns a stub directly.
     * <p>
     *
     * @return STUB_JWT For Demo
     */
    public String fetchMdsBlob() {
        log.info("[DEMO] Skipping real MDS fetch from {}, returning stub JWT", MDS_URL);
        return STUB_JWT;
    }

    /**
     * Step 2: Verify JWT signature (RS256).
     * <p>
     * Production flow:
     * <p>
     * 1. Extract leaf certificate (DER Base64) from header.x5c.
     * <p>
     * 2. Validate the certificate chain using the FIDO Alliance root CA (trust chain validation).
     * <p>
     * 3. Verify the JWS signature using the public key from the leaf certificate.
     * <p>
     * Demo: returns a stub directly.
     */
    public boolean verifyJwt(String jwt) throws Exception {
        String[] parts = splitJwt(jwt);

        String headerJson = decodeBase64Url(parts[0]);
        JsonObject header = gson.fromJson(headerJson, JsonObject.class);
        log.info("JWT alg: {}", header.get("alg").getAsString());

        JsonArray x5c = header.getAsJsonArray("x5c");
        if (x5c == null || x5c.isEmpty()) {
            // demo stub 沒有真實 cert，跳過驗簽
            log.warn("[DEMO] x5c is empty, skipping signature verification");
            return true;
        }

        // 取 leaf cert（x5c[0]）並還原成 X509Certificate
        byte[] certBytes = Base64.getDecoder().decode(x5c.get(0).getAsString());
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        log.info("Signer DN: {}", cert.getSubjectX500Principal().getName());

        // 用 leaf cert 公鑰驗 RS256 簽章
        Signature sig = Signature.getInstance("SHA256withRSA", "BC");
        sig.initVerify(cert.getPublicKey());
        sig.update((parts[0] + "." + parts[1]).getBytes());

        boolean valid = sig.verify(Base64.getUrlDecoder().decode(parts[2]));
        log.info("JWT signature valid: {}", valid);
        return valid;
    }

    /**
     * Step 3: Base64url decode payload → JSON parse → MdsPayload.
     * <p>
     * MDS3 payload structure: { legalHeader, no, nextUpdate, entries: [...] }
     */
    public MdsPayload parseMdsPayload(String jwt) {
        String[] parts = splitJwt(jwt);
        String payloadJson = decodeBase64Url(parts[1]);
        MdsPayload payload = gson.fromJson(payloadJson, MdsPayload.class);
        log.info("MDS no={}, nextUpdate={}, entries={}",
                payload.no(), payload.nextUpdate(), payload.entries().size());
        return payload;
    }

    /**
     * Step 4: Retrieve the metadata entry for a specific AAID (UAF uses aaid; FIDO2 uses aaguid).
     */
    public Optional<MdsEntry> findByAaid(String aaid) {
        return parseMdsPayload(fetchMdsBlob()).entries().stream()
                .filter(e -> aaid.equals(e.aaid()))
                .findFirst();
    }

    // ─── MDS data model ───────────────────────────────────────────────────────

    public record MdsPayload(
            String legalHeader,
            int no,
            String nextUpdate,
            List<MdsEntry> entries
    ) {
    }

    /**
     * MDS3 TOC entry；UAF uses aaid，FIDO2 uses aaguid
     */
    public record MdsEntry(
            String aaid,
            String aaguid,
            String url,
            String hash,
            List<StatusReport> statusReports
    ) {
    }

    public record StatusReport(
            String status,
            String effectiveDate
    ) {
    }

    // ─── helpers ──────────────────────────────────────────────────────────────

    private String[] splitJwt(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) throw new IllegalArgumentException("Invalid JWT: expected 3 parts");
        return parts;
    }

    private String decodeBase64Url(String encoded) {
        return new String(Base64.getUrlDecoder().decode(encoded));
    }

    // ─── Demo stub（no real cert / no real signature）─────────────────────────

    private static String buildStubJwt() {
        // x5c 為空 → verifyJwt 會跳過驗簽並記 WARN
        String header = base64Url("""
                {"alg":"RS256","x5c":[]}""");

        String payload = base64Url("""
                {
                  "legalHeader": "[DEMO] FIDO Alliance MDS3 stub - not a real blob",
                  "no": 42,
                  "nextUpdate": "2026-05-01",
                  "entries": [
                    {
                      "aaid": "4e4e#4005",
                      "url": "https://mds3.fidoalliance.org/metadata/4e4e4005",
                      "hash": "stub-hash-1",
                      "statusReports": [{"status": "FIDO_CERTIFIED", "effectiveDate": "2020-01-01"}]
                    },
                    {
                      "aaid": "0012#0001",
                      "url": "https://mds3.fidoalliance.org/metadata/00120001",
                      "hash": "stub-hash-2",
                      "statusReports": [{"status": "NOT_FIDO_CERTIFIED", "effectiveDate": "2021-06-01"}]
                    }
                  ]
                }""");

        String sig = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("demo-signature-not-real".getBytes());

        return header + "." + payload + "." + sig;
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.trim().getBytes());
    }
}

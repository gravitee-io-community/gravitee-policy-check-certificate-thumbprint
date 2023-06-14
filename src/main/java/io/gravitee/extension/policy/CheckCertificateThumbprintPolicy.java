/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.gravitee.extension.policy;

import io.gravitee.extension.policy.configuration.CheckCertificateThumbprintPolicyConfiguration;
import io.gravitee.extension.policy.configuration.PolicyScope;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CheckCertificateThumbprintPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(CheckCertificateThumbprintPolicy.class);
    private CheckCertificateThumbprintPolicyConfiguration configuration;

    public CheckCertificateThumbprintPolicy(CheckCertificateThumbprintPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, PolicyChain policyChain) {

        if (configuration.getScope() == null || configuration.getScope() == PolicyScope.REQUEST) {

            final String accessToken = extractHeaderValue(request, configuration.getTokenHeader());
            final String certificate = extractHeaderValue(request, configuration.getCertHeader());

            if (accessToken == null || certificate == null) {
                LOGGER.error("CERT-001: Headers not found, please, check you configuration.");
                fail(policyChain);
                return;
            }

            if (!computeX5tS256(certificate).equals(extractX5tS256Token(accessToken))) {
                LOGGER.error("CERT-002: Certificate not belong to the current access_token.");
                fail(policyChain);
                return;
            }

        }

        policyChain.doNext(request, response);
    }

    private void fail(PolicyChain policyChain) {
        policyChain.failWith(
                PolicyResult.failure(configuration.getErrorCode(), configuration.getErrorMessage())
        );
    }

    /* 2 ways to have the x5t#S256 in the token :
    {
        ...
        "cnf": {
            "x5t#S256": "f3ggo5QshPknsYKPlSFqKPW8_zXnYHVSftS2cenu8Sk"
        }
        ...
    }

    OR

    {
        ...
        "x5t#S256": "f3ggo5QshPknsYKPlSFqKPW8_zXnYHVSftS2cenu8Sk"
        ...
    }
    */
    public String extractX5tS256Token(String accessToken) {

        String x5tS256 = null;
        Base64.Decoder decoder = Base64.getDecoder();
        String token = accessToken.split(" ")[1];
        String[] chunks = token.split("\\.");
        String payload = new String(decoder.decode(chunks[1]));
        JsonObject claims = new JsonObject(payload);

        if (claims.containsKey("cnf")) {
            x5tS256 = claims.getJsonObject("cnf").getString("x5t#S256");
        } else {
            x5tS256 = claims.getString("x5t#S256");
        }

        if (x5tS256 == null) {
            LOGGER.error("CERT-010: Empty and cannot be parsed from token.");
            return null;
        }

        return x5tS256;
    }

    public String computeX5tS256(String certificate) {

        String decodeCert = null;

        try {

            decodeCert = URLDecoder.decode(certificate, StandardCharsets.UTF_8.toString());
            InputStream targetStream = new ByteArrayInputStream(decodeCert.getBytes());

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate certStringCertificate = (X509Certificate) cf.generateCertificate(targetStream);
            byte[] certFinal = certStringCertificate.getEncoded();

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] x5tS256Cert = sha256.digest(certFinal);

            return Base64.getUrlEncoder().withoutPadding().encodeToString(x5tS256Cert);

        } catch (UnsupportedEncodingException | CertificateException | NoSuchAlgorithmException e) {
            LOGGER.error("CERT-020: Error to compute x5t#S256: " + e.toString());
        }

        return null;
    }

    public String extractHeaderValue(Request request, String key) {

        String value = null;

        if (request.headers().contains(key)) {
            value = request.headers().getAll(key).get(0).split(",")[0];
        } else {
            LOGGER.error("CERT-030: There's no headers detected on request.");
        }

        return value;
    }
}

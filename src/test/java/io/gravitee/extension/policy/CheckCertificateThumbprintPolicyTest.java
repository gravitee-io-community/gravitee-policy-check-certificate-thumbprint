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
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import static org.mockito.Mockito.*;
import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(MockitoJUnitRunner.class)
public class CheckCertificateThumbprintPolicyTest {

    @Mock
    ExecutionContext executionContext;

    @Mock
    Request mockRequest;

    @Mock
    Response mockResponse;

    @Mock
    PolicyChain mockPolicychain;

    @Mock
    private CheckCertificateThumbprintPolicyConfiguration configuration;

    private String fakeAccessToken = "Bearer eyJhbGciOiJQUzI1NiIsInR5cCI6ImF0K2p3dCIsImtpZCI6IlBvRHpvbmhCZGQ1SGlsU3dWdF" +
            "9PN3hHUnh4V18wNzZsc2p5aUNIVnVnODQifQ.eyJzdWIiOiI5ODc1NzMyMTA5NCIsInNjb3BlIjoib3BlbmlkIHBheW1lbnRzI" +
            "GNvbnNlbnQ6dXJuOmNvcmFzY2Q6MjhjOTdhOWQtNTQzZS00NzNiLWEzYWEtYWZmMDNjMzg4NDUzIiwiaXNzIjoiaHR0cHM6Ly9" +
            "hdXRoLm9wZW5iYW5raW5nLnN0YWdlLmNvcmEuY29tLmJyIiwiY25mIjp7Ing1dCNTMjU2IjoibHVTRHZQXzU3ZThHc1Z1UXZPQ" +
            "jVPbVA3SFo1ZTkzZ2NuVDNvWDhLMnBjWSJ9LCJleHAiOjE2MzUyMTA3MTQsImlhdCI6MTYzNTIxMDExNCwiY2xpZW50X2lkIjo" +
            "iMjUzMDM3MDg1Mjk0MzQiLCJqdGkiOiI3NlItV0JlMy1XX05EdWJ5MlowMmpKQjlWc0xWc1lyazV5MDdVLVhFT2RnIn0.OUlJo" +
            "xMxt-FC70Z-ily8zOEJdRanR0_b1RfXUiMip4ki9NW5Rs-NESkScG5vQUAYhm-jTabEg_nVVI-RdRQ4aMNhOy7g7ktjpKU8T57" +
            "jooXApULgfBWT-pN8mmKpl_lF3bqWZaMKRbpXTpgJrNlPWjPtXf-Jfesm3WkiTZw4tCsXrsfTUqZByJHutU7qFboiPu7nLvW05" +
            "TCKeq_jx8OeBnxyLSjFRD0y7rMfz57EMeyLw3zEzgqtXmZQbiDY9G-a1O-6Q1JruSYeF5BOU4T71ktS9opmbPWZmP_TgxPOtfG" +
            "PaIZYuB9ih7LD9-bKyoAgYCRb8eUmFFr8O8EDEFirpQ";

    private String fakeAccessTokenWithoutCnf = "Bearer eyJhbGciOiJQUzI1NiIsInR5cCI6ImF0K2p3dCIsImtpZCI6IlBvRHpvbmhCZGQ" +
            "1SGlsU3dWdF9PN3hHUnh4V18wNzZsc2p5aUNIVnVnODQifQ.eyJzdWIiOiI5ODc1NzMyMTA5NCIsInNjb3BlIjoib3BlbmlkIH" +
            "BheW1lbnRzIGNvbnNlbnQ6dXJuOmNvcmFzY2Q6MjhjOTdhOWQtNTQzZS00NzNiLWEzYWEtYWZmMDNjMzg4NDUzIiwiaXNzIjoi" +
            "aHR0cHM6Ly9hdXRoLm9wZW5iYW5raW5nLnN0YWdlLmNvcmEuY29tLmJyIiwieDV0I1MyNTYiOiJsdVNEdlBfNTdlOEdzVnVRdk" +
            "9CNU9tUDdIWjVlOTNnY25UM29YOEsycGNZIiwiZXhwIjoxNjM1MjEwNzE0LCJpYXQiOjE2MzUyMTAxMTQsImNsaWVudF9pZCI6" +
            "IjI1MzAzNzA4NTI5NDM0IiwianRpIjoiNzZSLVdCZTMtV19ORHVieTJaMDJqSkI5VnNMVnNZcms1eTA3VS1YRU9kZyJ9.iwi21" +
            "jCVox_Gq_h_02lhUz7rK7r6Ixec05m0zYNF-mttvC0LXvWYyYz1zipreb5KeJhwKpPpuA_we7kX_Muo638uwRpIFXNbk4MH1we" +
            "Q3HwOzBGXIg77co2RK4hpxtEHWVuv3I9lotb4dDMTAc6O1g6TRDtlT7vC42ArHsQuvGVuUerbua10c8xlhUA1EA1qpngeXy4xG" +
            "OWRxmME5eaF8SwgNXE-47KfN415GTw0Ib5JBYS70mfNmlEj2to0JAB64z4iSdVdHFHILuAl3MvobzflDsu4buoeSR3p7hW8dKi" +
            "NCBMqfnDhNk6zVKA4IcTg8_zCzPJ13NmIs38ao_U9eA";

    private String fakeCertificate = "-----BEGIN%20CERTIFICATE-----%0AMIIG%2BjCCBeKgAwIBAgIUXU6XaJxR7dm6HZ6SWwucLWDwDGc" +
            "wDQYJKoZIhvcNAQEL%0ABQAwcTELMAkGA1UEBhMCQlIxHDAaBgNVBAoTE09wZW4gQmFua2luZyBCcmFzaWwx%0AFTATBgNVBAs" +
            "TDE9wZW4gQmFua2luZzEtMCsGA1UEAxMkT3BlbiBCYW5raW5nIFNB%0ATkRCT1ggSXNzdWluZyBDQSAtIEcxMB4XDTIxMDcxMz" +
            "IwMTMwMFoXDTIyMDgxMjIw%0AMTMwMFowggEdMQswCQYDVQQGEwJCUjELMAkGA1UECBMCUlMxETAPBgNVBAcTCEJP%0AVEFGT0" +
            "dPMRwwGgYDVQQKExNPcGVuIEJhbmtpbmcgQnJhc2lsMS0wKwYDVQQLEyQ3%0ANGU5MjlkOS0zM2I2LTRkODUtOGJhNy1jMTQ2Y" +
            "zg2N2E4MTcxHzAdBgNVBAMTFm1v%0AY2stdHBwLTEucmFpZGlhbS5jb20xFjAUBgNVBAUTDTEzMzUzMjM2MDAxODkxNDAy%0AB" +
            "goJkiaJk%2FIsZAEBEyQ5ZTM1Nzk5NS1hMTkxLTQ4NjAtOWRiNy1jZWRhMzY5MmE4%0AYzkxHTAbBgNVBA8TFFByaXZhdGUgT3" +
            "JnYW5pemF0aW9uMRMwEQYLKwYBBAGCNzwC%0AAQMTAkJSMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5AX5rOlxG" +
            "E68%0APsSzYTnOp5UPZ1IO0BX%2B%2Fbe5dVZzmyYj3TCjCDloa98zOEDHhrBQtcWs06dPfsLY%0AD2oyehzKMmxKBUvBynmS%" +
            "2ByWgb9gGYIOLO47IUkhaVk4ZXwUCo6u7tMXWpdSGGUrt%0AHrIgnVy91MkRL0RizVyxW8it0BDsJso%2BrSyI%2BvV2uHYDJt" +
            "6Orz6QKMoIQ0kWm17g%0AdFXKzkIv20wJFmFDSqQ8s4xpZCtNdv9eKZPVSVYXIBAMLK9ZZAz%2F4YF%2FkwtIy5Xp%0AiTmaUU" +
            "d4IQ8zqA5k1f1g20vydZRFoxWhihv%2BoXQwZMDiCBOuZdv11DC6LGsa70p%2F%0AKj90LcjmRQIDAQABo4IC2jCCAtYwDAYDV" +
            "R0TAQH%2FBAIwADAfBgNVHSMEGDAWgBSG%0Af1itF%2FWCtk60BbP7sM4RQ99MvjBMBggrBgEFBQcBAQRAMD4wPAYIKwYBBQUH" +
            "MAGG%0AMGh0dHA6Ly9vY3NwLnNhbmRib3gucGtpLm9wZW5iYW5raW5nYnJhc2lsLm9yZy5i%0AcjBLBgNVHR8ERDBCMECgPqA8" +
            "hjpodHRwOi8vY3JsLnNhbmRib3gucGtpLm9wZW5i%0AYW5raW5nYnJhc2lsLm9yZy5ici9pc3N1ZXIuY3JsMA4GA1UdDwEB%2F" +
            "wQEAwIFoDAT%0ABgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUX7Z4hKwMMVZVlayEWFBdvq4q%0ALEwwIQYDVR0RBBowG" +
            "IIWbW9jay10cHAtMS5yYWlkaWFtLmNvbTCCAaEGA1UdIASC%0AAZgwggGUMIIBkAYKKwYBBAGDui9kATCCAYAwggE2BggrBgEF" +
            "BQcCAjCCASgMggEk%0AVGhpcyBDZXJ0aWZpY2F0ZSBpcyBzb2xlbHkgZm9yIHVzZSB3aXRoIFJhaWRpYW0g%0AU2VydmljZXMg" +
            "TGltaXRlZCBhbmQgb3RoZXIgcGFydGljaXBhdGluZyBvcmdhbmlz%0AYXRpb25zIHVzaW5nIFJhaWRpYW0gU2VydmljZXMgTGl" +
            "taXRlZHMgVHJ1c3QgRnJh%0AbWV3b3JrIFNlcnZpY2VzLiBJdHMgcmVjZWlwdCwgcG9zc2Vzc2lvbiBvciB1c2Ug%0AY29uc3R" +
            "pdHV0ZXMgYWNjZXB0YW5jZSBvZiB0aGUgUmFpZGlhbSBTZXJ2aWNlcyBM%0AdGQgQ2VydGljaWNhdGUgUG9saWN5IGFuZCByZW" +
            "xhdGVkIGRvY3VtZW50cyB0aGVy%0AZWluLjBEBggrBgEFBQcCARY4aHR0cDovL2Nwcy5zYW5kYm94LnBraS5vcGVuYmFu%0Aa2" +
            "luZ2JyYXNpbC5vcmcuYnIvcG9saWNpZXMwDQYJKoZIhvcNAQELBQADggEBABQt%0AKDrPGJmvyXhcNBr21T7sL79TVTI8g7EHl" +
            "awX3a%2BE2Np%2FDV2qLCdpAQwCJ4c9EKjj%0Az1I7u5xLCT83EpKn10qwOeJSRWUCfOLrr7FcqEgvIysH2i2cYRvT4gHCHyhE" +
            "%2FNaq%0AjL6L%2BNdW8TGzPGPjMOYcWk%2FmN%2FzDhARPtKHRxX04JI3uRu5DEAWlN3Nyo%2BxokeYI%0A6eMmhgHzgaHXn%" +
            "2B0pHQK%2FMh2m0FYVskuJW0pinXJ8ImXjY0sdBVbktIt4bvrledhg%0Ag5z5jVENzh5KjUP1bOLXm%2FBt%2FJSU0T8z7unTX" +
            "%2BDLd%2BEAKfVjfs%2Bap2uy3YceyR5S%0AZ%2FoJrI9TNCN4uc%2F4gVw%3D%0A-----END%20CERTIFICATE-----%0A";

    private String getFakeCertificateSecondary = "-----BEGIN%20CERTIFICATE-----%0AMIIDiTCCAnGgAwIBAgIUASUrtWTeIi" +
            "CBweRS3aj8xNf4fJYwDQYJKoZIhvcNAQEL%0ABQAwVDELMAkGA1UEBhMCQlIxCzAJBgNVBAgMAlNQMQswCQYDVQQHDAJTUDENMA" +
            "sG%0AA1UECgwEdGVzdDENMAsGA1UECwwEdGVzdDENMAsGA1UEAwwEdGVzdDAeFw0yMTEw%0AMjkwMjI5MzBaFw0yMjEwMjkwMjI" +
            "5MzBaMFQxCzAJBgNVBAYTAkJSMQswCQYDVQQI%0ADAJTUDELMAkGA1UEBwwCU1AxDTALBgNVBAoMBHRlc3QxDTALBgNVBAsMBHR" +
            "lc3Qx%0ADTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDc%0APUDtG6WBGYVG%2F2mQxqx1lh" +
            "q1YTZ3ddTExZMf0ZHLqF4Ga76XT3Yu7A%2F3vt4p4GdW%0AVcyECFVXW9BVluVEIKGmfJz2mgZxAwrRcrL0dyRynKu%2F%2B5UD" +
            "kTLuv9RpQWf6MPUZ%0Ai5sDgaUDYW0Y%2BsscVqQi0PseCdDM63LZ7LzHxf7iT3qjjSIntg%2FOw1dohX%2BaJUW1%0A7YIX71q" +
            "lGYuOToP50cVtY7Me4IWIS3m%2FeAE5chuVMogEcdqpfMv4jMY4QsBC0fIT%0Ao38fp7q3tQq1hPFsYK9cmfWypDwkaDgT5Cobz" +
            "7K%2Fb0qELIIoe7Slk3gfFXMVQEc0%0ASbtcvtbtxrB6XUlVFSxTAgMBAAGjUzBRMB0GA1UdDgQWBBSh2tw5Fq%2B5miUSk1XZ%" +
            "0AqIeoA%2FiiSjAfBgNVHSMEGDAWgBSh2tw5Fq%2B5miUSk1XZqIeoA%2FiiSjAPBgNVHRMB%0AAf8EBTADAQH%2FMA0GCSqGSI" +
            "b3DQEBCwUAA4IBAQDSZnntEVbMlnNvnq6Gxu16pRxg%0APzul4I7psFHbLIUkvnWaxk83tDFx%2F148eJT7Yc2gVd621esFzM07" +
            "5oNrK4ENidwW%0A8qOEW2U3JPqNHaE0lsnVXSKHdA3QiakmM%2B4HOnNC7iRfifwrjDZbNTiWYxsQQ7zU%0AA6Q5Hi9mV1bvzHv" +
            "n60a5erLftnrMpNMB3Xe%2Feq9fqnR%2B7zigj6d%2FnqxotR9z2%2BzU%0AhPS96aZVxp6u9o3VZmEQ7LbGrdGPjfwcf4uuDlh" +
            "lu2V4Q%2Bvd7d8JWXO8KPtGjviM%0AM6HEh06O6kEu6tEhikea28upWrqxMInvErYsW12CQ4cKPen3W%2F57JV55pUdI%0A" +
            "-----END%20CERTIFICATE-----%0A";

    @Before
    public void init() {
        initMocks(this);
    }

    @Test
    public void shouldSucceedCausedMatchedX5tS256Cnf() throws Exception {

        when(configuration.getTokenHeader()).thenReturn("Authorization");
        when(configuration.getCertHeader()).thenReturn("ssl-client-cert");

        HttpHeaders httpHeaders = HttpHeaders.create();
        httpHeaders.set("Authorization", fakeAccessToken);
        httpHeaders.set("ssl-client-cert", fakeCertificate);

        when(mockRequest.headers()).thenReturn(httpHeaders);
        CheckCertificateThumbprintPolicy policy = new CheckCertificateThumbprintPolicy(configuration);

        policy.onRequest(mockRequest, mockResponse, mockPolicychain);

        verify(mockPolicychain, never()).failWith(any(PolicyResult.class));
        verify(mockPolicychain, times(1)).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldSucceedCausedMatchedX5tS256WithoutCnf() throws Exception {

        when(configuration.getTokenHeader()).thenReturn("Authorization");
        when(configuration.getCertHeader()).thenReturn("ssl-client-cert");

        HttpHeaders httpHeaders = HttpHeaders.create();
        httpHeaders.set("Authorization", fakeAccessTokenWithoutCnf);
        httpHeaders.set("ssl-client-cert", fakeCertificate);

        when(mockRequest.headers()).thenReturn(httpHeaders);
        CheckCertificateThumbprintPolicy policy = new CheckCertificateThumbprintPolicy(configuration);

        policy.onRequest(mockRequest, mockResponse, mockPolicychain);

        verify(mockPolicychain, never()).failWith(any(PolicyResult.class));
        verify(mockPolicychain, times(1)).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldFailCausedDifferencesBetweenX5tS256() throws Exception {

        when(configuration.getTokenHeader()).thenReturn("Authorization");
        when(configuration.getCertHeader()).thenReturn("ssl-client-cert");

        HttpHeaders httpHeaders = HttpHeaders.create();
        httpHeaders.set("Authorization", fakeAccessToken);
        httpHeaders.set("ssl-client-cert", getFakeCertificateSecondary);

        when(mockRequest.headers()).thenReturn(httpHeaders);
        CheckCertificateThumbprintPolicy policy = new CheckCertificateThumbprintPolicy(configuration);

        policy.onRequest(mockRequest, mockResponse, mockPolicychain);

        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }
}
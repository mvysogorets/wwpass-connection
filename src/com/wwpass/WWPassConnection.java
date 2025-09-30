/**
 * WWPassConnection.java
 * <p>
 * WWPass Service Provider SDK
 *
 * @copyright (c) WWPass Corporation, 2012
 * @author Rostislav Kondratenko <r.kondratenko@wwpass.com>
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.wwpass;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.net.ProtocolException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import org.json.simple.JSONObject;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class WWPassConnection {

    private static byte[] hexToBytes(String s) {
        if (s == null) {
            return null;
        }
        try {
            return Hex.decodeHex(s);
        } catch (DecoderException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("SpellCheckingInspection")
    public static final String WWPassCA = "-----BEGIN CERTIFICATE-----\nMIIGATCCA+mgAwIBAgIJAN7JZUlglGn4MA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNV\nBAYTAlVTMRswGQYDVQQKExJXV1Bhc3MgQ29ycG9yYXRpb24xKzApBgNVBAMTIldX\nUGFzcyBDb3Jwb3JhdGlvbiBQcmltYXJ5IFJvb3QgQ0EwIhgPMjAxMjExMjgwOTAw\nMDBaGA8yMDUyMTEyODA4NTk1OVowVzELMAkGA1UEBhMCVVMxGzAZBgNVBAoTEldX\nUGFzcyBDb3Jwb3JhdGlvbjErMCkGA1UEAxMiV1dQYXNzIENvcnBvcmF0aW9uIFBy\naW1hcnkgUm9vdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmF\npl1WX80osygWx4ZX8xGyYfHx8cpz29l5s/7mgQIYCrmUSLK9KtSryA0pmzrOFkyN\nBuT0OU5ucCuv2WNgUriJZ78b8sekW1oXy2QXndZSs+CA+UoHFw0YqTEDO659/Tjk\nNqlE5HMXdYvIb7jhcOAxC8gwAJFgAkQboaMIkuWsAnpOtKzrnkWHGz45qoyICjqz\nfeDcN0dh3ITMHXrYiwkVq5fGXHPbuJPbuBN+unnakbL3Ogk3yPnEcm6YV+HrxQ7S\nKy83q60Abdy8ft0RpSJeUkBjJVwiHu4y4j5iKC1tNgtV8qE9Zf2g5vAHzL3obqnu\nIMr8JpmWp0MrrUa9jYOtKXk2LnZnfxurJ74NVk2RmuN5I/H0a/tUrHWtCE5pcVNk\nb3vmoqeFsbTs2KDCMq/gzUhHU31l4Zrlz+9DfBUxlb5fNYB5lF4FnR+5/hKgo75+\nOaNjiSfp9gTH6YfFCpS0OlHmKhsRJlR2aIKpTUEG9hjSg3Oh7XlpJHhWolQQ2BeL\nn++3UOyRMTDSTZ1bGa92oz5nS+UUsE5noUZSjLM+KbaJjZGCxzO9y2wiFBbRSbhL2\nzXpUD2dMB1G30jZwytjn15VAMEOYizBoHEp2Nf9PNhsDGa32AcpJ2a0n89pbSOlu\nnyr/vEzYjJ2DZ/TWQQb7upi0G2kRX17UIZ5ZfhjmBAgMBAAGjgcswgcgwHQYDVR0O\nBBYEFGu/H4b/gn8RzL7XKHBT6K4BQcl7MIGIBgNVHSMEgYAwfoAUa78fhv+CfxHM\nvtcocFPorgFByXuhW6RZMFcxCzAJBgNVBAYTAlVTMRswGQYDVQQKExJXV1Bhc3Mg\nQ29ycG9yYXRpb24xKzApBgNVBAMTIldXUGFzcyBDb3Jwb3JhdGlvbiBQcmltYXJ5\nIFJvb3QgQ0GCCQDeyWVJYJRp+DAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwIB\nBjANBgkqhkiG9w0BAQsFAAOCAgEAE46CMikI7378mkC3qZyKcVxkNfLRe3eD4h04\nOO27rmfZj/cMrDDCt0Bn2t9LBUGBdXfZEn13gqn598F6lmLoObtN4QYqlyXrFcPz\nFiwQarba+xq8togxjMkZ2y70MlV3/PbkKkwv4bBjOcLZQ1DsYehPdsr57C6Id4Ee\nkEQs/aMtKcMzZaSipkTuXFxfxW4uBifkH++tUASD44OD2r7m1UlSQ5viiv3l0qvA\nB89dPifVnIeAvPcd7+GY2RXTZCw36ZipnFiOWT9TkyTDpB/wjWQNFrgmmQvxQLeW\nBWIUSaXJwlVzMztdtThnt/bNZNGPMRfaZ76OljYB9BKC7WUmss2f8toHiys+ERHz\n0xfCTVhowlz8XtwWfb3A17jzJBm+KAlQsHPgeBEqtocxvBJcqhOiKDOpsKHHz+ng\nexIO3elr1TCVutPTE+UczYTBRsL+jIdoIxm6aA9rrN3qDVwMnuHThSrsiwyqOXCz\nzjCaCf4l5+KG5VNiYPytiGicv8PCBjwFkzIr+LRSyUiYzAZuiyRchpdT+yRAfL7q\nqHBuIHYhG3E47a3GguwUwUGcXR+NjrSmteHRDONOUYUCH41hw6240Mo1lL4F+rpr\nLEBB84k3+v+AtbXePEwvp+o1nu/+1sRkhqlNFHN67vakqC4xTxiuPxu6Pb/uDeNI\nip0+E9I=\n-----END CERTIFICATE-----";

    @SuppressWarnings("SpellCheckingInspection")
    private static final byte[] WWPassCA_DER = hexToBytes("30820601308203e9a003020102020900dec96549609469f8300d06092a864886f70d01010b05003057310b3009060355040613025553311b3019060355040a131257575061737320436f72706f726174696f6e312b30290603550403132257575061737320436f72706f726174696f6e205072696d61727920526f6f742043413022180f32303132313132383039303030305a180f32303532313132383038353935395a3057310b3009060355040613025553311b3019060355040a131257575061737320436f72706f726174696f6e312b30290603550403132257575061737320436f72706f726174696f6e205072696d61727920526f6f7420434130820222300d06092a864886f70d01010105000382020f003082020a0282020100c985a65d565fcd28b32816c78657f311b261f1f1f1ca73dbd979b3fee68102180ab99448b2bd2ad4abc80d299b3ace164c8d06e4f4394e6e702bafd9636052b88967bf1bf2c7a45b5a17cb64179dd652b3e080f94a07170d18a931033bae7dfd38e436a944e47317758bc86fb8e170e0310bc83000916002441ba1a30892e5ac027a4eb4aceb9e45871b3e39aa8c880a3ab37de0dc374761dc84cc1d7ad88b0915ab97c65c73dbb893dbb8137eba79da91b2f73a0937c8f9c4726e9857e1ebc50ed22b2f37abad006ddcbc7edd11a5225e524063255c221eee32e23e62282d6d360b55f2a13d65fda0e6f007ccbde86ea9ee20cafc269996a7432bad46bd8d83ad2979362e76677f1bab27be0d564d919ae37923f1f46bfb54ac75ad084e697153646f7be6a2a785b1b4ecd8a0c232afe0cd4847537d65e19ae5cfef437c153195be5f358079945e059d1fb9fe12a0a3be7e39a3638927e9f604c7e987c50a94b43a51e62a1b112654766882a94d4106f618d28373a1ed7969247856a25410d8178bfbedd43b244c4c34936756c66bdda8cf99d2f9452c1399e85194a32ccf8a6da2636460b1ccef72db088505b4526e12f6cd7a540f674c0751b7d23670cad8e7d795403043988b30681c4a7635ff4f361b0319adf601ca49d9ad27f3da5b48e96ecabfef1336232760d9fd359041beeea62d06da4457d7b50867965f8639810203010001a381cb3081c8301d0603551d0e041604146bbf1f86ff827f11ccbed7287053e8ae0141c97b3081880603551d23048180307e80146bbf1f86ff827f11ccbed7287053e8ae0141c97ba15ba4593057310b3009060355040613025553311b3019060355040a131257575061737320436f72706f726174696f6e312b30290603550403132257575061737320436f72706f726174696f6e205072696d61727920526f6f74204341820900dec96549609469f8300f0603551d130101ff040530030101ff300b0603551d0f040403020106300d06092a864886f70d01010b05000382020100138e82322908ef7efc9a40b7a99c8a715c6435f2d17b7783e21d3838edbbae67d98ff70cac30c2b74067dadf4b0541817577d9127d7782a9f9f7c17a9662e839bb4de1062a9725eb15c3f3162c106ab6dafb1abcb688318cc919db2ef4325577fcf6e42a4c2fe1b06339c2d94350ec61e84f76caf9ec2e8877811e90442cfda32d29c33365a4a2a644ee5c5c5fc56e2e0627e41fefad500483e38383dabee6d54952439be28afde5d2abc007cf5d3e27d59c8780bcf71defe198d915d3642c37e998a99c588e593f539324c3a41ff08d640d16b826990bf140b79605621449a5c9c25573333b5db53867b7f6cd64d18f3117da67be8e963601f41282ed6526b2cd9ff2da078b2b3e1111f3d317c24d5868c25cfc5edc167dbdc0d7b8f32419be280950b073e078112ab68731bc125caa13a22833a9b0a1c7cfe9e07b120edde96bd53095bad3d313e51ccd84c146c2fe8c87682319ba680f6bacddea0d5c0c9ee1d3852aec8b0caa3970b3ce309a09fe25e7e286e5536260fcad88689cbfc3c2063c0593322bf8b452c94898cc066e8b245c869753fb24407cbeeaa8706e2076211b7138edadc682ec14c1419c5d1f8d8eb4a6b5e1d10ce34e5185021f8d61c3adb8d0ca3594be05faba6b2c4041f38937faff80b5b5de3c4c2fa7ea359eeffed6c46486a94d14737aeef6a4a82e314f18ae3f1bba3dbfee0de3488a9d3e13d2");

    private static final byte[] MESSAGE_NONCE = hexToBytes("7c0bb4d60d8bc2c90d90d957bd2d21fd");

    public static class WWPassReply {
        private String data;
        private Integer ttl = null;
        private byte[] messageKey = null;
        private String originalTicket = null;

        public WWPassReply(String data) {
            this.data = data;
        }

        public String getData() {
            return data;
        }

        public void setData(String data) {
            this.data = data;
        }

        public Integer getTtl() {
            return ttl;
        }

        public void setTtl(Integer ttl) {
            this.ttl = ttl;
        }

        public void setTtl(String ttl) throws NumberFormatException {
            this.ttl = Integer.valueOf(ttl);
        }

        public byte[] getMessageKey() {
            return messageKey;
        }

        public void setMessageKey(byte[] messageKey) {
            this.messageKey = messageKey;
        }

        public String getOriginalTicket() {
            return originalTicket;
        }

        public void setOriginalTicket(String originalTicket) {
            this.originalTicket = originalTicket;
        }
    }

    public static class WWPassProtocolException extends ProtocolException {
        private static final long serialVersionUID = 1;

        public WWPassProtocolException(String message) {
            super(message);
        }
    }

    private static PKCS8EncodedKeySpec readKeyFile(String path) throws IOException {
        try (FileInputStream stream = new FileInputStream(path)) {
            FileChannel fileChannel = stream.getChannel();
            MappedByteBuffer byteBuffer = fileChannel.map(FileChannel.MapMode.READ_ONLY, 0, fileChannel.size());
            String pem = Charset.defaultCharset().decode(byteBuffer).toString();
            pem = pem.replaceFirst("-----BEGIN (RSA )?PRIVATE KEY-----", "")
                     .replaceFirst("-----END (RSA )?PRIVATE KEY-----", "")
                     .replaceAll("\r", "")
                     .replaceAll("\n", "");
            return new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem));
        }
    }

    private static X509Certificate readCertificate(String certFile) throws IOException, GeneralSecurityException {
        X509Certificate cert;
        try (FileInputStream certInput = new FileInputStream(certFile)) {
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certInput);
        }
        return cert;
    }

    private static String getDataFromElement(Element el) {
        String encoding = el.getAttributes().getNamedItem("encoding").getTextContent();
        String ret;
        if ("base64".equalsIgnoreCase(encoding)) {
            byte[] buffer = Base64.getDecoder().decode(el.getTextContent());
            ret = new String(buffer, StandardCharsets.UTF_8);
        } else {
            ret = el.getTextContent();
        }
        return ret;
    }

    private static WWPassReply getReplyData(InputStream rawXMLInput) throws IOException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        Document dom;
        try {
            documentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);  // To prevent XXE
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            InputStreamReader streamReader = new InputStreamReader(rawXMLInput);
            StringBuilder stringBuilder = new StringBuilder();
            BufferedReader bufferedReader = new BufferedReader(streamReader);
            String line = bufferedReader.readLine();

            while (line != null) {
                stringBuilder.append(line);
                line = bufferedReader.readLine();
            }

            String reply = stringBuilder.toString();
            dom = documentBuilder.parse(new InputSource(new StringReader(reply)));
            Element element = dom.getDocumentElement();
            Node node = element.getElementsByTagName("result").item(0);
            boolean result = node.getTextContent().equalsIgnoreCase("true");
            Element data = (Element) element.getElementsByTagName("data").item(0);
            String strData = getDataFromElement(data);

            if (!result) {
                throw new WWPassProtocolException("SPFE returned error: " + strData);
            }

            WWPassReply replyObject = new WWPassReply(strData);
            NodeList ttlElements = element.getElementsByTagName("ttl");

            if (ttlElements.getLength() > 0) {
                try {
                    replyObject.setTtl(getDataFromElement((Element) (ttlElements.item(0))));
                } catch (NumberFormatException e) {
                    throw new WWPassProtocolException("unable to convert ttl to int");
                }
            }

            NodeList originalTicketElements = element.getElementsByTagName("originalTicket");
            if (originalTicketElements.getLength() > 0) {
                replyObject.setOriginalTicket(getDataFromElement((Element) (originalTicketElements.item(0))));
            }

            return replyObject;
        } catch (ParserConfigurationException | SAXException e) {
            throw new WWPassProtocolException("Malformed SPFE reply: " + e.getMessage());
        }
    }

    public static final String DEFAULT_SPFE_ADDRESS = "spfe.wwpass.com";
    public static final int DEFAULT_TIMEOUT_SEC = 10;

    protected SSLContext SPFEContext;
    final protected int timeoutMs;
    final protected String SpfeURL;

    public WWPassConnection(X509Certificate cert, PKCS8EncodedKeySpec key, int timeoutSec, String spfeAddr) throws IOException, GeneralSecurityException {
        timeoutMs = timeoutSec * 1000;
        SpfeURL = "https://" + spfeAddr + "/";

        // Setting up client certificate and key
        X509Certificate[] chain = { cert };
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(key);
        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(privateKey, chain);

        // This provides no additional security, but Java requires to password-protect the key
        byte[] passwordBytes = new byte[16];
        new SecureRandom().nextBytes(passwordBytes);
        String password = Base64.getEncoder().encodeToString(passwordBytes);

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
        pkcs12.load(null);
        pkcs12.setEntry("WWPass client key", privateKeyEntry, new KeyStore.PasswordProtection(password.toCharArray()));
        keyManagerFactory.init(pkcs12, password.toCharArray());

        // Making root CA certificate
        InputStream inputStream = new ByteArrayInputStream(WWPassCA_DER);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate rootCA = (X509Certificate) certificateFactory.generateCertificate(inputStream);

        // Creating TrustManager for this CA
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        KeyStore jks = KeyStore.getInstance("JKS");
        jks.load(null);
        jks.setCertificateEntry("WWPass Root CA", rootCA);

        trustManagerFactory.init(jks);

        SPFEContext = SSLContext.getInstance("TLS");
        SPFEContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
    }

    public WWPassConnection(X509Certificate cert, PKCS8EncodedKeySpec key, String spfeAddr) throws IOException, GeneralSecurityException {
        this(cert, key, DEFAULT_TIMEOUT_SEC, spfeAddr);
    }

    public WWPassConnection(X509Certificate cert, PKCS8EncodedKeySpec key, int timeoutSec) throws IOException, GeneralSecurityException {
        this(cert, key, timeoutSec, DEFAULT_SPFE_ADDRESS);
    }

    public WWPassConnection(X509Certificate cert, PKCS8EncodedKeySpec key) throws IOException, GeneralSecurityException {
        this(cert, key, DEFAULT_TIMEOUT_SEC, DEFAULT_SPFE_ADDRESS);
    }

    public WWPassConnection(String certFile, String keyFile, int timeoutSec, String spfeAddr) throws IOException, GeneralSecurityException {
        this(readCertificate(certFile), readKeyFile(keyFile), timeoutSec, spfeAddr);
    }

    public WWPassConnection(String certFile, String keyFile, String spfeAddr) throws IOException, GeneralSecurityException {
        this(readCertificate(certFile), readKeyFile(keyFile), DEFAULT_TIMEOUT_SEC, spfeAddr);
    }

    public WWPassConnection(String certFile, String keyFile, int timeoutSec) throws IOException, GeneralSecurityException {
        this(readCertificate(certFile), readKeyFile(keyFile), timeoutSec, DEFAULT_SPFE_ADDRESS);
    }

    public WWPassConnection(String certFile, String keyFile) throws IOException, GeneralSecurityException {
        this(readCertificate(certFile), readKeyFile(keyFile), DEFAULT_TIMEOUT_SEC, DEFAULT_SPFE_ADDRESS);
    }

    protected WWPassReply makeRequest(String method, String command, Map<String, String> parameters) throws IOException {
        String commandUrl= SpfeURL + command + ".xml";
        StringBuilder paramsString = new StringBuilder();
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            paramsString.append(URLEncoder.encode(entry.getKey(), "UTF-8")).append("=").append(URLEncoder.encode(entry.getValue(), "UTF-8")).append("&");
        }
        if ("GET".equalsIgnoreCase(method)) {
            commandUrl += "?" + paramsString;
        } else if (!"POST".equalsIgnoreCase(method)) {
            throw new IllegalArgumentException("Method " + method + " not supported");
        }

        try {
            HttpsURLConnection connection = (HttpsURLConnection) new URI(commandUrl).toURL().openConnection();
            connection.setReadTimeout(timeoutMs);
            connection.setSSLSocketFactory(SPFEContext.getSocketFactory());
            if ("POST".equalsIgnoreCase(method)) {
                connection.setDoOutput(true);
                OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream());
                writer.write(paramsString.toString());
                writer.flush();
            }
            return getReplyData(connection.getInputStream());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Command-parameters combination is invalid: " + e.getMessage());
        }
    }


    // API

    // Functions to work with user containers

    public String getPUID(String ticket, String auth_type) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("ticket", ticket);
        if (auth_type != null && !auth_type.isEmpty()) {
            parameters.put("auth_type", auth_type);
        }
        return makeRequest("GET", "puid", parameters).getData();
    }

    public String getPUID(String ticket) throws IOException {
        return getPUID(ticket, null);
    }

    public WWPassReply getTicket(String auth_type, int ttl, String message, String qas_uri) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        if (auth_type != null && !auth_type.isEmpty()) {
            parameters.put("auth_type", auth_type);
        }
        if (ttl != 0) {
            parameters.put("ttl", Integer.toString(ttl));
        }
        byte[] messageKey = null;
        if (message != null && !message.isEmpty()) {
            final int TAG_LENGTH = 16;
            messageKey = new byte[TAG_LENGTH];
            new SecureRandom().nextBytes(messageKey);
            SecretKey secretKey = new SecretKeySpec(messageKey, "AES");
            byte[] result;
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH * 8, MESSAGE_NONCE);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
                result = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
            byte[] cipherText = Arrays.copyOfRange(result, 0, result.length - TAG_LENGTH);
            byte[] tag = Arrays.copyOfRange(result, result.length - TAG_LENGTH, result.length);
            Map<String, String> map = new HashMap<>();
            Base64.Encoder base64encoder = Base64.getEncoder();
            map.put("ciphertext", base64encoder.encodeToString(cipherText));
            map.put("tag", base64encoder.encodeToString(tag));
            map.put("nonce", base64encoder.encodeToString(MESSAGE_NONCE));
            parameters.put("message", new JSONObject(map).toJSONString());
        }
        if (qas_uri != null && !qas_uri.isEmpty()) {
            parameters.put("qasUri", qas_uri);
        }
        WWPassReply ret = makeRequest("GET", "get", parameters);
        ret.setMessageKey(messageKey);
        return ret;
    }

    public String getTicket() throws IOException {
        return getTicket(null, 0, null, null).getData();
    }

    public String getTicket(int ttl) throws IOException {
        return getTicket(null, ttl, null, null).getData();
    }

    public WWPassReply getTicket(String message) throws IOException {
        return getTicket(null, 0, message, null);
    }

    public WWPassReply getTicket(int ttl, String message) throws IOException {
        return getTicket(null, ttl, message, null);
    }

    public WWPassReply getTicket(String auth_type, int ttl) throws IOException {
        return getTicket(auth_type, ttl, null, null);
    }

    public WWPassReply getTicket(String auth_type, int ttl, String message) throws IOException {
        return getTicket(auth_type, ttl, message, null);
    }

    public WWPassReply getTicket(String message, String qas_uri) throws IOException {
        return getTicket(null, 0, message, qas_uri);
    }

    public WWPassReply getTicket(int ttl, String message, String qas_uri) throws IOException {
        return getTicket(null, ttl, message, qas_uri);
    }

    public String getName() throws IOException {
        String ticket = getTicket(0);
        int colon = ticket.indexOf(':');
        if (colon == -1) {
            throw new WWPassProtocolException("SPFE returned ticket without a colon");
        }
        return ticket.substring(0, colon);
    }

    public String putTicket(String ticket, String auth_type, int ttl) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("ticket", ticket);
        if (auth_type != null && !auth_type.isEmpty()) {
            parameters.put("auth_type", auth_type);
        }
        if (ttl != 0) {
            parameters.put("ttl", Integer.toString(ttl));
        }
        return makeRequest("GET", "put", parameters).getData();
    }

    public String putTicket(String ticket, String auth_type) throws IOException {
        return putTicket(ticket, auth_type, 0);
    }

    public String putTicket(String ticket, int ttl) throws IOException {
        return putTicket(ticket, null, ttl);
    }

    public String putTicket(String ticket) throws IOException {
        return putTicket(ticket, null, 0);
    }

    public String readData(String ticket, String container) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("ticket", ticket);
        if (container != null && !container.isEmpty()) {
            parameters.put("container", container);
        }
        return makeRequest("GET", "read", parameters).getData();
    }

    public String readData(String ticket) throws IOException {
        return readData(ticket, null);
    }

    public String readDataAndLock(String ticket, String container, int lockTimeout) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("ticket", ticket);
        if (container != null && !container.isEmpty()) {
            parameters.put("container", container);
        }
        parameters.put("to", Integer.toString(lockTimeout));
        parameters.put("lock", "1");
        return makeRequest("GET", "read", parameters).getData();
    }

    public String readDataAndLock(String ticket, int lockTimeout) throws IOException {
        return readDataAndLock(ticket, null, lockTimeout);
    }

    public String writeData(String ticket, String data, String container) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("ticket", ticket);
        parameters.put("data", data);
        if (container != null && !container.isEmpty()) {
            parameters.put("container", container);
        }
        return makeRequest("POST", "write", parameters).getData();
    }

    public String writeData(String ticket, String data) throws IOException {
        return writeData(ticket, data, null);
    }

    public String writeDataAndUnlock(String ticket, String data, String container) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("ticket", ticket);
        parameters.put("data", data);
        if (container != null && !container.isEmpty()) {
            parameters.put("container", container);
        }
        parameters.put("unlock", "1");
        return makeRequest("POST", "write", parameters).getData();
    }

    public String writeDataAndUnlock(String ticket, String data) throws IOException {
        return writeDataAndUnlock(ticket, data, null);
    }

    public String lock(String ticket, int lockTimeout, String lockid) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("ticket", ticket);
        parameters.put("to", Integer.toString(lockTimeout));
        if (lockid != null && !lockid.isEmpty()) {
            parameters.put("lockid", lockid);
        }
        return makeRequest("GET", "lock", parameters).getData();
    }

    public String lock(String ticket, int lockTimeout) throws IOException {
        return lock(ticket, lockTimeout, null);
    }

    public String unlock(String ticket, String lockid) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("ticket", ticket);
        if (lockid != null && !lockid.isEmpty()) {
            parameters.put("lockid", lockid);
        }
        return makeRequest("GET", "unlock", parameters).getData();
    }

    public String unlock(String ticket) throws IOException {
        return unlock(ticket, null);
    }

    // Functions to work with SP-only containers

    public String createPFID(String data) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        if (data != null && !data.isEmpty()) {
            parameters.put("data", data);
        }
        return makeRequest("POST", "sp/create", parameters).getData();
    }

    public String createPFID() throws IOException {
        return createPFID(null);
    }

    public String removePFID(String pfid) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("pfid", pfid);
        return makeRequest("GET", "sp/remove", parameters).getData();
    }

    public String readDataSP(String pfid) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("pfid", pfid);
        return makeRequest("GET", "sp/read", parameters).getData();
    }

    public String readDataSPandLock(String pfid, int lockTimeout) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("pfid", pfid);
        parameters.put("to", Integer.toString(lockTimeout));
        parameters.put("lock", "1");
        return makeRequest("GET", "sp/read", parameters).getData();
    }

    public String writeDataSP(String pfid, String data) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("pfid", pfid);
        parameters.put("data", data);
        return makeRequest("POST", "sp/write", parameters).getData();
    }

    public String writeDataSPandUnlock(String pfid, String data) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("pfid", pfid);
        parameters.put("data", data);
        parameters.put("unlock", "1");
        return makeRequest("POST", "sp/write", parameters).getData();
    }

    public String lockSP(String lockid, int lockTimeout) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("lockid", lockid);
        parameters.put("to", Integer.toString(lockTimeout));
        return makeRequest("GET", "sp/lock", parameters).getData();
    }

    public String unlockSP(String lockid) throws IOException {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("lockid", lockid);
        return makeRequest("GET", "sp/unlock", parameters).getData();
    }
}

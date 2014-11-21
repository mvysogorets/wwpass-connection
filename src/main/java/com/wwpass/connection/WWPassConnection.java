/**
 * WWPassConnection.java 
 *
 * WWPass Client Library
 *
 * @copyright (c) WWPass Corporation, 2012
 * @author Rostislav Kondratenko <r.kondratenko@wwpass.com>, Stanislav Panyushkin <s.panyushkin@wwpass.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.wwpass.connection;


import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.net.URLCodec;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import com.wwpass.connection.exceptions.WWPassProtocolException;

/**
 *
 * Client library implement the SPFE interface protocol. This library is made available to
 * WWPass Service Providers to facilitate WWPass integration into the desired application
 * (typically a website) enabling the secure exchange of WWPass authentication data.
 *
 */
public class WWPassConnection {
    public static final String WWPassCA=
            "-----BEGIN CERTIFICATE-----\nMIIGATCCA+mgAwIBAgIJAN7JZUlglGn4MA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNV\nBAYTAlVTMRswGQYDVQQKExJXV1Bhc3MgQ29ycG9yYXRpb24xKzApBgNVBAMTIldX\nUGFzcyBDb3Jwb3JhdGlvbiBQcmltYXJ5IFJvb3QgQ0EwIhgPMjAxMjExMjgwOTAw\nMDBaGA8yMDUyMTEyODA4NTk1OVowVzELMAkGA1UEBhMCVVMxGzAZBgNVBAoTEldX\nUGFzcyBDb3Jwb3JhdGlvbjErMCkGA1UEAxMiV1dQYXNzIENvcnBvcmF0aW9uIFBy\naW1hcnkgUm9vdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmF\npl1WX80osygWx4ZX8xGyYfHx8cpz29l5s/7mgQIYCrmUSLK9KtSryA0pmzrOFkyN\nBuT0OU5ucCuv2WNgUriJZ78b8sekW1oXy2QXndZSs+CA+UoHFw0YqTEDO659/Tjk\nNqlE5HMXdYvIb7jhcOAxC8gwAJFgAkQboaMIkuWsAnpOtKzrnkWHGz45qoyICjqz\nfeDcN0dh3ITMHXrYiwkVq5fGXHPbuJPbuBN+unnakbL3Ogk3yPnEcm6YV+HrxQ7S\nKy83q60Abdy8ft0RpSJeUkBjJVwiHu4y4j5iKC1tNgtV8qE9Zf2g5vAHzL3obqnu\nIMr8JpmWp0MrrUa9jYOtKXk2LnZnfxurJ74NVk2RmuN5I/H0a/tUrHWtCE5pcVNk\nb3vmoqeFsbTs2KDCMq/gzUhHU31l4Zrlz+9DfBUxlb5fNYB5lF4FnR+5/hKgo75+\nOaNjiSfp9gTH6YfFCpS0OlHmKhsRJlR2aIKpTUEG9hjSg3Oh7XlpJHhWolQQ2BeL\nn++3UOyRMTDSTZ1bGa92oz5nS+UUsE5noUZSjLM+KbaJjZGCxzO9y2wiFBbRSbhL2\nzXpUD2dMB1G30jZwytjn15VAMEOYizBoHEp2Nf9PNhsDGa32AcpJ2a0n89pbSOlu\nnyr/vEzYjJ2DZ/TWQQb7upi0G2kRX17UIZ5ZfhjmBAgMBAAGjgcswgcgwHQYDVR0O\nBBYEFGu/H4b/gn8RzL7XKHBT6K4BQcl7MIGIBgNVHSMEgYAwfoAUa78fhv+CfxHM\nvtcocFPorgFByXuhW6RZMFcxCzAJBgNVBAYTAlVTMRswGQYDVQQKExJXV1Bhc3Mg\nQ29ycG9yYXRpb24xKzApBgNVBAMTIldXUGFzcyBDb3Jwb3JhdGlvbiBQcmltYXJ5\nIFJvb3QgQ0GCCQDeyWVJYJRp+DAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwIB\nBjANBgkqhkiG9w0BAQsFAAOCAgEAE46CMikI7378mkC3qZyKcVxkNfLRe3eD4h04\nOO27rmfZj/cMrDDCt0Bn2t9LBUGBdXfZEn13gqn598F6lmLoObtN4QYqlyXrFcPz\nFiwQarba+xq8togxjMkZ2y70MlV3/PbkKkwv4bBjOcLZQ1DsYehPdsr57C6Id4Ee\nkEQs/aMtKcMzZaSipkTuXFxfxW4uBifkH++tUASD44OD2r7m1UlSQ5viiv3l0qvA\nB89dPifVnIeAvPcd7+GY2RXTZCw36ZipnFiOWT9TkyTDpB/wjWQNFrgmmQvxQLeW\nBWIUSaXJwlVzMztdtThnt/bNZNGPMRfaZ76OljYB9BKC7WUmss2f8toHiys+ERHz\n0xfCTVhowlz8XtwWfb3A17jzJBm+KAlQsHPgeBEqtocxvBJcqhOiKDOpsKHHz+ng\nexIO3elr1TCVutPTE+UczYTBRsL+jIdoIxm6aA9rrN3qDVwMnuHThSrsiwyqOXCz\nzjCaCf4l5+KG5VNiYPytiGicv8PCBjwFkzIr+LRSyUiYzAZuiyRchpdT+yRAfL7q\nqHBuIHYhG3E47a3GguwUwUGcXR+NjrSmteHRDONOUYUCH41hw6240Mo1lL4F+rpr\nLEBB84k3+v+AtbXePEwvp+o1nu/+1sRkhqlNFHN67vakqC4xTxiuPxu6Pb/uDeNI\nip0+E9I=\n-----END CERTIFICATE-----";

    private static final byte[] WWPassCA_DER = {
            (byte)0x30, (byte)0x82, (byte)0x06, (byte)0x01, (byte)0x30, (byte)0x82, (byte)0x03, (byte)0xe9, (byte)0xa0, (byte)0x03, (byte)0x02, (byte)0x01,
            (byte)0x02, (byte)0x02, (byte)0x09, (byte)0x00, (byte)0xde, (byte)0xc9, (byte)0x65, (byte)0x49, (byte)0x60, (byte)0x94, (byte)0x69, (byte)0xf8,
            (byte)0x30, (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xf7, (byte)0x0d, (byte)0x01, (byte)0x01,
            (byte)0x0b, (byte)0x05, (byte)0x00, (byte)0x30, (byte)0x57, (byte)0x31, (byte)0x0b, (byte)0x30, (byte)0x09, (byte)0x06, (byte)0x03, (byte)0x55,
            (byte)0x04, (byte)0x06, (byte)0x13, (byte)0x02, (byte)0x55, (byte)0x53, (byte)0x31, (byte)0x1b, (byte)0x30, (byte)0x19, (byte)0x06, (byte)0x03,
            (byte)0x55, (byte)0x04, (byte)0x0a, (byte)0x13, (byte)0x12, (byte)0x57, (byte)0x57, (byte)0x50, (byte)0x61, (byte)0x73, (byte)0x73, (byte)0x20,
            (byte)0x43, (byte)0x6f, (byte)0x72, (byte)0x70, (byte)0x6f, (byte)0x72, (byte)0x61, (byte)0x74, (byte)0x69, (byte)0x6f, (byte)0x6e, (byte)0x31,
            (byte)0x2b, (byte)0x30, (byte)0x29, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x03, (byte)0x13, (byte)0x22, (byte)0x57, (byte)0x57,
            (byte)0x50, (byte)0x61, (byte)0x73, (byte)0x73, (byte)0x20, (byte)0x43, (byte)0x6f, (byte)0x72, (byte)0x70, (byte)0x6f, (byte)0x72, (byte)0x61,
            (byte)0x74, (byte)0x69, (byte)0x6f, (byte)0x6e, (byte)0x20, (byte)0x50, (byte)0x72, (byte)0x69, (byte)0x6d, (byte)0x61, (byte)0x72, (byte)0x79,
            (byte)0x20, (byte)0x52, (byte)0x6f, (byte)0x6f, (byte)0x74, (byte)0x20, (byte)0x43, (byte)0x41, (byte)0x30, (byte)0x22, (byte)0x18, (byte)0x0f,
            (byte)0x32, (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x31, (byte)0x31, (byte)0x32, (byte)0x38, (byte)0x30, (byte)0x39, (byte)0x30, (byte)0x30,
            (byte)0x30, (byte)0x30, (byte)0x5a, (byte)0x18, (byte)0x0f, (byte)0x32, (byte)0x30, (byte)0x35, (byte)0x32, (byte)0x31, (byte)0x31, (byte)0x32,
            (byte)0x38, (byte)0x30, (byte)0x38, (byte)0x35, (byte)0x39, (byte)0x35, (byte)0x39, (byte)0x5a, (byte)0x30, (byte)0x57, (byte)0x31, (byte)0x0b,
            (byte)0x30, (byte)0x09, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x06, (byte)0x13, (byte)0x02, (byte)0x55, (byte)0x53, (byte)0x31,
            (byte)0x1b, (byte)0x30, (byte)0x19, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x0a, (byte)0x13, (byte)0x12, (byte)0x57, (byte)0x57,
            (byte)0x50, (byte)0x61, (byte)0x73, (byte)0x73, (byte)0x20, (byte)0x43, (byte)0x6f, (byte)0x72, (byte)0x70, (byte)0x6f, (byte)0x72, (byte)0x61,
            (byte)0x74, (byte)0x69, (byte)0x6f, (byte)0x6e, (byte)0x31, (byte)0x2b, (byte)0x30, (byte)0x29, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04,
            (byte)0x03, (byte)0x13, (byte)0x22, (byte)0x57, (byte)0x57, (byte)0x50, (byte)0x61, (byte)0x73, (byte)0x73, (byte)0x20, (byte)0x43, (byte)0x6f,
            (byte)0x72, (byte)0x70, (byte)0x6f, (byte)0x72, (byte)0x61, (byte)0x74, (byte)0x69, (byte)0x6f, (byte)0x6e, (byte)0x20, (byte)0x50, (byte)0x72,
            (byte)0x69, (byte)0x6d, (byte)0x61, (byte)0x72, (byte)0x79, (byte)0x20, (byte)0x52, (byte)0x6f, (byte)0x6f, (byte)0x74, (byte)0x20, (byte)0x43,
            (byte)0x41, (byte)0x30, (byte)0x82, (byte)0x02, (byte)0x22, (byte)0x30, (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x2a, (byte)0x86, (byte)0x48,
            (byte)0x86, (byte)0xf7, (byte)0x0d, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x05, (byte)0x00, (byte)0x03, (byte)0x82, (byte)0x02, (byte)0x0f,
            (byte)0x00, (byte)0x30, (byte)0x82, (byte)0x02, (byte)0x0a, (byte)0x02, (byte)0x82, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0xc9, (byte)0x85,
            (byte)0xa6, (byte)0x5d, (byte)0x56, (byte)0x5f, (byte)0xcd, (byte)0x28, (byte)0xb3, (byte)0x28, (byte)0x16, (byte)0xc7, (byte)0x86, (byte)0x57,
            (byte)0xf3, (byte)0x11, (byte)0xb2, (byte)0x61, (byte)0xf1, (byte)0xf1, (byte)0xf1, (byte)0xca, (byte)0x73, (byte)0xdb, (byte)0xd9, (byte)0x79,
            (byte)0xb3, (byte)0xfe, (byte)0xe6, (byte)0x81, (byte)0x02, (byte)0x18, (byte)0x0a, (byte)0xb9, (byte)0x94, (byte)0x48, (byte)0xb2, (byte)0xbd,
            (byte)0x2a, (byte)0xd4, (byte)0xab, (byte)0xc8, (byte)0x0d, (byte)0x29, (byte)0x9b, (byte)0x3a, (byte)0xce, (byte)0x16, (byte)0x4c, (byte)0x8d,
            (byte)0x06, (byte)0xe4, (byte)0xf4, (byte)0x39, (byte)0x4e, (byte)0x6e, (byte)0x70, (byte)0x2b, (byte)0xaf, (byte)0xd9, (byte)0x63, (byte)0x60,
            (byte)0x52, (byte)0xb8, (byte)0x89, (byte)0x67, (byte)0xbf, (byte)0x1b, (byte)0xf2, (byte)0xc7, (byte)0xa4, (byte)0x5b, (byte)0x5a, (byte)0x17,
            (byte)0xcb, (byte)0x64, (byte)0x17, (byte)0x9d, (byte)0xd6, (byte)0x52, (byte)0xb3, (byte)0xe0, (byte)0x80, (byte)0xf9, (byte)0x4a, (byte)0x07,
            (byte)0x17, (byte)0x0d, (byte)0x18, (byte)0xa9, (byte)0x31, (byte)0x03, (byte)0x3b, (byte)0xae, (byte)0x7d, (byte)0xfd, (byte)0x38, (byte)0xe4,
            (byte)0x36, (byte)0xa9, (byte)0x44, (byte)0xe4, (byte)0x73, (byte)0x17, (byte)0x75, (byte)0x8b, (byte)0xc8, (byte)0x6f, (byte)0xb8, (byte)0xe1,
            (byte)0x70, (byte)0xe0, (byte)0x31, (byte)0x0b, (byte)0xc8, (byte)0x30, (byte)0x00, (byte)0x91, (byte)0x60, (byte)0x02, (byte)0x44, (byte)0x1b,
            (byte)0xa1, (byte)0xa3, (byte)0x08, (byte)0x92, (byte)0xe5, (byte)0xac, (byte)0x02, (byte)0x7a, (byte)0x4e, (byte)0xb4, (byte)0xac, (byte)0xeb,
            (byte)0x9e, (byte)0x45, (byte)0x87, (byte)0x1b, (byte)0x3e, (byte)0x39, (byte)0xaa, (byte)0x8c, (byte)0x88, (byte)0x0a, (byte)0x3a, (byte)0xb3,
            (byte)0x7d, (byte)0xe0, (byte)0xdc, (byte)0x37, (byte)0x47, (byte)0x61, (byte)0xdc, (byte)0x84, (byte)0xcc, (byte)0x1d, (byte)0x7a, (byte)0xd8,
            (byte)0x8b, (byte)0x09, (byte)0x15, (byte)0xab, (byte)0x97, (byte)0xc6, (byte)0x5c, (byte)0x73, (byte)0xdb, (byte)0xb8, (byte)0x93, (byte)0xdb,
            (byte)0xb8, (byte)0x13, (byte)0x7e, (byte)0xba, (byte)0x79, (byte)0xda, (byte)0x91, (byte)0xb2, (byte)0xf7, (byte)0x3a, (byte)0x09, (byte)0x37,
            (byte)0xc8, (byte)0xf9, (byte)0xc4, (byte)0x72, (byte)0x6e, (byte)0x98, (byte)0x57, (byte)0xe1, (byte)0xeb, (byte)0xc5, (byte)0x0e, (byte)0xd2,
            (byte)0x2b, (byte)0x2f, (byte)0x37, (byte)0xab, (byte)0xad, (byte)0x00, (byte)0x6d, (byte)0xdc, (byte)0xbc, (byte)0x7e, (byte)0xdd, (byte)0x11,
            (byte)0xa5, (byte)0x22, (byte)0x5e, (byte)0x52, (byte)0x40, (byte)0x63, (byte)0x25, (byte)0x5c, (byte)0x22, (byte)0x1e, (byte)0xee, (byte)0x32,
            (byte)0xe2, (byte)0x3e, (byte)0x62, (byte)0x28, (byte)0x2d, (byte)0x6d, (byte)0x36, (byte)0x0b, (byte)0x55, (byte)0xf2, (byte)0xa1, (byte)0x3d,
            (byte)0x65, (byte)0xfd, (byte)0xa0, (byte)0xe6, (byte)0xf0, (byte)0x07, (byte)0xcc, (byte)0xbd, (byte)0xe8, (byte)0x6e, (byte)0xa9, (byte)0xee,
            (byte)0x20, (byte)0xca, (byte)0xfc, (byte)0x26, (byte)0x99, (byte)0x96, (byte)0xa7, (byte)0x43, (byte)0x2b, (byte)0xad, (byte)0x46, (byte)0xbd,
            (byte)0x8d, (byte)0x83, (byte)0xad, (byte)0x29, (byte)0x79, (byte)0x36, (byte)0x2e, (byte)0x76, (byte)0x67, (byte)0x7f, (byte)0x1b, (byte)0xab,
            (byte)0x27, (byte)0xbe, (byte)0x0d, (byte)0x56, (byte)0x4d, (byte)0x91, (byte)0x9a, (byte)0xe3, (byte)0x79, (byte)0x23, (byte)0xf1, (byte)0xf4,
            (byte)0x6b, (byte)0xfb, (byte)0x54, (byte)0xac, (byte)0x75, (byte)0xad, (byte)0x08, (byte)0x4e, (byte)0x69, (byte)0x71, (byte)0x53, (byte)0x64,
            (byte)0x6f, (byte)0x7b, (byte)0xe6, (byte)0xa2, (byte)0xa7, (byte)0x85, (byte)0xb1, (byte)0xb4, (byte)0xec, (byte)0xd8, (byte)0xa0, (byte)0xc2,
            (byte)0x32, (byte)0xaf, (byte)0xe0, (byte)0xcd, (byte)0x48, (byte)0x47, (byte)0x53, (byte)0x7d, (byte)0x65, (byte)0xe1, (byte)0x9a, (byte)0xe5,
            (byte)0xcf, (byte)0xef, (byte)0x43, (byte)0x7c, (byte)0x15, (byte)0x31, (byte)0x95, (byte)0xbe, (byte)0x5f, (byte)0x35, (byte)0x80, (byte)0x79,
            (byte)0x94, (byte)0x5e, (byte)0x05, (byte)0x9d, (byte)0x1f, (byte)0xb9, (byte)0xfe, (byte)0x12, (byte)0xa0, (byte)0xa3, (byte)0xbe, (byte)0x7e,
            (byte)0x39, (byte)0xa3, (byte)0x63, (byte)0x89, (byte)0x27, (byte)0xe9, (byte)0xf6, (byte)0x04, (byte)0xc7, (byte)0xe9, (byte)0x87, (byte)0xc5,
            (byte)0x0a, (byte)0x94, (byte)0xb4, (byte)0x3a, (byte)0x51, (byte)0xe6, (byte)0x2a, (byte)0x1b, (byte)0x11, (byte)0x26, (byte)0x54, (byte)0x76,
            (byte)0x68, (byte)0x82, (byte)0xa9, (byte)0x4d, (byte)0x41, (byte)0x06, (byte)0xf6, (byte)0x18, (byte)0xd2, (byte)0x83, (byte)0x73, (byte)0xa1,
            (byte)0xed, (byte)0x79, (byte)0x69, (byte)0x24, (byte)0x78, (byte)0x56, (byte)0xa2, (byte)0x54, (byte)0x10, (byte)0xd8, (byte)0x17, (byte)0x8b,
            (byte)0xfb, (byte)0xed, (byte)0xd4, (byte)0x3b, (byte)0x24, (byte)0x4c, (byte)0x4c, (byte)0x34, (byte)0x93, (byte)0x67, (byte)0x56, (byte)0xc6,
            (byte)0x6b, (byte)0xdd, (byte)0xa8, (byte)0xcf, (byte)0x99, (byte)0xd2, (byte)0xf9, (byte)0x45, (byte)0x2c, (byte)0x13, (byte)0x99, (byte)0xe8,
            (byte)0x51, (byte)0x94, (byte)0xa3, (byte)0x2c, (byte)0xcf, (byte)0x8a, (byte)0x6d, (byte)0xa2, (byte)0x63, (byte)0x64, (byte)0x60, (byte)0xb1,
            (byte)0xcc, (byte)0xef, (byte)0x72, (byte)0xdb, (byte)0x08, (byte)0x85, (byte)0x05, (byte)0xb4, (byte)0x52, (byte)0x6e, (byte)0x12, (byte)0xf6,
            (byte)0xcd, (byte)0x7a, (byte)0x54, (byte)0x0f, (byte)0x67, (byte)0x4c, (byte)0x07, (byte)0x51, (byte)0xb7, (byte)0xd2, (byte)0x36, (byte)0x70,
            (byte)0xca, (byte)0xd8, (byte)0xe7, (byte)0xd7, (byte)0x95, (byte)0x40, (byte)0x30, (byte)0x43, (byte)0x98, (byte)0x8b, (byte)0x30, (byte)0x68,
            (byte)0x1c, (byte)0x4a, (byte)0x76, (byte)0x35, (byte)0xff, (byte)0x4f, (byte)0x36, (byte)0x1b, (byte)0x03, (byte)0x19, (byte)0xad, (byte)0xf6,
            (byte)0x01, (byte)0xca, (byte)0x49, (byte)0xd9, (byte)0xad, (byte)0x27, (byte)0xf3, (byte)0xda, (byte)0x5b, (byte)0x48, (byte)0xe9, (byte)0x6e,
            (byte)0xca, (byte)0xbf, (byte)0xef, (byte)0x13, (byte)0x36, (byte)0x23, (byte)0x27, (byte)0x60, (byte)0xd9, (byte)0xfd, (byte)0x35, (byte)0x90,
            (byte)0x41, (byte)0xbe, (byte)0xee, (byte)0xa6, (byte)0x2d, (byte)0x06, (byte)0xda, (byte)0x44, (byte)0x57, (byte)0xd7, (byte)0xb5, (byte)0x08,
            (byte)0x67, (byte)0x96, (byte)0x5f, (byte)0x86, (byte)0x39, (byte)0x81, (byte)0x02, (byte)0x03, (byte)0x01, (byte)0x00, (byte)0x01, (byte)0xa3,
            (byte)0x81, (byte)0xcb, (byte)0x30, (byte)0x81, (byte)0xc8, (byte)0x30, (byte)0x1d, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x0e,
            (byte)0x04, (byte)0x16, (byte)0x04, (byte)0x14, (byte)0x6b, (byte)0xbf, (byte)0x1f, (byte)0x86, (byte)0xff, (byte)0x82, (byte)0x7f, (byte)0x11,
            (byte)0xcc, (byte)0xbe, (byte)0xd7, (byte)0x28, (byte)0x70, (byte)0x53, (byte)0xe8, (byte)0xae, (byte)0x01, (byte)0x41, (byte)0xc9, (byte)0x7b,
            (byte)0x30, (byte)0x81, (byte)0x88, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x23, (byte)0x04, (byte)0x81, (byte)0x80, (byte)0x30,
            (byte)0x7e, (byte)0x80, (byte)0x14, (byte)0x6b, (byte)0xbf, (byte)0x1f, (byte)0x86, (byte)0xff, (byte)0x82, (byte)0x7f, (byte)0x11, (byte)0xcc,
            (byte)0xbe, (byte)0xd7, (byte)0x28, (byte)0x70, (byte)0x53, (byte)0xe8, (byte)0xae, (byte)0x01, (byte)0x41, (byte)0xc9, (byte)0x7b, (byte)0xa1,
            (byte)0x5b, (byte)0xa4, (byte)0x59, (byte)0x30, (byte)0x57, (byte)0x31, (byte)0x0b, (byte)0x30, (byte)0x09, (byte)0x06, (byte)0x03, (byte)0x55,
            (byte)0x04, (byte)0x06, (byte)0x13, (byte)0x02, (byte)0x55, (byte)0x53, (byte)0x31, (byte)0x1b, (byte)0x30, (byte)0x19, (byte)0x06, (byte)0x03,
            (byte)0x55, (byte)0x04, (byte)0x0a, (byte)0x13, (byte)0x12, (byte)0x57, (byte)0x57, (byte)0x50, (byte)0x61, (byte)0x73, (byte)0x73, (byte)0x20,
            (byte)0x43, (byte)0x6f, (byte)0x72, (byte)0x70, (byte)0x6f, (byte)0x72, (byte)0x61, (byte)0x74, (byte)0x69, (byte)0x6f, (byte)0x6e, (byte)0x31,
            (byte)0x2b, (byte)0x30, (byte)0x29, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x03, (byte)0x13, (byte)0x22, (byte)0x57, (byte)0x57,
            (byte)0x50, (byte)0x61, (byte)0x73, (byte)0x73, (byte)0x20, (byte)0x43, (byte)0x6f, (byte)0x72, (byte)0x70, (byte)0x6f, (byte)0x72, (byte)0x61,
            (byte)0x74, (byte)0x69, (byte)0x6f, (byte)0x6e, (byte)0x20, (byte)0x50, (byte)0x72, (byte)0x69, (byte)0x6d, (byte)0x61, (byte)0x72, (byte)0x79,
            (byte)0x20, (byte)0x52, (byte)0x6f, (byte)0x6f, (byte)0x74, (byte)0x20, (byte)0x43, (byte)0x41, (byte)0x82, (byte)0x09, (byte)0x00, (byte)0xde,
            (byte)0xc9, (byte)0x65, (byte)0x49, (byte)0x60, (byte)0x94, (byte)0x69, (byte)0xf8, (byte)0x30, (byte)0x0f, (byte)0x06, (byte)0x03, (byte)0x55,
            (byte)0x1d, (byte)0x13, (byte)0x01, (byte)0x01, (byte)0xff, (byte)0x04, (byte)0x05, (byte)0x30, (byte)0x03, (byte)0x01, (byte)0x01, (byte)0xff,
            (byte)0x30, (byte)0x0b, (byte)0x06, (byte)0x03, (byte)0x55, (byte)0x1d, (byte)0x0f, (byte)0x04, (byte)0x04, (byte)0x03, (byte)0x02, (byte)0x01,
            (byte)0x06, (byte)0x30, (byte)0x0d, (byte)0x06, (byte)0x09, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xf7, (byte)0x0d, (byte)0x01,
            (byte)0x01, (byte)0x0b, (byte)0x05, (byte)0x00, (byte)0x03, (byte)0x82, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x13, (byte)0x8e, (byte)0x82,
            (byte)0x32, (byte)0x29, (byte)0x08, (byte)0xef, (byte)0x7e, (byte)0xfc, (byte)0x9a, (byte)0x40, (byte)0xb7, (byte)0xa9, (byte)0x9c, (byte)0x8a,
            (byte)0x71, (byte)0x5c, (byte)0x64, (byte)0x35, (byte)0xf2, (byte)0xd1, (byte)0x7b, (byte)0x77, (byte)0x83, (byte)0xe2, (byte)0x1d, (byte)0x38,
            (byte)0x38, (byte)0xed, (byte)0xbb, (byte)0xae, (byte)0x67, (byte)0xd9, (byte)0x8f, (byte)0xf7, (byte)0x0c, (byte)0xac, (byte)0x30, (byte)0xc2,
            (byte)0xb7, (byte)0x40, (byte)0x67, (byte)0xda, (byte)0xdf, (byte)0x4b, (byte)0x05, (byte)0x41, (byte)0x81, (byte)0x75, (byte)0x77, (byte)0xd9,
            (byte)0x12, (byte)0x7d, (byte)0x77, (byte)0x82, (byte)0xa9, (byte)0xf9, (byte)0xf7, (byte)0xc1, (byte)0x7a, (byte)0x96, (byte)0x62, (byte)0xe8,
            (byte)0x39, (byte)0xbb, (byte)0x4d, (byte)0xe1, (byte)0x06, (byte)0x2a, (byte)0x97, (byte)0x25, (byte)0xeb, (byte)0x15, (byte)0xc3, (byte)0xf3,
            (byte)0x16, (byte)0x2c, (byte)0x10, (byte)0x6a, (byte)0xb6, (byte)0xda, (byte)0xfb, (byte)0x1a, (byte)0xbc, (byte)0xb6, (byte)0x88, (byte)0x31,
            (byte)0x8c, (byte)0xc9, (byte)0x19, (byte)0xdb, (byte)0x2e, (byte)0xf4, (byte)0x32, (byte)0x55, (byte)0x77, (byte)0xfc, (byte)0xf6, (byte)0xe4,
            (byte)0x2a, (byte)0x4c, (byte)0x2f, (byte)0xe1, (byte)0xb0, (byte)0x63, (byte)0x39, (byte)0xc2, (byte)0xd9, (byte)0x43, (byte)0x50, (byte)0xec,
            (byte)0x61, (byte)0xe8, (byte)0x4f, (byte)0x76, (byte)0xca, (byte)0xf9, (byte)0xec, (byte)0x2e, (byte)0x88, (byte)0x77, (byte)0x81, (byte)0x1e,
            (byte)0x90, (byte)0x44, (byte)0x2c, (byte)0xfd, (byte)0xa3, (byte)0x2d, (byte)0x29, (byte)0xc3, (byte)0x33, (byte)0x65, (byte)0xa4, (byte)0xa2,
            (byte)0xa6, (byte)0x44, (byte)0xee, (byte)0x5c, (byte)0x5c, (byte)0x5f, (byte)0xc5, (byte)0x6e, (byte)0x2e, (byte)0x06, (byte)0x27, (byte)0xe4,
            (byte)0x1f, (byte)0xef, (byte)0xad, (byte)0x50, (byte)0x04, (byte)0x83, (byte)0xe3, (byte)0x83, (byte)0x83, (byte)0xda, (byte)0xbe, (byte)0xe6,
            (byte)0xd5, (byte)0x49, (byte)0x52, (byte)0x43, (byte)0x9b, (byte)0xe2, (byte)0x8a, (byte)0xfd, (byte)0xe5, (byte)0xd2, (byte)0xab, (byte)0xc0,
            (byte)0x07, (byte)0xcf, (byte)0x5d, (byte)0x3e, (byte)0x27, (byte)0xd5, (byte)0x9c, (byte)0x87, (byte)0x80, (byte)0xbc, (byte)0xf7, (byte)0x1d,
            (byte)0xef, (byte)0xe1, (byte)0x98, (byte)0xd9, (byte)0x15, (byte)0xd3, (byte)0x64, (byte)0x2c, (byte)0x37, (byte)0xe9, (byte)0x98, (byte)0xa9,
            (byte)0x9c, (byte)0x58, (byte)0x8e, (byte)0x59, (byte)0x3f, (byte)0x53, (byte)0x93, (byte)0x24, (byte)0xc3, (byte)0xa4, (byte)0x1f, (byte)0xf0,
            (byte)0x8d, (byte)0x64, (byte)0x0d, (byte)0x16, (byte)0xb8, (byte)0x26, (byte)0x99, (byte)0x0b, (byte)0xf1, (byte)0x40, (byte)0xb7, (byte)0x96,
            (byte)0x05, (byte)0x62, (byte)0x14, (byte)0x49, (byte)0xa5, (byte)0xc9, (byte)0xc2, (byte)0x55, (byte)0x73, (byte)0x33, (byte)0x3b, (byte)0x5d,
            (byte)0xb5, (byte)0x38, (byte)0x67, (byte)0xb7, (byte)0xf6, (byte)0xcd, (byte)0x64, (byte)0xd1, (byte)0x8f, (byte)0x31, (byte)0x17, (byte)0xda,
            (byte)0x67, (byte)0xbe, (byte)0x8e, (byte)0x96, (byte)0x36, (byte)0x01, (byte)0xf4, (byte)0x12, (byte)0x82, (byte)0xed, (byte)0x65, (byte)0x26,
            (byte)0xb2, (byte)0xcd, (byte)0x9f, (byte)0xf2, (byte)0xda, (byte)0x07, (byte)0x8b, (byte)0x2b, (byte)0x3e, (byte)0x11, (byte)0x11, (byte)0xf3,
            (byte)0xd3, (byte)0x17, (byte)0xc2, (byte)0x4d, (byte)0x58, (byte)0x68, (byte)0xc2, (byte)0x5c, (byte)0xfc, (byte)0x5e, (byte)0xdc, (byte)0x16,
            (byte)0x7d, (byte)0xbd, (byte)0xc0, (byte)0xd7, (byte)0xb8, (byte)0xf3, (byte)0x24, (byte)0x19, (byte)0xbe, (byte)0x28, (byte)0x09, (byte)0x50,
            (byte)0xb0, (byte)0x73, (byte)0xe0, (byte)0x78, (byte)0x11, (byte)0x2a, (byte)0xb6, (byte)0x87, (byte)0x31, (byte)0xbc, (byte)0x12, (byte)0x5c,
            (byte)0xaa, (byte)0x13, (byte)0xa2, (byte)0x28, (byte)0x33, (byte)0xa9, (byte)0xb0, (byte)0xa1, (byte)0xc7, (byte)0xcf, (byte)0xe9, (byte)0xe0,
            (byte)0x7b, (byte)0x12, (byte)0x0e, (byte)0xdd, (byte)0xe9, (byte)0x6b, (byte)0xd5, (byte)0x30, (byte)0x95, (byte)0xba, (byte)0xd3, (byte)0xd3,
            (byte)0x13, (byte)0xe5, (byte)0x1c, (byte)0xcd, (byte)0x84, (byte)0xc1, (byte)0x46, (byte)0xc2, (byte)0xfe, (byte)0x8c, (byte)0x87, (byte)0x68,
            (byte)0x23, (byte)0x19, (byte)0xba, (byte)0x68, (byte)0x0f, (byte)0x6b, (byte)0xac, (byte)0xdd, (byte)0xea, (byte)0x0d, (byte)0x5c, (byte)0x0c,
            (byte)0x9e, (byte)0xe1, (byte)0xd3, (byte)0x85, (byte)0x2a, (byte)0xec, (byte)0x8b, (byte)0x0c, (byte)0xaa, (byte)0x39, (byte)0x70, (byte)0xb3,
            (byte)0xce, (byte)0x30, (byte)0x9a, (byte)0x09, (byte)0xfe, (byte)0x25, (byte)0xe7, (byte)0xe2, (byte)0x86, (byte)0xe5, (byte)0x53, (byte)0x62,
            (byte)0x60, (byte)0xfc, (byte)0xad, (byte)0x88, (byte)0x68, (byte)0x9c, (byte)0xbf, (byte)0xc3, (byte)0xc2, (byte)0x06, (byte)0x3c, (byte)0x05,
            (byte)0x93, (byte)0x32, (byte)0x2b, (byte)0xf8, (byte)0xb4, (byte)0x52, (byte)0xc9, (byte)0x48, (byte)0x98, (byte)0xcc, (byte)0x06, (byte)0x6e,
            (byte)0x8b, (byte)0x24, (byte)0x5c, (byte)0x86, (byte)0x97, (byte)0x53, (byte)0xfb, (byte)0x24, (byte)0x40, (byte)0x7c, (byte)0xbe, (byte)0xea,
            (byte)0xa8, (byte)0x70, (byte)0x6e, (byte)0x20, (byte)0x76, (byte)0x21, (byte)0x1b, (byte)0x71, (byte)0x38, (byte)0xed, (byte)0xad, (byte)0xc6,
            (byte)0x82, (byte)0xec, (byte)0x14, (byte)0xc1, (byte)0x41, (byte)0x9c, (byte)0x5d, (byte)0x1f, (byte)0x8d, (byte)0x8e, (byte)0xb4, (byte)0xa6,
            (byte)0xb5, (byte)0xe1, (byte)0xd1, (byte)0x0c, (byte)0xe3, (byte)0x4e, (byte)0x51, (byte)0x85, (byte)0x02, (byte)0x1f, (byte)0x8d, (byte)0x61,
            (byte)0xc3, (byte)0xad, (byte)0xb8, (byte)0xd0, (byte)0xca, (byte)0x35, (byte)0x94, (byte)0xbe, (byte)0x05, (byte)0xfa, (byte)0xba, (byte)0x6b,
            (byte)0x2c, (byte)0x40, (byte)0x41, (byte)0xf3, (byte)0x89, (byte)0x37, (byte)0xfa, (byte)0xff, (byte)0x80, (byte)0xb5, (byte)0xb5, (byte)0xde,
            (byte)0x3c, (byte)0x4c, (byte)0x2f, (byte)0xa7, (byte)0xea, (byte)0x35, (byte)0x9e, (byte)0xef, (byte)0xfe, (byte)0xd6, (byte)0xc4, (byte)0x64,
            (byte)0x86, (byte)0xa9, (byte)0x4d, (byte)0x14, (byte)0x73, (byte)0x7a, (byte)0xee, (byte)0xf6, (byte)0xa4, (byte)0xa8, (byte)0x2e, (byte)0x31,
            (byte)0x4f, (byte)0x18, (byte)0xae, (byte)0x3f, (byte)0x1b, (byte)0xba, (byte)0x3d, (byte)0xbf, (byte)0xee, (byte)0x0d, (byte)0xe3, (byte)0x48,
            (byte)0x8a, (byte)0x9d, (byte)0x3e, (byte)0x13, (byte)0xd2};


    private static PKCS8EncodedKeySpec readKeyFile(String path) throws IOException {
        FileInputStream stream = new FileInputStream(new File(path));
        try {
            FileChannel fc = stream.getChannel();
            MappedByteBuffer bb = fc.map(FileChannel.MapMode.READ_ONLY, 0, fc.size());
            String pem = Charset.defaultCharset().decode(bb).toString();
            pem = pem.replaceFirst("-----BEGIN (RSA )?PRIVATE KEY-----\r?\n?", "").replace("-----END (RSA )?PRIVATE KEY-----", "");
            Base64 dec1 = new Base64();
            byte [] encoded = dec1.decode(pem);
            return new PKCS8EncodedKeySpec(encoded);
        }
        finally {
            stream.close();
        }
    }

    private static X509Certificate readCertificate(String certFile)
            throws IOException, GeneralSecurityException
    {
        X509Certificate cert = null;
        FileInputStream certInput = new FileInputStream(certFile);
        try {
            cert = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(certInput);
        } finally {
            certInput.close();
        }

        return cert;
    }

    private static InputStream getReplyData(final InputStream rawXMLInput)
            throws IOException, WWPassProtocolException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        Document dom;
        InputStream is = null;

        try {
            DocumentBuilder db = dbf.newDocumentBuilder();

            is = rawXMLInput;

            dom = db.parse(is);

            Element docEle = dom.getDocumentElement();

            Node result = docEle.getElementsByTagName("result").item(0);
            boolean res = result.getTextContent().equalsIgnoreCase("true");

            Element data = (Element)docEle.getElementsByTagName("data").item(0);
            String encoding = data.getAttributes().getNamedItem("encoding").getTextContent();
            String strData;
            byte[] bb;
            if ( "base64".equalsIgnoreCase(encoding) ){
                bb = (new Base64()).decode(data.getTextContent());
                strData = new String(bb, Charset.forName("UTF-8"));
                if (!res) {
                    throw new WWPassProtocolException("SPFE returned error: " + strData);
                }
                return new ByteArrayInputStream(bb);
            }
            else{
                strData = data.getTextContent();
                if (!res) {
                    throw new WWPassProtocolException("SPFE returned error: " + strData);
                }
                return new ByteArrayInputStream(strData.getBytes());
            }

        } catch(ParserConfigurationException pce) {
            throw new WWPassProtocolException("Malformed SPFE reply: " + pce.getMessage());
        } catch(SAXException se) {
            throw new WWPassProtocolException("Malformed SPFE reply: " + se.getMessage());
        } finally {
            if (is != null) {
                is.close();
            }
        }
    }

    // Uncomment the code below and comment out method getReplyData(..) above to use JSON instead of XML 
    // (don't forget to change commandUrl in method makeRequest(..).
    
    /*private class WWPassData {
    	private String encoding;
    	private String result;
    	private String data;
    	
    	public String getEncoding() { return encoding; }
    	public String getResult() { return result; }
    	public String getData() { return data; }
    	
    	public void setEncoding(String e) { encoding = e; }
    	public void setResult(String r) { result = r; }
    	public void setData(String d) { data = d; }
    }
	private static String getReplyData(InputStream rawXMLInput)	throws IOException, WWPassProtocolException, IOException{
		ObjectMapper mapper = new ObjectMapper();
		// read JSON from InputStream, convert it to WWPassData class
		WWPassData data = mapper.readValue(new InputStreamReader(rawXMLInput),
				WWPassData.class);

		String str_data = data.getData();
		String result = data.getResult();
		String encoding = data.getEncoding();
		// Convert result string to boolean
		Boolean res = result.equalsIgnoreCase("true"); 

		byte[] bb = null;
		if ("base64".equalsIgnoreCase(encoding)) {
			bb = (new Base64()).decode(str_data);
			// Decode data string, if encoding is Base64
			str_data = new String(bb, Charset.forName("UTF-8"));
		}
		if (!res) {
			throw new WWPassProtocolException("SPFE returned error: " + str_data);
		}

		return str_data;
	}*/

    private static final String DEFAULT_SPFE_ADDRESS = "spfe.wwpass.com";
    private static final int DEFAULT_TIMEOUT_SEC = 10;

    private SSLContext SPFEContext;
    private final int timeoutMs;
    private final String SpfeURL;

    public WWPassConnection(X509Certificate cert, PKCS8EncodedKeySpec key, int timeoutSec, String spfeAddr)
            throws IOException, GeneralSecurityException
    {
        timeoutMs = timeoutSec*1000;
        SpfeURL = "https://"+spfeAddr+"/";
        // Setting up client certificate and key

        X509Certificate[] chain = {cert};

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privKey = kf.generatePrivate(key);

        KeyStore.PrivateKeyEntry pke = new KeyStore.PrivateKeyEntry(privKey,chain);

        //This adds no security but Java requires to password-protect the key
        byte[] password_bytes = new byte[16];
        (new java.security.SecureRandom()).nextBytes(password_bytes);
        // String password = (new BASE64Encoder()).encode(password_bytes);
        String password = (new Base64()).encodeToString(password_bytes);

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null);

        keyStore.setEntry("WWPass client key", pke, new KeyStore.PasswordProtection(password.toCharArray()) );
        keyManagerFactory.init(keyStore, password.toCharArray());

        SPFEContext = SSLContext.getInstance("TLS");

        // Making rootCA certificate
        InputStream is = null;
        CertificateFactory cf;
        X509Certificate rootCA = null;
        try {
            is = new ByteArrayInputStream(WWPassCA_DER);
            cf = CertificateFactory.getInstance("X.509");
            rootCA = (X509Certificate) cf.generateCertificate(is);
        } finally {
            if (is != null) {
                is.close();
            }
        }

        //Creating TrustManager for this CA
        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null);
        ks.setCertificateEntry("WWPass Root CA", rootCA);

        trustManagerFactory.init(ks);

        SPFEContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new java.security.SecureRandom());
    }

    public WWPassConnection(X509Certificate cert, PKCS8EncodedKeySpec key, String spfeAddr)
            throws IOException, GeneralSecurityException
    {
        this(cert,key,DEFAULT_TIMEOUT_SEC,spfeAddr);
    }

    public WWPassConnection(X509Certificate cert, PKCS8EncodedKeySpec key, int timeoutSec)
            throws IOException, GeneralSecurityException
    {
        this(cert,key,timeoutSec,DEFAULT_SPFE_ADDRESS);
    }

    public WWPassConnection(X509Certificate cert, PKCS8EncodedKeySpec key)
            throws IOException, GeneralSecurityException
    {
        this(cert,key,DEFAULT_TIMEOUT_SEC,DEFAULT_SPFE_ADDRESS);
    }

    public WWPassConnection(String certFile, String keyFile, int timeoutSec, String spfeAddr)
            throws IOException, GeneralSecurityException
    {
        this(readCertificate(certFile),readKeyFile(keyFile), timeoutSec, spfeAddr);
    }

    public WWPassConnection(String certFile, String keyFile, String spfeAddr)
            throws IOException, GeneralSecurityException
    {
        this(readCertificate(certFile),readKeyFile(keyFile), DEFAULT_TIMEOUT_SEC, spfeAddr);
    }

    public WWPassConnection(String certFile, String keyFile, int timeoutSec)
            throws IOException, GeneralSecurityException
    {
        this(readCertificate(certFile),readKeyFile(keyFile), timeoutSec, DEFAULT_SPFE_ADDRESS);
    }

    public WWPassConnection(String certFile, String keyFile)
            throws IOException, GeneralSecurityException
    {
        this(readCertificate(certFile),readKeyFile(keyFile), DEFAULT_TIMEOUT_SEC, DEFAULT_SPFE_ADDRESS);
    }

    private InputStream makeRequest(String method, String command, Map<String, ?> parameters)
            throws IOException, WWPassProtocolException
    {
        String commandUrl = SpfeURL + command + ".xml";
        //String command_url = SpfeURL + command + ".json";

        StringBuilder sb = new StringBuilder();
        URLCodec codec = new URLCodec();

        @SuppressWarnings("unchecked")
        Map<String, Object> localParams = (Map<String, Object>) parameters;

        for (Map.Entry<String, Object> entry : localParams.entrySet()) {
            sb.append(URLEncoder.encode(entry.getKey(),"UTF-8"));
            sb.append("=");
            if (entry.getValue() instanceof String) {
                sb.append(URLEncoder.encode((String) entry.getValue(),"UTF-8"));
            } else {
                sb.append(new String(codec.encode((byte[]) entry.getValue())));
            }
            sb.append("&");
        }
        String paramsString = sb.toString();
        sb = null;
        if ("GET".equalsIgnoreCase(method)) {
            commandUrl += "?" + paramsString;
        } else if ("POST".equalsIgnoreCase(method)) {

        } else {
            throw new IllegalArgumentException("Method " + method + " not supported.");
        }

        HttpsURLConnection conn = null;
        try {
            URL url = new URL(commandUrl);
            conn = (HttpsURLConnection)url.openConnection();
            conn.setReadTimeout(timeoutMs);
            conn.setSSLSocketFactory(SPFEContext.getSocketFactory());
            if ("POST".equalsIgnoreCase(method)) {
                conn.setDoOutput(true);
                OutputStreamWriter writer = new OutputStreamWriter(conn.getOutputStream());
                writer.write(paramsString);
                writer.flush();
            }
            InputStream in = conn.getInputStream();
            return getReplyData(in);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Command-parameters combination is invalid: "+e.getMessage());
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }


// API

    // Functions to work with user containers

    /**
     * <p>Gets an id of the user from the Service Provider Front End. This ID is unique for one 
     * Service Provider, and different for different Service Providers.</p>
     *
     * @param ticket Ticket issued by the SPFE
     * @param auth_type Defines which credentials should have been asked of the user to authenticate 
     * this ticket. Currently, only two values are supported: 'p' for a PassKey and access code, 
     * '' (empty string) for a PassKey only (default).
     * @return PUID issued by the SPFE
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String getPUID(String ticket, String auth_type)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("auth_type", auth_type);

        Scanner scanner = new Scanner(makeRequest("GET", "puid", parameters));
        StringBuilder sb = new StringBuilder();

        while(scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();
        return sb.toString();

    }

    /**
     * <p>Gets an id of the user from the Service Provider Front End. This ID is unique for one
     * Service Provider, and different for different Service Providers.</p>
     *
     * @param ticket Ticket issued by the SPFE
     *
     * @return PUID issued by the SPFE
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String getPUID(String ticket)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);

        Scanner scanner = new Scanner(makeRequest("GET", "puid", parameters));
        StringBuilder sb = new StringBuilder();

        while(scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();
        return sb.toString();
    }

    /**
     * <p>Calls to this function acquire a newly issued ticket from SPFE.</p>
     *
     * @param auth_type Defines which credentials will be asked of the user to authorize this ticket. 
     * Currently only two values supported: 'p': to ask for PassKey and password; empty string to ask 
     * for PassKey only (default).
     * @param ttl The period in seconds for the ticket to remain valid since issuance. The default 
     * value is 120 seconds.
     * @return Ticket issued by the SPFE
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String getTicket(String auth_type, int ttl)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("auth_type", auth_type);
        parameters.put("ttl", Integer.toString(ttl));

        Scanner scanner = new Scanner(makeRequest("GET", "get", parameters));
        StringBuilder sb = new StringBuilder();

        while(scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();

        return sb.toString();
    }

    /**
     * <p>Calls to this function acquire a newly issued ticket from SPFE.</p>
     *
     * @param auth_type Defines which credentials will be asked of the user to authorize this ticket. 
     * Currently only two values supported: 'p': to ask for PassKey and password; empty string to ask 
     * for PassKey only (default).
     * @return Ticket issued by the SPFE
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String getTicket(String auth_type)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("auth_type", auth_type);

        Scanner scanner = new Scanner(makeRequest("GET", "get", parameters));
        StringBuilder sb = new StringBuilder();

        while(scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();

        return sb.toString();
    }

    /**
     * <p>Calls to this function acquire a newly issued ticket from SPFE.</p>
     *
     * @param ttl The period in seconds for the ticket to remain valid since issuance. 
     * The default value is 120 seconds.
     * @return Ticket issued by the SPFE
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String getTicket(int ttl)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ttl", Integer.toString(ttl));

        Scanner scanner = new Scanner(makeRequest("GET", "get", parameters));
        StringBuilder sb = new StringBuilder();

        while(scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();

        return sb.toString();
    }

    /**
     * <p>Calls to this function acquire a newly issued ticket from SPFE.</p>
     *
     * @return Ticket issued by the SPFE
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String getTicket()
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();

        Scanner scanner = new Scanner(makeRequest("GET", "get", parameters));
        StringBuilder sb = new StringBuilder();

        while(scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();

        return sb.toString();
    }

    /**
     * <p>Call this method to get name of the Service Provider, on which the certificate was used
     * for initiate this WWPassConnection instance</p>
     *
     * @return Service Provider's name
     * @throws WWPassProtocolException
     * @throws IOException
     */
    public String getName()
            throws IOException, WWPassProtocolException
    {
        String ticket = getTicket(0);
        int colon = ticket.indexOf(':');
        if (colon == -1) {
            throw new WWPassProtocolException("SPFE returned ticket without a colon.");
        }
        return ticket.substring(0, colon);
    }

    /**
     * <p>Calls to this function check the authentication of the ticket.</p>
     *
     * @param ticket The ticket to validate.
     * @param auth_type Defines which credentials will be asked of the user to authorize this ticket. 
     * Currently only two values supported: 'p': to ask for PassKey and password; empty string to ask 
     * for PassKey only (default).
     * @param ttl The period in seconds for the ticket to remain valid since issuance. The default 
     * value is 120 seconds.
     * @return Returns current ticket or newly issued ticket. The new ticket should be used in future 
     * operations with the SPFE.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String putTicket(String ticket, String auth_type, int ttl)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("auth_type", auth_type);
        parameters.put("ttl", Integer.toString(ttl));

        Scanner scanner = new Scanner(makeRequest("GET", "put", parameters));
        StringBuilder sb = new StringBuilder();

        while (scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();
        return sb.toString();
    }
    /**
     * <p>Calls to this function check the authentication of the ticket.</p>
     *
     * @param ticket The ticket to validate.
     * @param auth_type Defines which credentials will be asked of the user to authorize this ticket. 
     * Currently only two values supported: 'p': to ask for PassKey and password; empty string to ask 
     * for PassKey only (default).
     * @return Returns current ticket or newly issued ticket. The new ticket should be used in future 
     * operations with the SPFE.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String putTicket(String ticket, String auth_type)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("auth_type", auth_type);

        Scanner scanner = new Scanner(makeRequest("GET", "put", parameters));
        StringBuilder sb = new StringBuilder();

        while (scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();
        return sb.toString();
    }
    /**
     * <p>Calls to this function check the authentication of the ticket.</p>
     *
     * @param ticket The ticket to validate.
     * @param ttl The period in seconds for the ticket to remain valid since issuance. The default 
     * value is 120 seconds.
     * @return Returns current ticket or newly issued ticket. The new ticket should be used in future 
     * operations with the SPFE.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String putTicket(String ticket, int ttl)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("ttl", Integer.toString(ttl));

        Scanner scanner = new Scanner(makeRequest("GET", "put", parameters));
        StringBuilder sb = new StringBuilder();

        while (scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();
        return sb.toString();
    }
    /**
     * <p>Calls to this function check the authentication of the ticket.</p>
     *
     * @param ticket The ticket to validate.
     * @return Returns current ticket or newly issued ticket. The new ticket should be used in future 
     * operations with the SPFE.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String putTicket(String ticket)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);

        Scanner scanner = new Scanner(makeRequest("GET", "put", parameters));
        StringBuilder sb = new StringBuilder();

        while (scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();
        return sb.toString();
    }

    /**
     * <p>Calls to this function request data stored in the user's data container.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param container Arbitrary string (only the first 32 bytes matter) that identifies the user's 
     * data container.
     * @return Returns the data stored in the user's data container. Returns "None" character sequence if the data
     * container does not exist.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public InputStream readData(String ticket, String container)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("container", container);
        return makeRequest("GET", "read", parameters);
    }
    /**
     * <p>Calls to this function request String data stored in the user's data container.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param container Arbitrary string (only the first 32 bytes matter) that identifies the user's data container.
     * @return Returns the data stored in the user's data container. Returns "None" character sequence if the data
     * container does not exist.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String readDataAsString(String ticket, String container)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("container", container);

        Scanner scanner = new Scanner(makeRequest("GET", "read", parameters));
        StringBuilder sb = new StringBuilder();

        while (scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();

        return sb.toString();
    }
    /**
     * <p>Calls to this function request binary data stored in the user's data container.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @return Returns the data stored in the user's data container. Returns "None".getBytes() if the data container
     * does not exist.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public InputStream readData(String ticket)
            throws IOException, WWPassProtocolException {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);

        return makeRequest("GET", "read", parameters);
        /*if (response instanceof String) {
        	return (String) response;
        } else {
        	return new String((byte[]) response, Charset.forName("UTF-8"));
        }*/
    }
    /**
     * <p>Calls to this function request string data stored in the user's data container.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @return Returns the data stored in the user's data container. Returns "None" character sequence if the data
     * container does not exist.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String readDataAsString(String ticket)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);

        Scanner scanner = new Scanner(makeRequest("GET", "read", parameters));
        StringBuilder sb = new StringBuilder();

        while (scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();

        return sb.toString();
    }
    /**
     * <p>Calls to this function request data stored in the user's data container and lock it.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param container Arbitrary string (only the first 32 bytes matter) that identifies the user's data container.
     * @param lockTimeout The period in seconds for the data container to remain protected from the new data being
     * accessed.
     * @return Returns the data stored in the user's data container. Returns "None" character sequence if the data
     * container does not exist.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public InputStream readDataAndLock(String ticket, String container, int lockTimeout)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("container", container);
        parameters.put("to", Integer.toString(lockTimeout));
        parameters.put("lock", "1");
        return makeRequest("GET", "read", parameters);
    }
    /**
     * <p>Calls to this function request string data stored in the user's data container and lock it.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param container Arbitrary string (only the first 32 bytes matter) that identifies the user's data container.
     * @param lockTimeout The period in seconds for the data container to remain protected from the new data being
     * accessed.
     * @return Returns the data stored in the user's data container, represented as String. Returns "None" character
     * sequence if the data container does not exist.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String readDataAsStringAndLock(String ticket, String container, int lockTimeout)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("container", container);
        parameters.put("to", Integer.toString(lockTimeout));
        parameters.put("lock", "1");

        Scanner scanner = new Scanner(makeRequest("GET", "read", parameters));
        StringBuilder sb = new StringBuilder();

        while (scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();

        return sb.toString();
    }
    /**
     * <p>Calls to this function request data stored in the user's data container and lock it.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param lockTimeout The period in seconds for the data container to remain protected from the new data being
     * accessed.
     * @return Returns the data stored in the user's data container. Returns "None" character sequence if the data
     * container does not exist.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public InputStream readDataAndLock(String ticket, int lockTimeout)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("to", Integer.toString(lockTimeout));
        parameters.put("lock", "1");
        return makeRequest("GET", "read", parameters);
    }
    /**
     * <p>Calls to this function request string data stored in the user's data container and lock it.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param lockTimeout The period in seconds for the data container to remain protected from the new data being
     * accessed.
     * @return Returns the data stored in the user's data container, represented as String. Returns "None" character sequence if the data
     * container does not exist.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String readDataAsStringAndLock(String ticket, int lockTimeout)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("to", Integer.toString(lockTimeout));
        parameters.put("lock", "1");

        Scanner scanner = new Scanner(makeRequest("GET", "read", parameters));
        StringBuilder sb = new StringBuilder();

        while (scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();

        return sb.toString();
    }
    /**
     * <p>Calls to this function write data into the user's data container.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param data The string to write into the container.
     * @param container Arbitrary string (only the first 32 bytes matter) that identifies the user's data container.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void writeData(String ticket, String data, String container)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("data", data);
        parameters.put("container", container);
        makeRequest("POST", "write", parameters);
    }
    /**
     * <p>Calls to this function write data into the user's data container.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param data The byte array to write into the container.
     * @param container Arbitrary string (only the first 32 bytes matter) that identifies the user's data container.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void writeData(String ticket, byte[] data, String container)
            throws IOException, WWPassProtocolException
    {
        HashMap<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("ticket", ticket);
        parameters.put("data", data);
        parameters.put("container", container);
        makeRequest("POST", "write", parameters);
    }
    /**
     * <p>Calls to this function write data into the user's data container.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param data The string to write into the container.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void writeData(String ticket, String data)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("data", data);
        makeRequest("POST", "write", parameters);
    }
    /**
     * <p>Calls to this function write data into the user's data container.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param data The string to write into the container.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void writeData(String ticket, byte[] data)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,Object> parameters = new HashMap<String,Object>();
        parameters.put("ticket", ticket);
        parameters.put("data", data);
        makeRequest("POST", "write", parameters);
    }
    /**
     * <p>Calls to this function write the data into the user's Data Container and unlock 
     * an associated lock. If the lock is already unlocked, the write will succeed, but the 
     * function will return an appropriate error.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param data The string to write into the container.
     * @param container Arbitrary string (only the first 32 bytes matter) that identifies the user's data container.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void writeDataAndUnlock(String ticket, String data, String container)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("data", data);
        parameters.put("container", container);
        parameters.put("unlock", "1");
        makeRequest("POST", "write", parameters);
    }
    /**
     * <p>Calls to this function write the data into the user's Data Container and unlock 
     * an associated lock. If the lock is already unlocked, the write will succeed, but the 
     * function will return an appropriate error.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param data The byte array to write into the container.
     * @param container Arbitrary string (only the first 32 bytes matter) that identifies the user's data container.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void writeDataAndUnlock(String ticket, byte[] data, String container)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,Object> parameters = new HashMap<String,Object>();
        parameters.put("ticket", ticket);
        parameters.put("data", data);
        parameters.put("container", container);
        parameters.put("unlock", "1");
        makeRequest("POST", "write", parameters);
    }
    /**
     * <p>Calls to this function write the data into the user's Data Container and unlock 
     * an associated lock. If the lock is already unlocked, the write will succeed, but the 
     * function will return an appropriate error.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param data The string to write into the container.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void writeDataAndUnlock(String ticket, String data)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("data", data);
        parameters.put("unlock", "1");
        makeRequest("POST", "write", parameters);
    }
    /**
     * <p>Calls to this function write the data into the user's Data Container and unlock 
     * an associated lock. If the lock is already unlocked, the write will succeed, but the 
     * function will return an appropriate error.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param data The string to write into the container.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void writeDataAndUnlock(String ticket, byte[] data)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,Object> parameters = new HashMap<String,Object>();
        parameters.put("ticket", ticket);
        parameters.put("data", data);
        parameters.put("unlock", "1");
        makeRequest("POST", "write", parameters);
    }
    /**
     * <p>Calls to this function lock the user's data container it.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param lockTimeout The period in seconds for the data container to remain protected 
     * from the new data being accessed.
     * @param lockid The arbitrary string (only the first 32 bytes matter) that identifies 
     * the lock.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void lock(String ticket, int lockTimeout, String lockid)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("to", Integer.toString(lockTimeout));
        parameters.put("lockid", lockid);
        makeRequest("GET", "lock", parameters);
    }
    /**
     * <p>Calls to this function lock the user's data container it.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param lockTimeout The period in seconds for the data container to remain protected 
     * from the new data being accessed.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void lock(String ticket, int lockTimeout)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("to", Integer.toString(lockTimeout));
        makeRequest("GET", "lock", parameters);
    }

    /**
     * <p>Calls to this function unlock the user's data container.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @param lockid The arbitrary string (only the first 32 bytes matter) that identifies 
     * the lock.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void unlock(String ticket, String lockid)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        parameters.put("lockid", lockid);
        makeRequest("GET", "unlock", parameters);
    }
    /**
     * <p>Calls to this function unlock the user's data container.</p>
     *
     * @param ticket The authenticated ticket issued by the SPFE.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void unlock(String ticket)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("ticket", ticket);
        makeRequest("GET", "unlock", parameters);
    }

    // Functions to work with SP-only containers

    /**
     * <p>Calls to this function create a new Service Provider's Data Container and write 
     * data into it.</p>
     *
     * @param data The string to write into the Data Container.
     * @return Returns the data container identifier of the newly created Data Container.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public byte[] createPFID(String data)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();
        parameters.put("data", data);

        BufferedInputStream bis = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            bis = new BufferedInputStream(makeRequest("POST", "sp/create", parameters));

            byte[] buffer = new byte[8192];
            int bytesRead;

            while ((bytesRead = bis.read(buffer)) != -1)
            {
                baos.write(buffer, 0, bytesRead);
            }
            return baos.toByteArray();
        } finally {
            if (bis != null) {
                bis.close();
            }
            baos.close();
        }
    }
    /**
     * <p>Calls to this function create a new Service Provider's Data Container.</p>
     *
     * @return Returns the data container identifier of the newly created Data Container.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public byte[] createPFID()
            throws IOException, WWPassProtocolException
    {
        HashMap<String,String> parameters = new HashMap<String,String>();

        BufferedInputStream bis = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            bis = new BufferedInputStream(makeRequest("POST", "sp/create", parameters));

            byte[] buffer = new byte[8192];
            int bytesRead;

            while ((bytesRead = bis.read(buffer)) != -1)
            {
                baos.write(buffer, 0, bytesRead);
            }
            return baos.toByteArray();
        } finally {
            if (bis != null) {
                bis.close();
            }
            baos.close();
        }
    }

    /**
     * <p>Destroys the Service Provider's Data Container. The container will then be 
     * nonexistent as if it was never created.</p>
     *
     * @param pfid The Data Container Identifier as returned by createPFID.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void removePFID(byte[] pfid)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,Object> parameters = new HashMap<String,Object>();
        parameters.put("pfid", pfid);
        makeRequest("GET", "sp/remove", parameters);
    }

    /**
     * <p>Calls to this function request data stored in the Service Provider data container.</p>
     *
     * @param pfid The data container identifier as returned by createPFID.
     * @return Returns the data stored in the Service Provider data container. Returns "None" character sequence if
     * the data container does not exist.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public InputStream readDataSP(byte[] pfid)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,Object> parameters = new HashMap<String,Object>();
        parameters.put("pfid", pfid);
        return makeRequest("GET", "sp/read", parameters);
    }
    /**
     * <p>Calls to this function request string data stored in the Service 
     * Provider data container.</p>
     *
     * @param pfid The data container identifier as returned by createPFID.
     * @return Returns the data stored in the Service Provider data container, represented as String. Returns "None"
     * character sequence if the data container does not exist.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String readDataSPasString(byte[] pfid)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,Object> parameters = new HashMap<String,Object>();
        parameters.put("pfid", pfid);

        Scanner scanner = new Scanner(makeRequest("GET", "sp/read", parameters));
        StringBuilder sb = new StringBuilder();

        while (scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();

        return sb.toString();
    }
    /**
     * <p>Calls to this function request the data stored in the Service Provider's Data Container 
     * and try to atomically lock an associated lock.</p>
     *
     * @param pfid The data container identifier as returned by createPFID.
     * @param lockTimeout The period in seconds for the data container to remain protected from 
     * the new data being accessed.
     * @return Returns the data stored in the Service Provider data container. Returns "False" character sequence if
     * the data container does not exist.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public InputStream readDataSPandLock(byte[] pfid, int lockTimeout)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,Object> parameters = new HashMap<String,Object>();
        parameters.put("pfid", pfid);
        parameters.put("to", Integer.toString(lockTimeout));
        parameters.put("lock", "1");
        return makeRequest("GET", "sp/read", parameters);
    }
    /**
     * <p>Calls to this function request the string data stored in the Service 
     * Provider's Data Container and try to atomically lock an associated lock.</p>
     *
     * @param pfid The data container identifier as returned by createPFID.
     * @param lockTimeout The period in seconds for the data container to remain protected from 
     * the new data being accessed.
     * @return Returns the data stored in the Service Provider data container. Returns "False" character sequence if
     * the data container does not exist.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public String readDataSPasStringAndLock(byte[] pfid, int lockTimeout)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,Object> parameters = new HashMap<String,Object>();
        parameters.put("pfid", pfid);
        parameters.put("to", Integer.toString(lockTimeout));
        parameters.put("lock", "1");

        Scanner scanner = new Scanner(makeRequest("GET", "sp/read", parameters));
        StringBuilder sb = new StringBuilder();

        while (scanner.hasNextLine()) {
            sb.append(scanner.nextLine());
        }
        scanner.close();

        return sb.toString();
    }
    /**
     * <p>Writes the data into the Service Provider's Data Container.</p>
     *
     * @param pfid The Data Container Identifier as returned by createPFID.
     * @param data The string to write into the container.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void writeDataSP(byte[] pfid, String data)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,Object> parameters = new HashMap<String,Object>();
        parameters.put("pfid", pfid);
        parameters.put("data", data);
        makeRequest("POST", "sp/write", parameters);
    }
    /**
     * <p>Writes the data into the Service Provider's Data Container.</p>
     *
     * @param pfid The Data Container Identifier as returned by createPFID.
     * @param data The binary data to write into the container.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void writeDataSP(byte[] pfid, byte[] data)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,Object> parameters = new HashMap<String,Object>();
        parameters.put("pfid", pfid);
        parameters.put("data", data);
        makeRequest("POST", "sp/write", parameters);
    }
    /**
     * <p>Writes the data into the Service Provider's Data Container and unlocks an associated lock. 
     * If the lock is already unlocked, the write will succeed, but the function will return an appropriate error.</p>
     *
     * @param data The string to write into the container.
     * @param pfid The data container identifier as returned by createPFID.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void writeDataSPandUnlock(byte[] pfid, String data)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,Object> parameters = new HashMap<String,Object>();
        parameters.put("pfid", pfid);
        parameters.put("data", data);
        parameters.put("unlock", "1");
        makeRequest("POST", "sp/write", parameters);
    }
    /**
     * <p>Writes the data into the Service Provider's Data Container and unlocks an associated lock. 
     * If the lock is already unlocked, the write will succeed, but the function will return an appropriate error.</p>
     *
     * @param data The binary data to write into the container.
     * @param pfid The data container identifier as returned by createPFID.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void writeDataSPandUnlock(byte[] pfid, byte[] data)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,Object> parameters = new HashMap<String,Object>();
        parameters.put("pfid", pfid);
        parameters.put("data", data);
        parameters.put("unlock", "1");
        makeRequest("POST", "sp/write", parameters);
    }
    /**
     * <p>Calls to this function lock the user's data container it.</p>
     *
     * @param lockTimeout The period in seconds for the data container to remain protected from 
     * the new data being accessed.
     * @param lockid The arbitrary string (only the first 32 bytes matter) that identifies the lock.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void lockSP(byte[] lockid, int lockTimeout)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,Object> parameters = new HashMap<String,Object>();
        parameters.put("to", Integer.toString(lockTimeout));
        parameters.put("lockid", lockid);
        makeRequest("GET", "sp/lock", parameters);
    }

    /**
     * <p>Calls to this function unlock the user's data container.</p>
     *
     * @param lockid The arbitrary string (only the first 32 bytes matter) that identifies the lock.
     * @throws IOException
     * @throws WWPassProtocolException
     */
    public void unlockSP(byte[] lockid)
            throws IOException, WWPassProtocolException
    {
        HashMap<String,Object> parameters = new HashMap<String,Object>();
        parameters.put("lockid", lockid);
        makeRequest("GET", "sp/unlock", parameters);
    }


}

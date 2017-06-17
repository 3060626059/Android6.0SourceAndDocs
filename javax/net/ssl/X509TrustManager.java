/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package javax.net.ssl;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**X509证书的信任管理器，用来对安全套接字实施认证
 * The trust manager for X509 certificates to be used to perform authentication
 * for secure sockets.
 */
public interface X509TrustManager extends TrustManager {

    /**检测指定的证书链是否可以被验证，是否可以被指定类型的客户端认证信任，
     * 检查指定的证书链（部分或完整）是否可以
           *被验证并被信任用于指定的客户端身份验证类型。
     * Checks whether the specified certificate chain (partial or complete) can
     * be validated and is trusted for client authentication for the specified
     * authentication type.
     *
     * @param chain
     *            the certificate chain to validate.
     * @param authType
     *            the authentication type used.
     * @throws CertificateException
     *             if the certificate chain can't be validated or isn't trusted.
     * @throws IllegalArgumentException
     *             if the specified certificate chain is empty or {@code null},
     *             or if the specified authentication type is {@code null} or an
     *             empty string.
     */
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException;


    /**检查指定的证书链（部分或完整）是否可以
           *被验证并被信任用于指定的服务器认证
           *密钥交换算法
     * Checks whether the specified certificate chain (partial or complete) can
     * be validated and is trusted for server authentication for the specified
     * key exchange algorithm.
     *
     * @param chain
     *            the certificate chain to validate.
     * @param authType
     *            the key exchange algorithm name.
     * @throws CertificateException
     *             if the certificate chain can't be validated or isn't trusted.
     * @throws IllegalArgumentException
     *             if the specified certificate chain is empty or {@code null},
     *             or if the specified authentication type is {@code null} or an
     *             empty string.
     */
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException;

    /**返回对端信任的证书颁发机构列表
     * Returns the list of certificate issuer authorities which are trusted for
     * authentication of peers.
     *
     * @return the list of certificate issuer authorities which are trusted for
     *         authentication of peers.
     */
    public X509Certificate[] getAcceptedIssuers();
}

/* Copyright 2019 OSU OPEnS Lab
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * SSLClientParameters.h
 * 
 * This file contains a simple utility class to store parameters about an SSL Session
 * for reuse later.
 */

#include "bearssl.h"
#undef min
#undef max
#include <vector>

#ifndef SSLClientParameters_H_
#define SSLClientParameters_H_

/**
 * \brief This class stores data required for SSLClient to use mutual authentication.
 * 
 * TLS mutual authentication is a process in which both the server and client
 * perform cryptographic operations to verify the authenticity of eachother, for more
 * information check out this article: https://medium.com/sitewards/the-magic-of-tls-x509-and-mutual-authentication-explained-b2162dec4401 .
 * If this struct is provided to SSLClient::SSLClient, SSLClient will automatically
 * send a client certificate if one is requested by the server. This will happen for all
 * SSLClient connections, and may cause issues for websites that do not need mutual authentication---
 * as a result, please only turn on mutual authentication if you are sure it is neccesary.
 * 
 * At the moment SSLClient only supports mutual authentication using ECC client certificates.
 */

class SSLClientParameters {
public:

    /*
    static SSLClientParameters fromECCPEM(const char* cert_pem, const char* key_pem);
    static SSLClientParameters fromECCDER(const char* cert_der, const char* key_der);
    static SSLClientParameters fromRSAPEM(const char* cert_pem, const char* key_pem);
    static SSLClientParameters fromRSADER(const char* cert_der, const char* key_der);
    */

    const br_x509_certificate* getCertChain() const { return &m_cert_struct; }
    int getCertType() const { return br_skey_decoder_key_type(&m_key); }
    const br_ec_private_key* getECKey() const { return br_skey_decoder_get_ec(&m_key); }
    const br_rsa_private_key* getRSAKey() const { return br_skey_decoder_get_rsa(&m_key); }

// protected:
    SSLClientParameters(const char* cert, const size_t cert_len, const char* key, const size_t key_len, bool is_der = false);

private:
    const std::vector<char> m_cert;
    const br_x509_certificate m_cert_struct;
    const br_skey_decoder_context m_key;
};

#endif
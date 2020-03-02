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
 * @brief This class stores data required for SSLClient to use mutual authentication.
 * 
 * TLS mutual authentication is a process in which both the server and client
 * perform cryptographic operations to verify the authenticity of eachother, for more
 * information check out this article: https://medium.com/sitewards/the-magic-of-tls-x509-and-mutual-authentication-explained-b2162dec4401 .
 * If this struct is provided to SSLClient::SSLClient via SSLClient::setMutualAuthParams,
 * SSLClient will automatically send a client certificate if one is requested by the server. 
 * This will happen for all SSLClient connections, and may cause issues for websites that 
 * do not need mutual authentication---as a result, please only turn on mutual 
 * authentication if you are sure it is neccesary.
 * 
 * SSLClientParameters supports both ECC and RSA client certificates. I recommend using
 * ECC certificates if possible, as SSLClientParameters will make a copy of both the
 * certificate and the private key in memory, and ECC keys tend to be smaller than RSA ones.
 */
class SSLClientParameters {
public:
    /**
     * @brief Create mutual authentication parameters from a PEM certificate and private key
     * 
     * Use this function to create a mutual tls context from a PEM client certificate and PEM
     * private key. This function will convert the PEM certificates into DER format (creating
     * a copy in the process), extract the needed information from the private key, and store
     * that information into a SSLClientParameters object. Given the certifiate and key parsed
     * correctly, you can then use SSLClient::setMutualAuthParams at the begining of your sketch
     * to enable mTLS with SSLClient. This function supports both ECC and RSA certificate/private
     * keys (use EC keys wherever possible, as they are signifigantly smaller and faster), however
     * SSLClient only supports the p256, p384, and p512 curves for ECC.
     * 
     * Because SSLClientParameters creates a copy of both the certificate and key, you do not
     * need to ensure that the data pointed to by cert_pem or key_pem is accessible after
     * this function (i.e. you can free them afterwards).
     * 
     * Please note that if the certificate or private key are incorrect, this function will not
     * report an error, and instead SSLClient will fall back to regular TLS when making a 
     * connection.
     * 
     * @param cert_pem A PEM formatted certificate, including the "BEGIN" and "END" header/footers.
     * Can be ECC or RSA. cert_pem supports both LF and CRLF for endlines, but all other constraints 
     * on a valid PEM file apply.
     * @param cert_len The number of bytes in cert_pem.
     * @param key_pem A PEM formatted private key, including the "BEGIN" and "END" header/footers.
     * Can be ECC or RSA. key_pem supports both LF and CRLF for endlines, but all other constraints \
     * on a valid PEM file apply.
     * @param key_len The number of bytes in key_pem
     * @return An SSLClientParameters context, to be used with SSLClient::setMutualAuthParams.
     */
    static SSLClientParameters fromPEM(const char* cert_pem, const size_t cert_len, const char* key_pem, const size_t key_len);

    /**
     * @brief Create mutual authentication parameters from a DER certificate and private key
     * 
     * Use this function to create a mutual tls context from a DER client certificate and DER
     * private key. This function will copy the certificate and private key, extract the needed 
     * information from the private key, and store both that information and the copied cert
     * into a SSLClientParameters object. Given the key parsed correctly, you can then use 
     * SSLClient::setMutualAuthParams at the begining of your sketch to enable mTLS with SSLClient. 
     * This function supports both ECC and RSA certificate/private keys (use EC keys wherever 
     * possible, as they are signifigantly smaller and faster), however SSLClient only supports 
     * the p256, p384, and p512 curves for ECC.
     * 
     * Because SSLClientParameters creates a copy of both the certificate and key, you do not
     * need to ensure that the data pointed to by cert_der or key_der is accessible after
     * this function (i.e. you can free them afterwards).
     * 
     * Please note that if the private key is incorrect, this function will not
     * report an error, and instead SSLClient will fall back to regular TLS when making a 
     * connection.
     * 
     * @param cert_der A DER encoded certificate, can be ECC or RSA.
     * @param cert_len The number of bytes in cert_der.
     * @param key_der A DER encoded private key, can be ECC or RSA.
     * @param key_len The number of bytes in key_ders
     * @return An SSLClientParameters context, to be used with SSLClient::setMutualAuthParams.
     */
    static SSLClientParameters fromDER(const char* cert_der, const size_t cert_len, const char* key_der, const size_t key_len);

    /** mTLS information used by SSLClient during authentication */
    const br_x509_certificate* getCertChain() const { return &m_cert_struct; }

    /** mTLS information used by SSLClient during authentication */
    int getCertType() const { return br_skey_decoder_key_type(&m_key_struct); }

    /** mTLS information used by SSLClient during authentication */
    const br_ec_private_key* getECKey() const { return br_skey_decoder_get_ec(&m_key_struct); }

    /** mTLS information used by SSLClient during authentication */
    const br_rsa_private_key* getRSAKey() const { return br_skey_decoder_get_rsa(&m_key_struct); }

protected:
    SSLClientParameters(const char* cert, const size_t cert_len, const char* key, const size_t key_len, bool is_der);

private:
    const std::vector<char> m_cert;
    const br_x509_certificate m_cert_struct;
    const br_skey_decoder_context m_key_struct;
};

#endif
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

#ifndef SSLClientParameters_H_
#define SSLClientParameters_H_

/**
 * This file contains a simple struct to package together all the data required to
 * use client certificate authentication with SSLClient.
 */

/**
 * \brief This struct stores data required for SSLClient to use mutual authentication.
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

struct SSLClientParameters {
    /** 
     * \brief Pointer to the client certificate chain. 
     * 
     * Must be availible in memory AT ALL TIMES, should not be a local object.
     * Certificates must be ordered from Client->Intermediate->...->Root.
     */
    const br_x509_certificate* client_cert_chain;
    /** The number of certificates in SSLClientParameters::client_cert_chain  */
    const size_t chain_len;
    /** The private key corresponding to the first certificate in SSLClientParameters::client_cert_chain */
    const br_ec_private_key ec_key;
};

#endif
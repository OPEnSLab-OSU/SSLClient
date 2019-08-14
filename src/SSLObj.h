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
 * SSLObj.h
 * 
 * This file contains a utility class to take PEM input and store it as a DER object
 * for later use by BearSSL.
 */
#include <cstring>
#include "bearssl_pem.h"

#ifndef SSLObj_H_
#define SSLObj_H_

#undef min
#undef max
#include <vector>

/**
 * \brief This namespace works with raw DER byte arrays for use later with TLS mutual auth.
 * 
 * This namespace was created to store some of the values stored in ::SSLClientParameters, 
 * which allow BearSSL use client certificates when creating a TLS connection. Since
 * most certificates are transmitted over the internet in PEM format, a certificate can
 * be provided in PEM or DER format, and will be converted internally to DER format for
 * later use.
 */

namespace SSLObj {
    /**
     * @brief Convert a PEM buffer into a vector of raw DER bytes
     * 
     * This function takes a PEM buffer (e.g. `----BEGIN CERTIFICATE...`) and converts
     * it into a vector of raw bytes. The bytes given to this function must:
     * * Contain both the `-----BEGIN XXX-----` and `-----END XXX-----` strings. These are
     * removed during processing.
     * * Have a base64 encoded body
     * * Only contain a single object (certificate, private key, etc.).
     * 
     * @returns The raw bytes decoded from the PEM file.
     */
    const std::vector<unsigned char> make_vector_pem(const char* data, const size_t len);
}

#endif
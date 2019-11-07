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
 * SSLSession.h
 * 
 * This file contains a simple utility class to store parameters about an SSL Session
 * for reuse later.
 */

#include "bearssl.h"
#include "Arduino.h"

#ifndef SSLSession_H_
#define SSLSession_H_

/**
 * \brief This class stores values which allow SSLClient to save and resume SSL sessions.
 * 
 * This class was created to extend the values stored in br_ssl_session_parameters, 
 * which allow BearSSL to resume an SSL session. When testing BearSSL's session
 * resumption feature, it was observed that BearSSL can only resume a session that was
 * was started with the same server. This becomes an issue when using repeated requests
 * to a domain name which can resolve to multiple IP addresses ("api.github.com"), as
 * the device will switch between two or three servers. Since BearSSL only stores one
 * session at a time, this results in session resumption being few and far between.
 * 
 * To remedy this problem, an SSLSession stores the IPAddress and hostname, along with
 * the parameters in br_ssl_session_parameters struct. Using this data, SSLClient is
 * able to remember which IPAddress is associated with which session, allowing it to
 * reconnect to the last IPAddress, as opposed to any associated with the domain.
 */

class SSLSession : public br_ssl_session_parameters {

public:
    /**
     * @brief SSLSession constructor
     * 
     * Sets all parameters to zero, and invalidates the session
     */
    SSLSession(const char* hostname)
        : m_hostname(hostname) {}

    /**
     * @brief Get the hostname string associated with this session
     * 
     * @returns A String object or "" if there is no hostname
     * @pre must check isValidSession before getting this value,
     * as if this session in invalid this value is not guarenteed
     * to be reset to "".
     */
    const String& get_hostname() const { return m_hostname; }

    /** @brief Returns a pointer to the ::br_ssl_session_parameters component of this class. */
    br_ssl_session_parameters* to_br_session() { return (br_ssl_session_parameters *)this; }

private:
    // aparently a hostname has a max length of 256 chars. Go figure.
    String m_hostname;
};



#endif /* SSLSession_H_ */
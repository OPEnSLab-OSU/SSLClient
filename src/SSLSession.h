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
    explicit SSLSession()
        : m_valid_session(false)
        , m_hostname({})
        , m_ip(INADDR_NONE) {}

    /**
     * \pre must call br_ssl_engine_get_session_parameters(engine, toBearSSlSession());
     */
    void set_parameters(const IPAddress& ip, const char* hostname = NULL) {
        // copy the hostname
        if (hostname != NULL) strncpy(m_hostname, hostname, sizeof m_hostname - 1);
        // or if there's no hostname, clear the string
        else m_hostname[0] = '\0';
        // and the IP address
        m_ip = ip;
        // check if both values are valid, and if so set valid to true
        if (m_ip != INADDR_NONE && session_id_len > 0
            && (hostname == NULL || strlen(m_hostname) > 0)) m_valid_session = true;
    }

    br_ssl_session_parameters* to_br_session() { return (br_ssl_session_parameters *)this; }

    /**
     * \pre must check isValidSession
     */
    const char* const get_hostname() const { return m_hostname; }

    /**
     * \pre must check isValidSession
     */
    const IPAddress& get_ip() const { return m_ip; }

    const bool is_valid_session() const { return m_valid_session; }
private:
    bool m_valid_session;
    // aparently a hostname has a max length of 256 chars. Go figure.
    char m_hostname[256];
    // store the IP Address we connected to
    IPAddress m_ip;
};

#endif /* SSLSession_H_ */
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
#include "IPAddress.h"

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
    SSLSession()
        : m_valid_session(false)
        , m_hostname()
        , m_ip(INADDR_NONE) {}

    /** @brief use clear_parameters or set_parameters instead */
    SSLSession& operator=(const SSLSession&) = delete;

    /**
     * @brief Get the hostname string associated with this session
     * 
     * @returns A String object or "" if there is no hostname
     * @pre must check isValidSession before getting this value,
     * as if this session in invalid this value is not guarenteed
     * to be reset to "".
     */
    const String& get_hostname() const { return m_hostname; }

    /**
     * @brief Get ::IPAddress associated with this session
     * 
     * @returns A ::IPAddress object, #INADDR_NONE if there is no IP
     * @pre must check isValidSession before getting this value,
     * as if this session in invalid this value is not guarenteed
     * to be reset to #INADDR_NONE.
     */
    const IPAddress& get_ip() const { return m_ip; }

    bool is_valid_session() const { return m_valid_session; }

     /**
     * @brief Set the ip address and hostname of the session.
     * 
     * This function stores the ip Address object and hostname object into
     * the session object. If hostname is not null or ip address is
     * not blank, and the ::br_ssl_session_parameters values are non-zero
     * it then validates the session.
     * 
     * @pre You must call 
     * ::br_ssl_engine_get_session_parameters
     * with this session before calling this function. This is because
     * there is no way to completely validate the ::br_ssl_session_parameters
     * and the session may end up in a corrupted state if this is not observed.
     * 
     * @param ip The IP address of the host associated with the session
     * @param hostname The string hostname ("www.google.com") associated with the session.
     * Take care that this value is corrent, SSLSession performs no validation
     * of the hostname.
     */
    void set_parameters(const IPAddress& ip, const char* hostname = NULL);

    /**
     * @brief Delete the parameters and invalidate the session.
     *
     * Roughly equivalent to this_session = SSLSession(), however 
     * this function preserves the String object, allowing it
     * to better handle the dynamic memory needed.
     */
    void clear_parameters();

    /** @brief Returns a pointer to the ::br_ssl_session_parameters component of this class. */
    br_ssl_session_parameters* to_br_session() { return (br_ssl_session_parameters *)this; }

private:
    bool m_valid_session;
    // aparently a hostname has a max length of 256 chars. Go figure.
    String m_hostname;
    // store the IP Address we connected to
    IPAddress m_ip;
};



#endif /* SSLSession_H_ */
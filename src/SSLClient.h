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
 * SSLCLient.h
 * 
 * This library was created to provide SSL functionality to the {@link https://learn.adafruit.com/adafruit-wiz5500-wiznet-ethernet-featherwing/overview}
 * Adafruit Ethernet shield. Since this shield does not implement SSL functionality on
 * its own, we need to use an external library: in this case BearSSL {@link https://bearssl.org/},
 * which is also used in the Arduino ESP8266 core. SSLClient will serve to implement the
 * BearSSL functionality inbetween EthernetClient and the User, such that the user.
 * 
 * This file specifically controls the class templating used to allow SSLClient to interface
 * with all of the CLient-based classes. To see details on the implementations of the functions
 * in SSLClient, please see {@link ./SSLClientImpl.h}.
 */

#include <type_traits>
#include "Client.h"
#include "SSLClientImpl.h"
#include "SSLSession.h"

#ifndef SSLClient_H_
#define SSLClient_H_

/**
 * \brief The main SSLClient class
 *  
 * TODO: fix this blurb
 * 
 * This class serves as a templating proxy class for the SSLClientImpl to do the real work.
 * 
 * A problem arose when writing this class: I wanted the user to be able to construct
 * this class in a single line of code (e.g. SSLClient(EthernetClient())), but I also
 * wanted to avoid the use of dynamic memory if possible. In an attempt to solve this
 * problem I used a templated classes. However, becuase of the Arduino build process 
 * this meant that the implementations for all the functions had to be in a header 
 * file (a weird effect of using templated classes and linking) which would slow down
 * the build quite a bit. As a comprimise, I instead decided to build the main class (SSLCLient)
 * as a templated class, and have use a not templated implementation class (SSLClientImpl)
 * that would be able to reside in a seperate file. This gets the best of both worlds
 * from the client side, however from the developer side it can be a bit confusing.
 */

template <class C, size_t SessionCache = 1>
class SSLClient : public SSLClientImpl {
/** 
 * static checks
 * I'm a java developer, so I want to ensure that my inheritance is safe.
 * These checks ensure that all the functions we use on class C are
 * actually present on class C. It does this by checking that the
 * class inherits from Client.
 * 
 * Additionally, I ran into a lot of memory issues with large sessions caches.
 * Since each session contains at max 352 bytes of memory, they eat of the
 * stack quite quickly and can cause overflows. As a result, I have added a
 * warning here to discourage the use of more than 3 sessions at a time. Any
 * amount past that will require special modification of this library, and 
 * assumes you know what you are doing.
 */
static_assert(std::is_base_of<Client, C>::value, "C must be a Client Class!");
static_assert(SessionCache > 0 && SessionCache < 255, "There can be no less than one and no more than 255 sessions in the cache!");
static_assert(SessionCache <= 3, "You need to decrease the size of m_iobuf in order to have more than 3 sessions at once, otherwise memory issues will occur.");

public:
    /**
     * @brief copies the client object, and passes the various parameters to the SSLCLientImpl functions.
     * 
     * We copy the client because we aren't sure the Client object
     * is going to exists past the inital creation of the SSLClient.
     * 
     * @pre You will need to generate an array of trust_anchors (root certificates)
     * based off of the domains you want to make SSL connections to. Check out the
     * Wiki on the pycert-bearssl tool for a simple way to do this.
     * @pre The analog_pin should be set to input.
     * 
     * @param trust_anchors Trust anchors used in the verification 
     * of the SSL server certificate, generated using the `brssl` command
     * line utility. For more information see the samples or bearssl.org
     * @param trust_anchors_num The number of trust anchors stored
     * @param analog_pin An analog pin to pull random bytes from, used in seeding the RNG
     * @param debug whether to enable or disable debug logging, must be constexpr
     */
    explicit SSLClient(const C& client, const br_x509_trust_anchor *trust_anchors, const size_t trust_anchors_num, const int analog_pin, const DebugLevel debug = SSL_WARN)
    : SSLClientImpl(NULL, trust_anchors, trust_anchors_num, analog_pin, debug) 
    , m_client(client)
    , m_sessions{SSLSession()}
    , m_index(0)
    {
        // since we are copying the client in the ctor, we have to set
        // the client pointer after the class is constructed
        set_client(&m_client);
        // set the timeout to a reasonable number (it can always be changes later)
        // SSL Connections take a really long time so we don't want to time out a legitimate thing
        setTimeout(10 * 1000);
    }
    
    /*
     * The special functions most clients have are below
     * Most of them smply pass through
     */
    /** 
     * @brief Equivalent to SSLClient::connected() > 0
     * @returns true if connected, false if not
     */
	virtual operator bool() { return connected() > 0; }
    /** {@link SSLClient::bool()} */
	virtual bool operator==(const bool value) { return bool() == value; }
    /** {@link SSLClient::bool()} */
	virtual bool operator!=(const bool value) { return bool() != value; }
    /** @brief Returns whether or not two SSLClient objects have the same underlying client object */
	virtual bool operator==(const C& rhs) { return m_client == rhs; }
    /** @brief Returns whether or not two SSLClient objects do not have the same underlying client object */
	virtual bool operator!=(const C& rhs) { return m_client != rhs; }
    /** @brief Returns the local port, if the Client class has a localPort() function. Else return 0. */
	virtual uint16_t localPort() {
        if (std::is_member_function_pointer<decltype(&C::localPort)>::value) return m_client.localPort();
        else {
            m_warn("Client class has no localPort function, so localPort() will always return 0", __func__);
            return 0;
        } 
    }
    /** @brief Returns the remote IP, if the Client class has a remoteIP() function. Else return INADDR_NONE. */
	virtual IPAddress remoteIP() { 
        if (std::is_member_function_pointer<decltype(&C::remoteIP)>::value) return m_client.remoteIP();
        else {
            m_warn("Client class has no remoteIP function, so remoteIP() will always return INADDR_NONE. This means that sessions caching will always be disabled.", __func__);
            return INADDR_NONE;
        } 
    }
    /** @brief Returns the remote port, if the Client class has a remotePort() function. Else return 0. */
	virtual uint16_t remotePort() {
        if (std::is_member_function_pointer<decltype(&C::remotePort)>::value) return m_client.remotePort();
        else {
            m_warn("Client class has no remotePort function, so remotePort() will always return 0", __func__);
            return 0;
        } 
    }

    /** @brief returns a refernence to the client object stored in this class. Take care not to break it. */
    C& getClient() { return m_client; }

    /**
     * @brief Get a sesssion reference corressponding to a host and IP, or a reference to a emptey session if none exist
     * 
     * If no session corresponding to the host and ip exist, then this function will cycle through
     * sessions in a rotating order. This allows the ssession cache to continuially store sessions,
     * however it will also result in old sessions being cleared and returned. In general, it is a
     * good idea to use a SessionCache size equal to the number of domains you plan on connecting to.
     * 
     * @param host A hostname c string, or NULL if one is not availible
     * @param ip An IP address
     * @returns A reference to an SSLSession object
     */
    virtual SSLSession& getSession(const char* host, const IPAddress& addr);

    /**
     * @brief Clear the session corresponding to a host and IP
     * 
     * @param host A hostname c string, or NULL if one is not availible
     * @param ip An IP address
     */
    virtual void removeSession(const char* host, const IPAddress& addr);
private:
    // utility function to find a session index based off of a host and IP
    int m_getSessionIndex(const char* host, const IPAddress& addr) const;
    // create a copy of the client
    C m_client;
    // also store an array of SSLSessions, so we can resume communication with multiple websites
    SSLSession m_sessions[SessionCache];
    // store an index of where a new session can be placed if we don't have any corresponding sessions
    size_t m_index;
};

template <class C, size_t SessionCache>
SSLSession& SSLClient<C, SessionCache>::getSession(const char* host, const IPAddress& addr) {
    const char* func_name = __func__;
    // search for a matching session with the IP
    int temp_index = m_getSessionIndex(host, addr);
    // if none are availible, use m_index
    if (temp_index == -1) {
        temp_index = m_index;
        // reset the session so we don't try to send one sites session to another
        m_sessions[temp_index].clear_parameters();
    }
    // increment m_index so the session cache is a circular buffer
    if (temp_index == m_index && ++m_index >= SessionCache) m_index = 0;
    // return the pointed to value
    m_info("Using session index: ", func_name);
    Serial.println(temp_index);
    return m_sessions[temp_index];
}

template <class C, size_t SessionCache>
void SSLClient<C, SessionCache>::removeSession(const char* host, const IPAddress& addr) {
    const char* func_name = __func__;
    int temp_index = m_getSessionIndex(host, addr);
    if (temp_index != -1) {
        m_info(" Deleted session ", func_name);
        m_info(temp_index, func_name);
        m_sessions[temp_index].clear_parameters();
    }
}

template <class C, size_t SessionCache>
int SSLClient<C, SessionCache>::m_getSessionIndex(const char* host, const IPAddress& addr) const {
    const char* func_name = __func__;
    // search for a matching session with the IP
    for (uint8_t i = 0; i < SessionCache; i++) {
        // if we're looking at a real session
        if (m_sessions[i].is_valid_session() 
            && (
                // and the hostname matches, or
                (host != NULL && m_sessions[i].get_hostname().equals(host))
                // there is no hostname and the IP address matches    
                || (host == NULL && addr == m_sessions[i].get_ip())
            )) {
            m_info("Found session match: ", func_name);
            m_info(m_sessions[i].get_hostname(), func_name);
            return i;
        }
    }
    // none found
    return -1;
}

#endif /** SSLClient_H_ */
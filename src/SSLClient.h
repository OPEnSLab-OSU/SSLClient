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
 * which is also use in the Arduino ESP8266 core. SSLClient will serve to implement the
 * BearSSL functionality inbetween EthernetCLient and the User, such that the user will
 * simply need to start with:
 * SSLCLient client(ethCLient);
 * And then call the functions they normally would with EthernetClient using SSLCLient.
 */

#include <type_traits>
#include "bearssl.h"
#include "Client.h"

#ifdef SSLClient_H_
#define SSLClient_H_

template <class C>
class SSLClient : public Client {
/** static type checks
 * I'm a java developer, so I want to ensure that my inheritance is safe.
 * These checks ensure that all the functions we use on class C are
 * actually present on class C. It does this by first checking that the
 * class inherits from Client, and then that it contains a status() function.
 */
static_assert(std::is_base_of(Client, C)::value, "C must be a Client Class!");
static_assert(std::is_function(decltype(C::status))::value, "C must have a status() function!");

/** error enums
 * Static constants defining the possible errors encountered
 * Read from getWriteError();
 */
enum Error {
    SSL_OK = 0,
    SSL_CLIENT_CONNECT_FAIL,
    SSL_BR_CONNECT_FAIL,
    SSL_CLIENT_WRTIE_ERROR,
    SSL_BR_WRITE_ERROR,
};

public:
    /**
     * @brief copies the client object and initializes SSL contexts for bearSSL
     * 
     * We copy the client because we aren't sure the Client object
     * is going to exists past the inital creation of the SSLClient.
     * 
     * @pre The client class must be able to access the internet, as SSLClient
     * cannot manage this for you.
     * 
     * @param trust_anchors Trust anchors used in the verification 
     * of the SSL server certificate, generated using the `brssl` command
     * line utility. For more information see the samples or bearssl.org
     * @param trust_anchors_num The number of trust anchors stored
     * @param debug whether to enable or disable debug logging, must be constexpr
     */
    SSLClient(const C client, const br_x509_trust_anchor *trust_anchors, const size_t trust_anchors_num, const bool debug = true)
        : m_client(client)
        , m_trust_anchors(trust_anchors)
        , m_trust_anchors_num(trust_anchors_num)
        , m_debug(debug);

    /** Dtor is implicit since unique_ptr handles it fine */

    /** 
     * The virtual functions defining a Client are below 
     * Most of them smply pass through
     */
	virtual int availableForWrite(void) const { return m_client.availableForWrite(); };
	virtual operator bool() const { return m_client.bool(); }
	virtual bool operator==(const bool value) const { return bool() == value; }
	virtual bool operator!=(const bool value) const { return bool() != value; }
	virtual bool operator==(const C& rhs) const { return m_client.operator==(rhs); }
	virtual bool operator!=(const C& rhs) const { return !this->operator==(rhs); }
	virtual uint16_t localPort() const { return m_client.localPort(); }
	virtual IPAddress remoteIP() const { return m_client.remoteIP(); }
	virtual uint16_t remotePort() const { return m_client.remotePort(); }
	virtual void setConnectionTimeout(uint16_t timeout) { m_client.setConnectionTimeout(timeout); }

    /** functions specific to the EthernetClient which I'll have to override */
    uint8_t status() const;
    uint8_t getSocketNumber() const;

    /** functions dealing with read/write that BearSSL will be injected into */
    /**
     * @brief Connect over SSL to a host specified by an ip address
     * 
     * SSLClient::connect(host, port) should be preffered over this function, 
     * as verifying the domain name is a step in ensuring the certificate is 
     * legitimate, which is important to the security of the device. Additionally,
     * SSL sessions cannot be resumed, which can drastically increase initial
     * connect time.
     * 
     * This function initializes EthernetClient by calling EthernetClient::connect
     * with the parameters supplied, then once the socket is open initializes
     * the appropriete bearssl contexts using the TLS_only_profile. Due to the 
     * design of the SSL standard, this function will probably take an extended 
     * period (1-2sec) to negotiate the handshake and finish the connection. 
     * 
     * @param ip The ip address to connect to
     * @param port the port to connect to
     * @returns 1 if success, 0 if failure (as found in EthernetClient)
     * 
     * @error SSL_CLIENT_CONNECT_FAIL The client object could not connect to the host or port
     * @error SSL_BR_CONNECT_FAIL BearSSL could not initialize the SSL connection.
     */
    virtual int connect(IPAddress ip, uint16_t port = 443);
    /**
     * @brief Connect over SSL using connect(ip, port), but use a DNS lookup to
     * get the IP Address first. 
     * 
     * This function initializes EthernetClient by calling EthernetClient::connect
     * with the parameters supplied, then once the socket is open initializes
     * the appropriete bearssl contexts using the TLS_only_profile. 
     * 
     * Due to the design of the SSL standard, this function will probably take an 
     * extended period (1-2sec) to negotiate the handshake and finish the 
     * connection. Since the hostname is provided, however, BearSSL is able to keep
     * a session cache of the clients we have connected to. This should reduce
     * connection time greatly. In order to use this feature, you must reuse the
     * same SSLClient object to connect to the reused host. Doing this will allow 
     * BearSSL to automatically match the hostname to a cached session.
     * 
     * @param host The cstring host ("www.google.com")
     * @param port the port to connect to
     * @returns 1 of success, 0 if failure (as found in EthernetClient)
     * 
     * @error SSL_CLIENT_CONNECT_FAIL The client object could not connect to the host or port
     * @error SSL_BR_CONNECT_FAIL BearSSL could not initialize the SSL connection.
     */
	virtual int connect(const char *host, uint16_t port = 443);
    virtual size_t write(uint8_t b) { return write(&b, 1); }
	virtual size_t write(const uint8_t *buf, size_t size);
	virtual int available();
	virtual int read();
	virtual int read(uint8_t *buf, size_t size);
	virtual int peek();
	virtual void flush();
	virtual void stop();
	virtual uint8_t connected();
    
    //! get the client object
    C& getClient() { return m_client; }

private:
    /** @brief debugging print function, only prints if m_debug is true */
    template<type T>
    constexpr void m_print(const T str) { 
        if (m_debug) {
            Serial.print("SSLClient: "); 
            Serial.println(str); 
        }
    }
    /** run the bearssl engine until a certain state */
    int m_run_until(const unsigned target);
    /** proxy for availble that returns the state */
    int m_update_engine(); 
    // create a copy of the client
    const C m_client;
    // store pointers to the trust anchors
    // should not be computed at runtime
    constexpr br_x509_trust_anchor *m_trust_anchors;
    constexpr size_t m_trust_anchors_num;
    // store whether to enable debug logging
    constexpr bool m_debug;
    // store the context values required for SSL
    br_ssl_client_context m_sslctx;
    br_x509_minimal_context m_x509ctx;
    // use a mono-directional buffer by default to cut memory in half
    // can expand to a bi-directional buffer with maximum of BR_SSL_BUFSIZE_BIDI
    // or shrink to below BR_SSL_BUFSIZE_MONO, and bearSSL will adapt automatically
    // simply edit this value to change the buffer size to the desired value
    unsigned char m_iobuf[BR_SSL_BUFSIZE_MONO];
    static_assert(sizeof m_iobuf <= BR_SSL_BUFSIZE_BIDI);
    br_sslio_context m_ioctx;
};

#endif /** SSLClient_H_ */
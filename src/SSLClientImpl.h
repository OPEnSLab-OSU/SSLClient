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

#include "bearssl.h"
#include "Client.h"
#include "Arduino.h"

#ifndef SSLClientImpl_H_
#define SSLClientImpl_H_

/** TODO: Write what this is */

class SSLClientImpl : public Client {
public:
    /**
     * @brief initializes SSL contexts for bearSSL
     * 
     * @pre The client class must be able to access the internet, as SSLClient
     * cannot manage this for you.
     * 
     * @post set_client must be called immediatly after to set the client class
     * pointer.
     * 
     * @param trust_anchors Trust anchors used in the verification 
     * of the SSL server certificate, generated using the `brssl` command
     * line utility. For more information see the samples or bearssl.org
     * @param trust_anchors_num The number of trust anchors stored
     * @param debug whether to enable or disable debug logging, must be constexpr
     */
    explicit SSLClientImpl(Client* client, const br_x509_trust_anchor *trust_anchors, const size_t trust_anchors_num, const bool debug = true);
    /** Dtor is implicit since unique_ptr handles it fine */

    /** functions specific to the EthernetClient which I'll have to override */
    // uint8_t status();
    // uint8_t getSocketNumber() const;

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
    virtual int connect(IPAddress ip, uint16_t port);
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
	virtual int connect(const char *host, uint16_t port);
    virtual size_t write(uint8_t b) { return write(&b, 1); }
	virtual size_t write(const uint8_t *buf, size_t size);
	virtual int available();
	virtual int read() { uint8_t read_val; return read(&read_val, 1) > 0 ? read_val : -1; }
	virtual int read(uint8_t *buf, size_t size);
	virtual int peek();
	virtual void flush();
	virtual void stop();
	virtual uint8_t connected();

protected:
    /** 
     * @brief set the pointer to the Client class that we wil use
     * 
     * Call this function immediatly after the ctor. This functionality
     * is placed in it's own function for flexibility reasons, but it
     * is critical that this function is called before anything else
     */
    void set_client(Client* c) { m_client = c; }
private:

    /** @brief debugging print function, only prints if m_debug is true */
    template<typename T>
    constexpr void m_print(const T str) const { 
        if (m_debug) {
            Serial.print("SSLClientImpl: "); 
            Serial.println(str); 
        }
    }
    /** run the bearssl engine until a certain state */
    int m_run_until(const unsigned target);
    /** proxy for availble that returns the state */
    unsigned m_update_engine(); 
    // hold a reference to the client
    Client* m_client;
    // store pointers to the trust anchors
    // should not be computed at runtime
    const br_x509_trust_anchor *m_trust_anchors;
    const size_t m_trust_anchors_num;
    // store whether to enable debug logging
    const bool m_debug;
    // store the context values required for SSL
    br_ssl_client_context m_sslctx;
    br_x509_minimal_context m_x509ctx;
    // use a mono-directional buffer by default to cut memory in half
    // can expand to a bi-directional buffer with maximum of BR_SSL_BUFSIZE_BIDI
    // or shrink to below BR_SSL_BUFSIZE_MONO, and bearSSL will adapt automatically
    // simply edit this value to change the buffer size to the desired value
    unsigned char m_iobuf[BR_SSL_BUFSIZE_MONO];
    static_assert(sizeof m_iobuf <= BR_SSL_BUFSIZE_BIDI, "m_iobuf must be below maximum buffer size");
    // store the index of where we are writing in the buffer
    // so we can send our records all at once to prevent
    // weird timing issues
    size_t m_write_idx;
    // store the last error code

};

#endif /* SSLClientImpl_H_ */
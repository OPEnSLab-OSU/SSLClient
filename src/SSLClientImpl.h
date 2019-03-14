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
#include "Arduino.h"
#include "Client.h"
#include "SSLSession.h"

#ifndef SSLClientImpl_H_
#define SSLClientImpl_H_

// system reset definitions
#define SYSRESETREQ    (1<<2)
#define VECTKEY        (0x05fa0000UL)
#define VECTKEY_MASK   (0x0000ffffUL)
#define AIRCR          (*(uint32_t*)0xe000ed0cUL) // fixed arch-defined address
#define REQUEST_EXTERNAL_RESET (AIRCR=(AIRCR&VECTKEY_MASK)|VECTKEY|SYSRESETREQ)

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
    SSL_INTERNAL_ERROR,
    SSL_OUT_OF_MEMORY
};

/** Debug level enum
 * Static enum defining the debugging levels to print
 * into the Serial monitor
 */
enum DebugLevel {
    SSL_NONE = 0,
    SSL_ERROR = 1,
    SSL_WARN = 2,
    SSL_INFO = 3,
};


#ifdef __arm__
// should use uinstd.h to define sbrk but Due causes a conflict
extern "C" char* sbrk(int incr);
#else  // __ARM__
extern char *__brkval;
#endif  // __arm__
 
static int freeMemory() {
  char top;
#ifdef __arm__
  return &top - reinterpret_cast<char*>(sbrk(0));
#elif defined(CORE_TEENSY) || (ARDUINO > 103 && ARDUINO != 151)
  return &top - __brkval;
#else  // __arm__
  return __brkval ? &top - __brkval : &top - __malloc_heap_start;
#endif  // __arm__
}


/** TODO: Write what this is */

class SSLClientImpl : public Client {
public:
    /**
     * @brief initializes SSL contexts for bearSSL
     * 
     * @pre The client class must be able to access the internet, as SSLClient
     * cannot manage this for you. Additionally it is recommended that the analog_pin
     * be set to input.
     * 
     * @post set_client must be called immediatly after to set the client class
     * pointer.
     * 
     * @param trust_anchors Trust anchors used in the verification 
     * of the SSL server certificate, generated using the `brssl` command
     * line utility. For more information see the samples or bearssl.org
     * @param trust_anchors_num The number of trust anchors stored
     * @param analog_pin An analog pin to pull random bytes from, used in seeding the RNG
     * @param get_remote_ip Function pointer to get the remote ip from the client. We
     * need this value since the Client abstract class has no remoteIP() function,
     * however most of the arduino internet client implementations do.
     * @param debug whether to enable or disable debug logging, must be constexpr
     */
    explicit SSLClientImpl(Client* client, const br_x509_trust_anchor *trust_anchors, 
        const size_t trust_anchors_num, const int analog_pin, const DebugLevel debug);
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

    // stub virtual functions to get things from the client
    virtual uint16_t localPort() = 0;
	virtual IPAddress remoteIP() = 0;
	virtual uint16_t remotePort() = 0;

    // as well as store and retrieve session data
    virtual SSLSession& getSession(const char* host, const IPAddress& addr) = 0;
protected:
    /** 
     * @brief set the pointer to the Client class that we wil use
     * 
     * Call this function immediatly after the ctor. This functionality
     * is placed in it's own function for flexibility reasons, but it
     * is critical that this function is called before anything else
     */
    void set_client(Client* c) { m_client = c; }

    /** @brief Prints a debugging prefix to all logs, so we can attatch them to useful information */
    void m_print_prefix(const char* func_name, const DebugLevel level) const;

    /** @brief Prints the string associated with a write error */
    void m_print_ssl_error(const int ssl_error, const DebugLevel level) const;

    /** @brief Print the text string associated with a BearSSL error code */
    void m_print_br_error(const unsigned br_error_code, const DebugLevel level) const;

    /** @brief debugging print function, only prints if m_debug is true */
    template<typename T>
    void m_print(const T str, const char* func_name, const DebugLevel level) const { 
        // check the current debug level
        if (level > m_debug) return;
        // print prefix
        m_print_prefix(func_name, level);
        // print the message
        Serial.println(str);
    }

    /** @brief Prints a info message to serial, if info messages are enabled */
    template<typename T>
    void m_info(const T str, const char* func_name) const { m_print(str, func_name, SSL_INFO); }

    template<typename T>
    void m_warn(const T str, const char* func_name) const { m_print(str, func_name, SSL_WARN); }

    template<typename T>
    void m_error(const T str, const char* func_name) const { m_print(str, func_name, SSL_ERROR); }

private:
    void printState(unsigned state) const {
        if(m_debug == DebugLevel::SSL_INFO) {
            m_info("State: ", __func__);
            if(state == 0) Serial.println("    Invalid");
            else if (state & BR_SSL_CLOSED) Serial.println("   Connection closed");
            else {
                if (state & BR_SSL_SENDREC) Serial.println("   SENDREC");
                if (state & BR_SSL_RECVREC) Serial.println("   RECVREC");
                if (state & BR_SSL_SENDAPP) Serial.println("   SENDAPP");
                if (state & BR_SSL_RECVAPP) Serial.println("   RECVAPP");
            }
        }
    }
    /** Returns whether or not the engine is connected, without polling the client over SPI or other (as opposed to connected()) */
    bool m_soft_connected(const char* func_name);
    /** start the ssl engine on the connected client */
    int m_start_ssl(const char* host, SSLSession& ssl_ses);
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
    // store the pin to fetch an RNG see from
    const int m_analog_pin;
    // store whether to enable debug logging
    const DebugLevel m_debug;
    // store the context values required for SSL
    br_ssl_client_context m_sslctx;
    br_x509_minimal_context m_x509ctx;
    // use a mono-directional buffer by default to cut memory in half
    // can expand to a bi-directional buffer with maximum of BR_SSL_BUFSIZE_BIDI
    // or shrink to below BR_SSL_BUFSIZE_MONO, and bearSSL will adapt automatically
    // simply edit this value to change the buffer size to the desired value
    // additionally, we need to correct buffer size based off of how many sessions we decide to cache
    // since SSL takes so much memory if we don't it will cause the stack and heap to collide 
    unsigned char m_iobuf[BR_SSL_BUFSIZE_MONO / 4];
    static_assert(sizeof m_iobuf <= BR_SSL_BUFSIZE_BIDI, "m_iobuf must be below maximum buffer size");
    // store the index of where we are writing in the buffer
    // so we can send our records all at once to prevent
    // weird timing issues
    size_t m_write_idx;
};

#endif /* SSLClientImpl_H_ */
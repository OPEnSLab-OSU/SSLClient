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

/**
 * @brief Static constants defining the possible errors encountered.
 * 
 * If SSLClient encounters an error, it will generally output
 * logs into the serial moniter. If you need a way of programmatically
 * checking the errors, you can do so with SSLCLient.getWriteError(),
 * which will return one of these values.
 */
enum Error {
    SSL_OK = 0,
    /** The underlying client failed to connect, probably not an issue with SSL */
    SSL_CLIENT_CONNECT_FAIL,
    /** BearSSL failed to complete the SSL handshake, check logs for bear ssl error output */
    SSL_BR_CONNECT_FAIL,
    /** The underlying client failed to write a payload, probably not an issue with SSL */
    SSL_CLIENT_WRTIE_ERROR,
    /** An internal error occurred with BearSSL, check logs for diagnosis. */
    SSL_BR_WRITE_ERROR,
    /** An internal error occured with SSLClient, and you probably need to submit an issue on Github. */
    SSL_INTERNAL_ERROR,
    /** SSLClient detected that there was not enough memory (>8000 bytes) to continue. */
    SSL_OUT_OF_MEMORY
};

/**
 * @brief Level of verbosity used in logging for SSLClient.
 * 
 * Use these values when initializing SSLCLient to set how many logs you
 * would like to see in the Serial moniter.
 */
enum DebugLevel {
    /** No logging output */
    SSL_NONE = 0,
    /** Only output errors that result in connection failure */
    SSL_ERROR = 1,
    /** Ouput errors and warnings (useful when just starting to develop) */
    SSL_WARN = 2,
    /** Output errors, warnings, and internal information (very verbose) */
    SSL_INFO = 3,
};

/** 
 * On error, any function in this class will terminate the socket.
 * TODO: Write what this is */

class SSLClientImpl : public Client {
public:
    /**
     * @brief initializes SSL contexts for bearSSL
     * 
     * @pre You will need to generate an array of trust_anchors (root certificates)
     * based off of the domains you want to make SSL connections to. Check out the
     * Wiki on the pycert-bearssl tool for a simple way to do this.
     * @pre The analog_pin should be set to input.
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

    /* functions dealing with read/write that BearSSL will be injected into */
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
     * the appropriete bearssl contexts. Due to the design of the SSL standard, 
     * this function will probably take an extended period (1-4sec) to negotiate 
     * the handshake and finish the connection. This function runs until the SSL 
     * handshake succeeds or fails, as found in most Arduino libraries, so be 
     * sure to design around this in your code.
     * 
     * @pre The underlying client object (passed in through the ctor) in a non-
     * error state, and must be able to access the server being connected to.
     * @pre SSLCLient can only have one connection at a time, so the client
     * object must not already have a socket open.
     * @pre There must be sufficient memory availible on the device to verify
     * the certificate (if the free memory drops below 8000 bytes during certain
     * points in the connection, SSLCLient will fail).
     * @pre There must be a trust anchor given to the ctor that corresponds to
     * the certificate provided by the IP address being connected to. For more
     * information check out the wiki on the pycert-bearssl tool.
     * @pre The analog pin passed to the ctor must be set to input, and must
     * be wired to something sort of random (floating is fine).
     * 
     * @param ip The ip address to connect to
     * @param port the port to connect to
     * @returns 1 if success, 0 if failure (as found in EthernetClient)
     */
    virtual int connect(IPAddress ip, uint16_t port);

    /**
     * @brief Connect over SSL using connect(ip, port), using a DNS lookup to
     * get the IP Address first. 
     * 
     * This function initializes EthernetClient by calling EthernetClient::connect
     * with the parameters supplied, then once the socket is open uses BearSSL to
     * to complete a SSL handshake. This function runs until the SSL handshake 
     * succeeds or fails, as found in most Arduino libraries.
     * 
     * SSL requires the client to generate some random bits (to be later combined 
     * with some random bits from the server), so SSLClient uses the least signinigant 
     * bits from the analog pin supplied in the ctor. The random bits are generated
     * from 16 consecutive analogReads, and given to BearSSL before the handshake
     * starts.
     * 
     * Due to the design of the SSL standard, this function will probably take an 
     * extended period (1-4sec) to negotiate the handshake and finish the 
     * connection. Since the hostname is provided, however, BearSSL is able to keep
     * a session cache of the clients we have connected to. This should reduce
     * connection time to about 100-200ms. In order to use this feature, the website
     * you are connecting to must support it (most do by default), you must 
     * reuse the same SSLClient object, and you must reconnect to the same server.
     * SSLClient automatcally stores an IP address and hostname in each session,
     * ensuring that if you call connect("www.google.com") SSLClient will use a
     * cached IP address instead of another DNS lookup. Because some websites have
     * multiple servers on a single IP address (github.com is an example), however,
     * you may find that even if you are connecting to the same host the connection
     * does not resume. This is a flaw in the SSL session protocol, and has been 
     * resolved in future versions. On top of all that, SSL sessions can expire
     * based on server criteria, which will result in a regular connection time.
     * Because of all these factors, it is generally prudent to assume the
     * connection will not be resumed, and go from there.
     * 
     * @pre The underlying client object (passed in through the ctor) in a non-
     * error state, and must be able to access the server being connected to.
     * @pre SSLCLient can only have one connection at a time, so the client
     * object must not already have a socket open.
     * @pre There must be sufficient memory availible on the device to verify
     * the certificate (if the free memory drops below 8000 bytes during certain
     * points in the connection, SSLCLient will fail).
     * @pre There must be a trust anchor given to the ctor that corresponds to
     * the certificate provided by the IP address being connected to. For more
     * information check out the wiki on the pycert-bearssl tool.
     * @pre The analog pin passed to the ctor must be set to input, and must
     * be wired to something sort of random (floating is fine).
     * 
     * @param host The cstring host ("www.google.com")
     * @param port the port to connect to (443)
     * @returns 1 of success, 0 if failure (as found in EthernetClient).
     */
	virtual int connect(const char *host, uint16_t port);

    /** @see SSLClient::write(uint8_t*, size_t) */
    virtual size_t write(uint8_t b) { return write(&b, 1); }
    /**
     * @brief Write some bytes to the SSL connection
     * 
     * Assuming all preconditions are met, this function waits for BearSSL
     * to be ready for data to be sent, then writes data to the BearSSL IO 
     * buffer, BUT does not initally send the data. Insead, it is
     * then checked if the BearSSL IO buffer is full, and if so, this function
     * waits until BearSSL has flushed the buffer (written it to the 
     * network client) and fills the buffer again. If the function finds 
     * that the BearSSL buffer is not full, it returns the number of 
     * bytes written. In other words, this function will only write data 
     * to the network if the BearSSL IO buffer is full. Instead, you must call 
     * SSLClient::availible or SSLClient::flush, which will detect that 
     * the buffer is ready for writing, and will write the data to the network.
     * 
     * This was implemented as a buffered function because users of Arduino Client
     * libraries will often write to the network as such:
     * @code{.cpp}
     * Client client;
     * ...
     * client.println("GET /asciilogo.txt HTTP/1.1");
     * client.println("Host: arduino.cc");
     * client.println("Connection: close");
     * while (!client.available()) { ... }
     * ...
     * @endcode
     * This is fine with most network clients. With SSL, however, if we are encryting and
     * writing to the network every write() call this will result in a lot of
     * small encryption tasks. Encryption takes a lot of time and code, and in general
     * the larger the batch we can do it in the better. For this reason, write() 
     * implicitly buffers until SSLClient::availible is called, or until the buffer is full.
     * If you would like to trigger a network write manually without using the SSLClient::available,
     * you can also call SSLClient::flush, which will write all data and return when finished.
     * 
     * @pre The socket and SSL layer must be connected, meaning SSLClient::connected must be true.
     * @pre BearSSL must not be waiting for the recipt of user data (if it is, there is
     * probably an error with how the protocol in implemented in your code).
     * 
     * @param buf the pointer to a buffer of bytes to copy
     * @param size the number of bytes to copy from the buffer
     * @returns The number of bytes copied to the buffer (size), or zero if the BearSSL engine 
     * fails to become ready for writing data.
     */
	virtual size_t write(const uint8_t *buf, size_t size);

    /**
     * @brief Returns the number of bytes availible to read from the SSL Socket
     * 
     * This function updates the state of the SSL engine (including writing any data, 
     * see SSLClient::write) and as a result should be called periodically when writing
     * or expecting data. Additionally, since this function returns zero if there are
     * no bytes and if SSLClient::connected is false (this same behavior is found
     * in EthernetClient), it is prudent to ensure in your own code that the 
     * preconditions are met before checking this function to prevent an ambigious
     * result.
     * 
     * @pre SSLClient::connected must be true.
     * 
     * @returns The number of bytes availible (can be zero), or zero if any of the pre
     * conditions aren't satisfied.
     */
	virtual int available();

    /** @see SSLClient::read(uint8_t*, size_t) */
	virtual int read() { uint8_t read_val; return read(&read_val, 1) > 0 ? read_val : -1; }
    /**
     * @brief Read size bytes from the SSL socket buffer, copying them into *buf, and return the number of bytes read.
     * 
     * This function checks if bytes are ready to be read by calling SSLClient::availible,
     * and if there are some copies size number of bytes from the IO buffer into buf.
     * 
     * It should be noted that a common problem I encountered with SSL connections is
     * buffer overflow, caused by the server sending too much data at once. This problem
     * only occurs...
     * 
     * TODO: finish
     */
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
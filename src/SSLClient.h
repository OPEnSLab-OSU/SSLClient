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

#include "Client.h"
#include "SSLSession.h"
#include "SSLClientParameters.h"
#include <vector>

#ifndef SSLClient_H_
#define SSLClient_H_

/**
 * @brief The main SSLClient class.
 * Check out README.md for more info.
 */

class SSLClient : public Client {
public:
    /**
     * @brief Static constants defining the possible errors encountered.
     * 
     * If SSLClient encounters an error, it will generally output
     * logs into the serial monitor. If you need a way of programmatically
     * checking the errors, you can do so with SSLClient::getWriteError(),
     * which will return one of these values.
     */
    enum Error {
        SSL_OK = 0,
        /** The underlying client failed to connect, probably not an issue with SSL */
        SSL_CLIENT_CONNECT_FAIL = 2,
        /** BearSSL failed to complete the SSL handshake, check logs for bear ssl error output */
        SSL_BR_CONNECT_FAIL = 3,
        /** The underlying client failed to write a payload, probably not an issue with SSL */
        SSL_CLIENT_WRTIE_ERROR = 4,
        /** An internal error occurred with BearSSL, check logs for diagnosis. */
        SSL_BR_WRITE_ERROR = 5,
        /** An internal error occurred with SSLClient, and you probably need to submit an issue on Github. */
        SSL_INTERNAL_ERROR = 6,
        /** SSLClient detected that there was not enough memory (>8000 bytes) to continue. */
        SSL_OUT_OF_MEMORY = 7
    };

    /**
     * @brief Level of verbosity used in logging for SSLClient.
     * 
     * Use these values when initializing SSLClient to set how many logs you
     * would like to see in the Serial monitor.
     */
    enum DebugLevel {
        /** No logging output */
        SSL_NONE = 0,
        /** Only output errors that result in connection failure */
        SSL_ERROR = 1,
        /** Output errors and warnings (useful when just starting to develop) */
        SSL_WARN = 2,
        /** Output errors, warnings, and internal information (very verbose) */
        SSL_INFO = 3,
        /** In addition to the above logs, dumps every byte in SSLClient::write to the Serial monitor */
        SSL_DUMP = 4,
    };

    /**
     * @brief Initialize SSLClient with all of the prerequisites needed.
     * 
     * @pre You will need to generate an array of trust_anchors (root certificates)
     * based off of the domains you want to make SSL connections to. Check out the
     * TrustAnchors.md file for more info.
     * @pre The analog_pin should be set to input.
     * 
     * @param client The base network device to create an SSL socket on. This object will be copied
     * and the copy will be stored in SSLClient.
     * @param trust_anchors Trust anchors used in the verification 
     * of the SSL server certificate. Check out TrustAnchors.md for more info.
     * @param trust_anchors_num The number of objects in the trust_anchors array.
     * @param analog_pin An analog pin to pull random bytes from, used in seeding the RNG.
     * @param max_sessions The maximum number of SSL sessions to store connection information from.
     * @param debug The level of debug logging (use the ::DebugLevel enum).
     */
    explicit SSLClient( Client& client, 
                        const br_x509_trust_anchor *trust_anchors, 
                        const size_t trust_anchors_num, 
                        const int analog_pin, 
                        const size_t max_sessions = 1,
                        const DebugLevel debug = SSL_WARN);

    //========================================
    //= Functions implemented in SSLClient.cpp
    //========================================

    /**
     * @brief Connect over SSL to a host specified by an IP address.
     * 
     * SSLClient::connect(host, port) should be preferred over this function, 
     * as verifying the domain name is a step in ensuring the certificate is 
     * legitimate, which is important to the security of the device. Additionally,
     * SSL sessions cannot be resumed when using this function, which can drastically increase initial
     * connect time.
     * 
     * This function initializes the socket by calling m_client::connect(IPAddress, uint16_t)
     * with the parameters supplied, then once the socket is open, uses BearSSL to
     * to complete a SSL handshake. Due to the design of the SSL standard, 
     * this function will probably take an extended period (1-4sec) to negotiate 
     * the handshake and finish the connection. This function runs until the SSL 
     * handshake succeeds or fails.
     * 
     * SSL requires the client to generate some random bits (to be later combined 
     * with some random bits from the server), so SSLClient uses the least significant 
     * bits from the analog pin supplied in the constructor. The random bits are generated
     * from 16 consecutive analogReads, and given to BearSSL before the handshake
     * starts.
     * 
     * The implementation for this function can be found in SSLClientImpl::connect_impl(IPAddress, uint16_t).
     * 
     * @pre The underlying client object (passed in through the constructor) is in a non-
     * error state, and must be able to access the IP.
     * @pre SSLClient can only have one connection at a time, so the client
     * object must not already be connected.
     * @pre There must be sufficient memory available on the device to verify
     * the certificate (if the free memory drops below 8000 bytes during certain
     * points in the connection, SSLClient will fail).
     * @pre There must be a trust anchor given to the constructor that corresponds to
     * the certificate provided by the IP address being connected to. For more
     * information check out TrustAnchors.md .
     * 
     * @param ip The IP address to connect to
     * @param port the port to connect to
     * @returns 1 if success, 0 if failure
     */
    int connect(IPAddress ip, uint16_t port) override;

    /**
     * @brief Connect over SSL to a host specified by a hostname.
     * 
     * This function initializes the socket by calling m_client::connect(const char*, uint16_t)
     * with the parameters supplied, then once the socket is open, uses BearSSL to
     * complete a SSL handshake. This function runs until the SSL handshake 
     * succeeds or fails.
     * 
     * SSL requires the client to generate some random bits (to be later combined 
     * with some random bits from the server), so SSLClient uses the least significant 
     * bits from the analog pin supplied in the constructor. The random bits are generated
     * from 16 consecutive analogReads, and given to BearSSL before the handshake
     * starts.
     * 
     * This function will usually take around 4-10 seconds. If possible, this function
     * also attempts to resume the SSL session if one is present matching the hostname 
     * string, which will reduce connection time to 100-500ms. To read more about this 
     * functionality, check out Session Caching in the README.
     * 
     * The implementation for this function can be found in SSLClientImpl::connect_impl(const char*, uint16_t)
     * 
     * @pre The underlying client object (passed in through the constructor) is in a non-
     * error state, and must be able to access the IP.
     * @pre SSLClient can only have one connection at a time, so the client
     * object must not already be connected.
     * @pre There must be sufficient memory available on the device to verify
     * the certificate (if the free memory drops below 8000 bytes during certain
     * points in the connection, SSLClient will fail).
     * @pre There must be a trust anchor given to the constructor that corresponds to
     * the certificate provided by the IP address being connected to. For more
     * information check out TrustAnchors.md .
     * 
     * @param host The hostname as a null-terminated c-string ("www.google.com")
     * @param port The port to connect to on the host (443 for HTTPS)
     * @returns 1 of success, 0 if failure
     */
	int connect(const char *host, uint16_t port) override;

    /**
     * @brief Write some bytes to the SSL connection
     * 
     * Assuming all preconditions are met, this function writes data to the BearSSL IO 
     * buffer, BUT does not initially send the data. Instead, you must call 
     * SSLClient::available or SSLClient::flush, which will detect that 
     * the buffer is ready for writing, and will write the data to the network. 
     * Alternatively, if this function is requested to write a larger amount of data than SSLClientImpl::m_iobuf
     * can handle, data will be written to the network in pages the size of SSLClientImpl::m_iobuf until
     * all the data in buf is sent--attempting to keep all writes to the network grouped together. For information
     * on why this is the case check out README.md .
     * 
     * The implementation for this function can be found in SSLClientImpl::write_impl(const uint8_t*, size_t)
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
	size_t write(const uint8_t *buf, size_t size) override;
    /** @see SSLClient::write(uint8_t*, size_t) */
    size_t write(uint8_t b) override { return write(&b, 1); }

    /**
     * @brief Returns the number of bytes available to read from the data that has been received and decrypted.
     * 
     * This function updates the state of the SSL engine (including writing any data, 
     * see SSLClient::write) and as a result should be called periodically when expecting data. 
     * Additionally, since if there are no bytes and if SSLClient::connected is false 
     * this function returns zero (this same behavior is found
     * in EthernetClient), it is prudent to ensure in your own code that the 
     * preconditions are met before checking this function to prevent an ambiguous
     * result.
     * 
     * The implementation for this function can be found in SSLClientImpl::available
     * 
     * @pre SSLClient::connected must be true. (Call SSLClient::connected before this function)
     * 
     * @returns The number of bytes available (can be zero), or zero if any of the pre
     * conditions aren't satisfied.
     */
	int available() override;

    /**
     * @brief Read size bytes from the SSL client buffer, copying them into *buf, and return the number of bytes read.
     * 
     * This function checks if bytes are ready to be read by calling SSLClient::available,
     * and if so copies size number of bytes from the IO buffer into the buf pointer.
     * Data read using this function will not 
     * include any SSL or socket commands, as the Client and BearSSL will capture those and 
     * process them separately.
     * 
     * If you find that you are having a lot of timeout errors, SSLClient may be experiencing a buffer
     * overflow. Checkout README.md for more information.
     * 
     * The implementation for this function can be found in SSLClientImpl::read_impl(uint8_t*, size_t)
     * 
     * @pre SSLClient::available must be >0
     * 
     * @param buf The pointer to the buffer to put SSL application data into
     * @param size The size (in bytes) to copy to the buffer
     * 
     * @returns The number of bytes copied (<= size), or -1 if the preconditions are not satisfied.
     */
	int read(uint8_t *buf, size_t size) override;
    /** 
     * @brief Read a single byte, or -1 if none is available.
     * @see SSLClient::read(uint8_t*, size_t) 
     */
	int read() override { uint8_t read_val; return read(&read_val, 1) > 0 ? read_val : -1; };

    /** 
     * @brief View the first byte of the buffer, without removing it from the SSLClient Buffer
     * 
     * The implementation for this function can be found in SSLClientImpl::peek 
     * @pre SSLClient::available must be >0
     * @returns The first byte received, or -1 if the preconditions are not satisfied (warning: 
     * do not use if your data may be -1, as the return value is ambiguous)
     */
    int peek() override;

    /**
     * @brief Force writing the buffered bytes from SSLClient::write to the network.
     * 
     * This function is blocking until all bytes from the buffer are written. For
     * an explanation of how writing with SSLClient works, please see SSLClient::write.
     * The implementation for this function can be found in SSLClientImpl::flush.
     */
	void flush() override;

    /**
     * @brief Close the connection
     *
     * If the SSL session is still active, all incoming data is discarded and BearSSL will attempt to
     * close the session gracefully (will write to the network), and then call m_client::stop. If the session is not active or an
     * error was encountered previously, this function will simply call m_client::stop.
     * The implementation for this function can be found in SSLClientImpl::peek.
     */
	void stop() override;

    /**
     * @brief Check if the device is connected.
     *
     * Use this function to determine if SSLClient is still connected and a SSL connection is active.
     * It should be noted that this function should be called before SSLClient::available--
     * both functions send and receive data with the SSLClient::m_client device, however SSLClient::available
     * has some delays built in to protect SSLClient::m_client from being polled too frequently, and SSLClient::connected
     * contains logic to ensure that if the socket is dropped SSLClient will react accordingly.
     * 
     * The implementation for this function can be found in SSLClientImpl::connected_impl.
     * 
     * @returns 1 if connected, 0 if not
     */
	uint8_t connected() override;

    //========================================
    //= Functions Not in the Client Interface
    //========================================

    /**
     * @brief Add a client certificate and enable support for mutual auth
     * 
     * Please ensure that the values in `params` are valid for the lifetime
     * of SSLClient. You may want to make them global constants.
     * 
     * @pre SSLClient has not already started an SSL connection.
     */
    void setMutualAuthParams(const SSLClientParameters& params);

    /**
     * @brief Gets a session reference corresponding to a host and IP, or a reference to a empty session if none exist
     * 
     * If no session corresponding to the host and IP exist, then this function will cycle through
     * sessions in a rotating order. This allows the session cache to continually store sessions,
     * however it will also result in old sessions being cleared and returned. In general, it is a
     * good idea to use a SessionCache size equal to the number of domains you plan on connecting to.
     * 
     * The implementation for this function can be found at SSLClientImpl::get_session_impl.
     * 
     * @param host A hostname c string, or NULL if one is not available
     * @param addr An IP address
     * @returns A pointer to the SSLSession, or NULL of none matched the criteria available
     */
    SSLSession* getSession(const char* host);

    /**
     * @brief Clear the session corresponding to a host and IP
     * 
     * The implementation for this function can be found at SSLClientImpl::remove_session_impl.
     * 
     * @param host A hostname c string, or nullptr if one is not available
     * @param addr An IP address
     */
    void removeSession(const char* host);

    /**
     * @brief Get the maximum number of SSL sessions that can be stored at once
     *
     *  @returns The SessionCache template parameter.
     */
    size_t getSessionCount() const { return m_sessions.size(); }

    /** 
     * @brief Equivalent to SSLClient::connected() > 0
     * 
     * @returns true if connected, false if not
     */
	operator bool() { return connected() > 0; }

    /** @brief Returns a reference to the client object stored in this class. Take care not to break it. */
    Client& getClient() { return m_client; }

    /** 
     * @brief Set the timeout when waiting for an SSL response.
     * @param t The timeout value, in milliseconds (defaults to 30 seconds if not set). Do not set to zero.
     */
	void setTimeout(unsigned int t) { m_timeout = t; }

    /** 
     * @brief Get the timeout when waiting for an SSL response.
     * @returns The timeout value in milliseconds.
     */
    unsigned int getTimeout() const { return m_timeout; }

    /**
     * @brief Change the time used during x509 verification to a different value.
     * 
     * This function directly calls br_x509_minimal_set_time to change the validation
     * time used by the minimal verification engine. You can use this function if the default value
     * of the compile time is causing issues. See https://bearssl.org/apidoc/bearssl__x509_8h.html#a7f3558b1999ce904084d578700b1002c
     * for more information what this function does and how to use it.
     * 
     * @param days Days are counted in a proleptic Gregorian calendar since January 1st, 0 AD.
     * @param seconds Seconds are counted since midnight, from 0 to 86400 (a count of 86400 is possible only if a leap second happened).
     */
    void setVerificationTime(uint32_t days, uint32_t seconds);

private:
    /** @brief Returns an instance of m_client that is polymorphic and can be used by SSLClientImpl */
    Client& get_arduino_client() { return m_client; }
    const Client& get_arduino_client() const { return m_client; }

    /** Returns whether or not the engine is connected, without polling the client over SPI or other (as opposed to connected()) */
    bool m_soft_connected(const char* func_name);
    /** start the ssl engine on the connected client */
    int m_start_ssl(const char* host = nullptr, SSLSession* ssl_ses = nullptr);
    /** run the bearssl engine until a certain state */
    int m_run_until(const unsigned target);
    /** proxy for available that returns the state */
    unsigned m_update_engine();
    /** utility function to find a session index based off of a host and IP */
    int m_get_session_index(const char* host) const; 

    /** @brief Prints a debugging prefix to all logs, so we can attatch them to useful information */
    void m_print_prefix(const char* func_name, const DebugLevel level) const;

    /** @brief Prints the string associated with a write error */
    void m_print_ssl_error(const int ssl_error, const DebugLevel level) const;

    /** @brief Print the text string associated with a BearSSL error code */
    void m_print_br_error(const unsigned br_error_code, const DebugLevel level) const;

    /** @brief Print the text string associated with the BearSSL state */
    void m_print_br_state(const unsigned br_state, const DebugLevel level) const;

    /** @brief debugging print function, only prints if m_debug is true */
    template<typename T>
    void m_print(const T str, const char* func_name, const DebugLevel level) const { 
        // check the current debug level and serial status
        if (level > m_debug || !Serial) return;
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

    //============================================
    //= Data Members
    //============================================
    // create a reference the client
    Client& m_client;
    // also store an array of SSLSessions, so we can resume communication with multiple websites
    std::vector<SSLSession> m_sessions;
    // as well as the maximmum number of sessions we can store
    const size_t m_max_sessions;
    // store the pin to fetch an RNG see from
    const int m_analog_pin;
    // store whether to enable debug logging
    const DebugLevel m_debug;
    // store if we are connected in bearssl or not
    bool m_is_connected;
    // store the timeout for SSL internals
    unsigned int m_timeout;
    // store the context values required for SSL
    br_ssl_client_context m_sslctx;
    br_x509_minimal_context m_x509ctx;
    // use a mono-directional buffer by default to cut memory in half
    // can expand to a bi-directional buffer with maximum of BR_SSL_BUFSIZE_BIDI
    // or shrink to below BR_SSL_BUFSIZE_MONO, and bearSSL will adapt automatically
    // simply edit this value to change the buffer size to the desired value
    // additionally, we need to correct buffer size based off of how many sessions we decide to cache
    // since SSL takes so much memory if we don't it will cause the stack and heap to collide 
    /**
     * @brief The internal buffer to use with BearSSL.
     * This buffer controls how much data BearSSL can encrypt/decrypt at a given time. It can be expanded
     * or shrunk to [255, BR_SSL_BUFSIZE_BIDI], depending on the memory and speed needs of your application.
     * As a rule of thumb SSLClient will fail if it does not have at least 8000 bytes when starting a
     * connection.
     */
    unsigned char m_iobuf[2048];
    // store the index of where we are writing in the buffer
    // so we can send our records all at once to prevent
    // weird timing issues
    size_t m_write_idx;
    // store the last BearSSL state so we can print changes to the console
    unsigned m_br_last_state;
};

#endif /** SSLClient_H_ */
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
#include "SSLDebugLevel.h"
#include "SSLError.h"
#include <type_traits>
#include <vector>

#ifndef SSLClient_H_
#define SSLClient_H_

#define DefaultBufferSize 2048

/**
 * @brief The main SSLClient class.
 * Check out README.md for more info.
 */
template <size_t BufferSize = DefaultBufferSize>
class SSLClientSized : public Client {
public:
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
    inline explicit SSLClientSized( Client& client, 
                        const br_x509_trust_anchor *trust_anchors, 
                        const size_t trust_anchors_num, 
                        const int analog_pin, 
                        const size_t max_sessions = 1,
                        const SSLDebugLevel debug = SSLDebugLevel::SSL_WARN)
        : m_client(client) 
        , m_sessions()
        , m_max_sessions(max_sessions)
        , m_analog_pin(analog_pin)
        , m_debug(debug)
        , m_is_connected(false)
        , m_write_idx(0)
        , m_br_last_state(0) {
        setTimeout(30*1000);
        // zero the iobuf just in case it's still garbage
        memset(m_iobuf, 0, sizeof m_iobuf);
        // initlalize the various bearssl libraries so they're ready to go when we connect
        br_client_init_TLS12_only(&m_sslctx, &m_x509ctx, trust_anchors, trust_anchors_num);
        // comment the above line and uncomment the line below if you're having trouble connecting over SSL
        // br_ssl_client_init_full(&m_sslctx, &m_x509ctx, m_trust_anchors, m_trust_anchors_num);
        // check if the buffer size is half or full duplex
        constexpr auto duplex = sizeof m_iobuf <= BR_SSL_BUFSIZE_MONO ? 0 : 1;
        br_ssl_engine_set_buffer(&m_sslctx.eng, m_iobuf, sizeof m_iobuf, duplex);
    }

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
    inline int connect(IPAddress ip, uint16_t port) override { return 0U; }

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
	inline int connect(const char *host, uint16_t port) override {
        const char* func_name = __func__;
        // connection check
        if (get_arduino_client().connected())
            m_warn("Arduino client is already connected? Continuing anyway...", func_name);
        // reset indexs for saftey
        m_write_idx = 0;
        // first we need our hidden client member to negotiate the socket for us,
        // since most times socket functionality is implemented in hardeware.
        if (!get_arduino_client().connect(host, port)) {
            m_error("Failed to connect using m_client. Are you connected to the internet?", func_name);
            setWriteError(static_cast<std::underlying_type<SSLError>::type>(SSLError::SSL_CLIENT_CONNECT_FAIL));
            return 0;
        }
        m_info("Base client connected!", func_name);
        // start ssl!
        return m_start_ssl(host, getSession(host));
    }

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
	inline size_t write(const uint8_t *buf, size_t size) override {
        const char* func_name = __func__;
        // super debug
        if (m_debug >= SSLDebugLevel::SSL_DUMP) Serial.write(buf, size);
        // check if the socket is still open and such
        if (!m_soft_connected(func_name) || !buf || !size) return 0;
        // wait until bearssl is ready to send
        if (m_run_until(BR_SSL_SENDAPP) < 0) {
            m_error("Failed while waiting for the engine to enter BR_SSL_SENDAPP", func_name);
            return 0;
        }
        // add to the bearssl io buffer, simply appending whatever we want to write
        size_t alen;
        unsigned char *br_buf = br_ssl_engine_sendapp_buf(&m_sslctx.eng, &alen);
        size_t cur_idx = 0;
        if (alen == 0) {
            m_error("BearSSL returned zero length buffer for sending, did an internal error occur?", func_name);
            return 0;
        }
        // while there are still elements to write
        while (cur_idx < size) {
            // if we're about to fill the buffer, we need to send the data and then wait
            // for another oppurtinity to send
            // so we only send the smallest of the buffer size or our data size - how much we've already sent
            const size_t cpamount = size - cur_idx >= alen - m_write_idx ? alen - m_write_idx : size - cur_idx;
            memcpy(br_buf + m_write_idx, buf + cur_idx, cpamount);
            // increment write idx
            m_write_idx += cpamount;
            // increment the buffer pointer
            cur_idx += cpamount;
            // if we filled the buffer, reset m_write_idx, and mark the data for sending
            if(m_write_idx == alen) {
                // indicate to bearssl that we are done writing
                br_ssl_engine_sendapp_ack(&m_sslctx.eng, m_write_idx);
                // reset the write index
                m_write_idx = 0;
                // write to the socket immediatly
                if (m_run_until(BR_SSL_SENDAPP) < 0) {
                    m_error("Failed while waiting for the engine to enter BR_SSL_SENDAPP", func_name);
                    return 0;
                }
                // reset the buffer pointer
                br_buf = br_ssl_engine_sendapp_buf(&m_sslctx.eng, &alen);
            }
        } 
        // works oky
        return size;
    }

    /** @see SSLClient::write(uint8_t*, size_t) */
    inline size_t write(uint8_t b) override { return write(&b, 1); }

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
	inline int available() override {
        const char* func_name = __func__;
        // connection check
        if (!m_soft_connected(func_name)) return 0;
        // run the SSL engine until we are waiting for either user input or a server response
        unsigned state = m_update_engine();
        if (state == 0) m_error("SSL engine failed to update.", func_name);
        else if(state & BR_SSL_RECVAPP) {
            // return how many received bytes we have
            size_t alen;
            br_ssl_engine_recvapp_buf(&m_sslctx.eng, &alen);
            return (int)(alen);
        }
        else if (state == BR_SSL_CLOSED) m_info("Engine closed after update", func_name);
        // flush the buffer if it's stuck in the SENDAPP state
        else if (state & BR_SSL_SENDAPP) br_ssl_engine_flush(&m_sslctx.eng, 0);
        // other state, or client is closed
        return 0;
    }

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
	inline int read(uint8_t *buf, size_t size) override {
        // check that the engine is ready to read
        if (available() <= 0 || !size) return -1;
        // read the buffer, send the ack, and return the bytes read
        size_t alen;
        unsigned char* br_buf = br_ssl_engine_recvapp_buf(&m_sslctx.eng, &alen);
        const size_t read_amount = size > alen ? alen : size;
        if(buf) memcpy(buf, br_buf, read_amount);
        // tell engine we read that many bytes
        br_ssl_engine_recvapp_ack(&m_sslctx.eng, read_amount);
        // tell the user we read that many bytes
        return read_amount;
    }

    /** 
     * @brief Read a single byte, or -1 if none is available.
     * @see SSLClient::read(uint8_t*, size_t) 
     */
	inline int read() override { uint8_t read_val; return read(&read_val, 1) > 0 ? read_val : -1; };

    /** 
     * @brief View the first byte of the buffer, without removing it from the SSLClient Buffer
     * 
     * The implementation for this function can be found in SSLClientImpl::peek 
     * @pre SSLClient::available must be >0
     * @returns The first byte received, or -1 if the preconditions are not satisfied (warning: 
     * do not use if your data may be -1, as the return value is ambiguous)
     */
    inline int peek() override {
        // check that the engine is ready to read
        if (available() <= 0) return -1; 
        // read the buffer, send the ack, and return the bytes read
        size_t alen;
        uint8_t read_num;
        read_num = br_ssl_engine_recvapp_buf(&m_sslctx.eng, &alen)[0];
        // tell the user we read that many bytes
        return (int)read_num;
    }

    /**
     * @brief Force writing the buffered bytes from SSLClient::write to the network.
     * 
     * This function is blocking until all bytes from the buffer are written. For
     * an explanation of how writing with SSLClient works, please see SSLClient::write.
     * The implementation for this function can be found in SSLClientImpl::flush.
     */
	inline void flush() override {
        if (m_write_idx > 0) {
            if(m_run_until(BR_SSL_RECVAPP) < 0) {
                m_error("Could not flush write buffer!", __func__);
                int error = br_ssl_engine_last_error(&m_sslctx.eng);
                if(error != BR_ERR_OK) 
                    m_print_br_error(error, SSLDebugLevel::SSL_ERROR);
                if (getWriteError()) 
                    m_print_ssl_error(getWriteError(), SSLDebugLevel::SSL_ERROR);
            }
        }
    }

    /**
     * @brief Close the connection
     *
     * If the SSL session is still active, all incoming data is discarded and BearSSL will attempt to
     * close the session gracefully (will write to the network), and then call m_client::stop. If the session is not active or an
     * error was encountered previously, this function will simply call m_client::stop.
     * The implementation for this function can be found in SSLClientImpl::peek.
     */
	inline void stop() override {
        // tell the SSL connection to gracefully close
        // Disabled to prevent close_notify from hanging SSLClient
        // br_ssl_engine_close(&m_sslctx.eng);
        // if the engine isn't closed, and the socket is still open
        auto state = br_ssl_engine_current_state(&m_sslctx.eng);
        if (state != BR_SSL_CLOSED
            && state != 0
            && connected()) {
            /*
	    	 * Discard any incoming application data.
	    	 */
	    	size_t len;
	    	if (br_ssl_engine_recvapp_buf(&m_sslctx.eng, &len) != nullptr) {
	    		br_ssl_engine_recvapp_ack(&m_sslctx.eng, len);
	    	}
            // run SSL to finish any existing transactions
            flush();
	    }
        // close the ethernet socket
        get_arduino_client().flush();
        get_arduino_client().stop();
        // we are no longer connected 
        m_is_connected = false;
    }

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
	inline uint8_t connected() override {
        const char* func_name = __func__;
        // check all of the error cases 
        const auto c_con = get_arduino_client().connected();
        const auto br_con = br_ssl_engine_current_state(&m_sslctx.eng) != BR_SSL_CLOSED && m_is_connected;
        const auto wr_ok = getWriteError() == 0;
        // if we're in an error state, close the connection and set a write error
        if (br_con && !c_con) {
            // If we've got a write error, the client probably failed for some reason
            if (get_arduino_client().getWriteError()) {
                m_error("Socket was unexpectedly interrupted. m_client error: ", func_name);
                m_error(get_arduino_client().getWriteError(), func_name);
                setWriteError(static_cast<std::underlying_type<SSLError>::type>(SSLError::SSL_CLIENT_WRTIE_ERROR));
            }
            // Else tell the user the endpoint closed the socket on us (ouch)
            else {
                m_warn("Socket was dropped unexpectedly (this can be an alternative to closing the connection)", func_name);
            }
            // we are not connected
            m_is_connected = false;
            // set the write error so the engine doesn't try to close the connection
            stop();
        }
        else if (!wr_ok) {
            m_error("Not connected because write error is set", func_name);
            m_print_ssl_error(getWriteError(), SSLDebugLevel::SSL_ERROR);
        }
        return c_con && br_con;
    }


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
    inline void setMutualAuthParams(const SSLClientParameters& params) {
        // if mutual authentication if needed, configure bearssl to support it.
        if (params.getECKey() != NULL) {
            br_ssl_client_set_single_ec(    &m_sslctx,
                                            params.getCertChain(),
                                            1,
                                            params.getECKey(),
                                            BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN,
                                            BR_KEYTYPE_EC,
                                            br_ssl_engine_get_ec(&m_sslctx.eng),
                                            &br_ecdsa_i15_sign_asn1);
        }
        else if (params.getRSAKey() != NULL) {
            br_ssl_client_set_single_rsa(   &m_sslctx,
                                            params.getCertChain(),
                                            1,
                                            params.getRSAKey(),
                                            &br_rsa_i15_pkcs1_sign);
        }
    }

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
    inline SSLSession* getSession(const char* host)  {
        const char* func_name = __func__;
        // search for a matching session with the IP
        int temp_index = m_get_session_index(host);
        // if none are availible, use m_session_index
        if (temp_index < 0) return nullptr;
        // return the pointed to value
        m_info("Using session index: ", func_name);
        m_info(temp_index, func_name);
        return &(m_sessions[temp_index]);
    }

    /**
     * @brief Clear the session corresponding to a host and IP
     * 
     * The implementation for this function can be found at SSLClientImpl::remove_session_impl.
     * 
     * @param host A hostname c string, or nullptr if one is not available
     * @param addr An IP address
     */
    inline void removeSession(const char* host) {
        const char* func_name = __func__;
        int temp_index = m_get_session_index(host);
        if (temp_index >= 0) {
            m_info(" Deleted session ", func_name);
            m_info(temp_index, func_name);
            m_sessions.erase(m_sessions.begin() + static_cast<size_t>(temp_index));
        }
    }

    /**
     * @brief Get the maximum number of SSL sessions that can be stored at once
     *
     *  @returns The SessionCache template parameter.
     */
    inline size_t getSessionCount() const { return m_sessions.size(); }

    /** 
     * @brief Equivalent to SSLClient::connected() > 0
     * 
     * @returns true if connected, false if not
     */
	inline operator bool() { return connected() > 0; }

    /** @brief Returns a reference to the client object stored in this class. Take care not to break it. */
    inline Client& getClient() { return m_client; }

    /** 
     * @brief Set the timeout when waiting for an SSL response.
     * @param t The timeout value, in milliseconds (defaults to 30 seconds if not set). Do not set to zero.
     */
	inline void setTimeout(unsigned int t) { m_timeout = t; }

    /** 
     * @brief Get the timeout when waiting for an SSL response.
     * @returns The timeout value in milliseconds.
     */
    inline unsigned int getTimeout() const { return m_timeout; }

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
    inline void setVerificationTime(uint32_t days, uint32_t seconds) {
        br_x509_minimal_set_time(&m_x509ctx, days, seconds);
    }

private:
    /** @brief Returns an instance of m_client that is polymorphic and can be used by SSLClientImpl */
    inline Client& get_arduino_client() { return m_client; }
    inline const Client& get_arduino_client() const { return m_client; }

    /** Returns whether or not the engine is connected, without polling the client over SPI or other (as opposed to connected()) */
    inline bool m_soft_connected(const char* func_name) {
        // check if the socket is still open and such
        if (getWriteError()) {
            m_error("Cannot operate if the write error is not reset: ", func_name); 
            m_print_ssl_error(getWriteError(), SSLDebugLevel::SSL_ERROR);
            return false;
        }
        // check if the ssl engine is still open
        if(!m_is_connected || br_ssl_engine_current_state(&m_sslctx.eng) == BR_SSL_CLOSED) {
            m_error("Cannot operate on a closed SSL connection.", func_name);
            int error = br_ssl_engine_last_error(&m_sslctx.eng);
            if(error != BR_ERR_OK) m_print_br_error(error, SSLDebugLevel::SSL_ERROR);   
            return false;
        }
        return true;
    }

    /** start the ssl engine on the connected client */
    inline int m_start_ssl(const char* host = nullptr, SSLSession* ssl_ses = nullptr) {
        const char* func_name = __func__;
        // clear the write error
        setWriteError(static_cast<std::underlying_type<SSLError>::type>(SSLError::SSL_OK));
        // get some random data by reading the analog pin we've been handed
        // we want 128 bits to be safe, as recommended by the bearssl docs
        uint8_t rng_seeds[16];
        // take the bottom 8 bits of the analog read
        for (uint8_t i = 0; i < sizeof rng_seeds; i++) 
            rng_seeds[i] = static_cast<uint8_t>(analogRead(m_analog_pin));
        br_ssl_engine_inject_entropy(&m_sslctx.eng, rng_seeds, sizeof rng_seeds);
        // inject session parameters for faster reconnection, if we have any
        if(ssl_ses != nullptr) {
            br_ssl_engine_set_session_parameters(&m_sslctx.eng, ssl_ses->to_br_session());
            m_info("Set SSL session!", func_name);
        }
        // reset the engine, but make sure that it reset successfully
        int ret = br_ssl_client_reset(&m_sslctx, host, 1);
        if (!ret) {
            m_error("Reset of bearSSL failed (is bearssl setup properly?)", func_name);
            m_print_br_error(br_ssl_engine_last_error(&m_sslctx.eng), SSLDebugLevel::SSL_ERROR);
            setWriteError(static_cast<std::underlying_type<SSLError>::type>(SSLError::SSL_BR_CONNECT_FAIL));
            return 0;
        }
        // initialize the SSL socket over the network
        // normally this would happen in write, but I think it makes
        // a little more structural sense to put it here
        if (m_run_until(BR_SSL_SENDAPP) < 0) {
	    	m_error("Failed to initlalize the SSL layer", func_name);
            m_print_br_error(br_ssl_engine_last_error(&m_sslctx.eng), SSLDebugLevel::SSL_ERROR);
            return 0;
	    }
        m_info("Connection successful!", func_name);
        m_is_connected = true;
        // all good to go! the SSL socket should be up and running
        // overwrite the session we got with new parameters
        if (ssl_ses != nullptr)
            br_ssl_engine_get_session_parameters(&m_sslctx.eng, ssl_ses->to_br_session());
        else if (host != nullptr) {
            if (m_sessions.size() >= m_max_sessions)
                m_sessions.erase(m_sessions.begin());
            SSLSession session(host);
            br_ssl_engine_get_session_parameters(&m_sslctx.eng, session.to_br_session());
            m_sessions.push_back(session);
        }
        return 1;
    }

    /** run the bearssl engine until a certain state */
    inline int m_run_until(const unsigned target) {
        const char* func_name = __func__;
        unsigned lastState = 0;
        size_t lastLen = 0;
        const unsigned long start = millis();
        for (;;) {
            unsigned state = m_update_engine();
	        // error check
            if (state == BR_SSL_CLOSED || getWriteError() != static_cast<std::underlying_type<SSLError>::type>(SSLError::SSL_OK)) {
                if (state == BR_SSL_CLOSED) {
                    m_warn("Terminating because the ssl engine closed", func_name);
                }
                else {
                    m_warn("Terminating with write error: ", func_name);
                    m_warn(getWriteError(), func_name);
                }
                return -1;
            }
            // timeout check
            if (millis() - start > getTimeout()) {
                m_error("SSL internals timed out! This could be an internal error, bad data sent from the server, or data being discarded due to a buffer overflow. If you are using Ethernet, did you modify the library properly (see README)?", func_name);
                setWriteError(static_cast<std::underlying_type<SSLError>::type>(SSLError::SSL_BR_WRITE_ERROR));
                stop();
                return -1;
            }
            // debug
            if (state != lastState || lastState == 0) {
                lastState = state;
                m_info("m_run changed state:", func_name);
                m_print_br_state(state, SSLDebugLevel::SSL_INFO);
            }
            if (state & BR_SSL_RECVREC) {
                size_t len;
                br_ssl_engine_recvrec_buf(&m_sslctx.eng, &len);
                if (lastLen != len) {
                    m_info("Expected bytes count: ", func_name);
                    m_info(lastLen = len, func_name);
                }
            }
            /*
	    	 * If we reached our target, then we are finished.
	    	 */
	    	if (state & target || (target == 0 && state == 0)) return 0;

	    	/*
	    	 * If some application data must be read, and we did not
	    	 * exit, then this means that we are trying to write data,
	    	 * and that's not possible until the application data is
	    	 * read. This may happen if using a shared in/out buffer,
	    	 * and the underlying protocol is not strictly half-duplex.
	    	 * Normally this would be unrecoverable, however we can attempt
             * to remedy the problem by telling the engine to discard 
             * the data.
	    	 */
	    	if (state & BR_SSL_RECVAPP && target & BR_SSL_SENDAPP) {
                size_t len;
                if (br_ssl_engine_recvapp_buf(&m_sslctx.eng, &len) != nullptr) {
                    m_write_idx = 0;
                    m_warn("Discarded unread data to favor a write operation", func_name);
                    br_ssl_engine_recvapp_ack(&m_sslctx.eng, len);
                    continue;
                }
                else {
                    m_error("SSL engine state is RECVAPP, however the buffer was null! (This is a problem with BearSSL internals)", func_name);
                    setWriteError(static_cast<std::underlying_type<SSLError>::type>(SSLError::SSL_BR_WRITE_ERROR));
                    stop();
                    return -1;
                }
            }

	    	/*
	    	 * We can reach that point if the target RECVAPP, and
	    	 * the state contains SENDAPP only. This may happen with
	    	 * a shared in/out buffer. In that case, we must flush
	    	 * the buffered data to "make room" for a new incoming
	    	 * record.
	    	 */
	    	if (state & BR_SSL_SENDAPP && target & BR_SSL_RECVAPP) br_ssl_engine_flush(&m_sslctx.eng, 0);
        }
    }

    /** proxy for available that returns the state */
    inline unsigned m_update_engine() {
        const char* func_name = __func__;
        for (;;) {
            // get the state
            unsigned state = br_ssl_engine_current_state(&m_sslctx.eng);
            // debug
            if (m_br_last_state == 0 || state != m_br_last_state) {
                m_br_last_state = state;
                m_print_br_state(state, SSLDebugLevel::SSL_INFO);
            }
            if (state & BR_SSL_CLOSED) return state;
            /*
            * If there is some record data to send, do it. This takes
            * precedence over everything else.
            */
            if (state & BR_SSL_SENDREC) {
                unsigned char *buf;
                size_t len;
                int wlen;

                buf = br_ssl_engine_sendrec_buf(&m_sslctx.eng, &len);
                wlen = get_arduino_client().write(buf, len);
                get_arduino_client().flush();
                if (wlen <= 0) {
                    // if the arduino client encountered an error
                    if (get_arduino_client().getWriteError() || !get_arduino_client().connected()) {
                        m_error("Error writing to m_client", func_name);
                        m_error(get_arduino_client().getWriteError(), func_name);
                        setWriteError(static_cast<std::underlying_type<SSLError>::type>(SSLError::SSL_CLIENT_WRTIE_ERROR));
                    }
                    // else presumably the socket just closed itself, so just stop the engine
                    stop();
                    return 0;
                }
                if (wlen > 0) {
                    br_ssl_engine_sendrec_ack(&m_sslctx.eng, wlen);
                }
	        continue;
            }

            /*
             * If the client has specified there is client data to send, and 
             * the engine is ready to handle it, send it along.
             */
            if (m_write_idx > 0) {
                // if we've reached the point where BR_SSL_SENDAPP is off but
                // data has been written to the io buffer, something is wrong
                if (!(state & BR_SSL_SENDAPP)) {
                    m_error("Error m_write_idx > 0 but the ssl engine is not ready for data", func_name);
                    m_error(br_ssl_engine_current_state(&m_sslctx.eng), func_name);
                    m_error(br_ssl_engine_last_error(&m_sslctx.eng), func_name);
                    setWriteError(static_cast<std::underlying_type<SSLError>::type>(SSLError::SSL_BR_WRITE_ERROR));
                    stop();
                    return 0;
                }
                // else time to send the application data
                else if (state & BR_SSL_SENDAPP) {
	                size_t alen;
                    unsigned char *buf = br_ssl_engine_sendapp_buf(&m_sslctx.eng, &alen);
                    // engine check
                    if (alen == 0 || buf == nullptr) {
                        m_error("Engine set write flag but returned null buffer", func_name);
                        setWriteError(static_cast<std::underlying_type<SSLError>::type>(SSLError::SSL_BR_WRITE_ERROR));
                        stop();
                        return 0;
                    }
                    // sanity check
                    if (alen < m_write_idx) {
                        m_error("Alen is less than m_write_idx", func_name);
                        setWriteError(static_cast<std::underlying_type<SSLError>::type>(SSLError::SSL_INTERNAL_ERROR));
                        stop();
                        return 0;
                    }
                    // all good? lets send the data
                    // presumably the SSLClient::write function has already added
                    // data to *buf, so now we tell bearssl it's time for the
                    // encryption step.
                    // this will encrypt the data and presumably spit it out
                    // for BR_SSL_SENDREC to send over ethernet.
                    br_ssl_engine_sendapp_ack(&m_sslctx.eng, m_write_idx);
                    // reset the iobuffer index
                    m_write_idx = 0;
                    // loop again!
                    continue;
                }
            }

            /*
             * If there is some record data to recieve, check if we've
             * recieved it so far. If we have, then we can update the state.
             * else we can return that we're still waiting for the server.
             */
            if (state & BR_SSL_RECVREC) {
	    		size_t len;
	    		unsigned char * buf = br_ssl_engine_recvrec_buf(&m_sslctx.eng, &len);
                // do we have the record you're looking for?
                const auto avail = get_arduino_client().available();
                if (avail > 0) {
                    // I suppose so!
                    int rlen = get_arduino_client().read(buf, avail < len ? avail : len);
                    if (rlen <= 0) {
                        m_error("Error reading bytes from m_client. Write Error: ", func_name);
                        m_error(get_arduino_client().getWriteError(), func_name);
                        setWriteError(static_cast<std::underlying_type<SSLError>::type>(SSLError::SSL_CLIENT_WRTIE_ERROR));
                        stop();
                        return 0;
                    }
                    if (rlen > 0) {
                        br_ssl_engine_recvrec_ack(&m_sslctx.eng, rlen);
                    }
                    continue;
                }
                // guess not, tell the state we're waiting still
	    		else {
                    // m_print("Bytes avail: ");
                    // m_print(avail);
                    // m_print("Bytes needed: ");
                    // m_print(len);
                    // add a delay since spamming get_arduino_client().availible breaks the poor wiz chip
                    delay(10);
                    return state;
                }
            }
            // if it's not any of the above states, then it must be waiting to send or recieve app data
            // in which case we return 
            return state;
        }
    }

    /** utility function to find a session index based off of a host and IP */
    inline int m_get_session_index(const char* host) const {
        const char* func_name = __func__;
        if (host == nullptr) return -1;
        // search for a matching session with the IP
        for (uint8_t i = 0; i < getSessionCount(); i++) {
            // if we're looking at a real session
            if (m_sessions[i].get_hostname().equals(host)) {
                m_info(m_sessions[i].get_hostname(), func_name);
                return i;
            }
        }
        // none found
        return -1;
    }

    /** @brief Prints a debugging prefix to all logs, so we can attatch them to useful information */
    inline void m_print_prefix(const char* func_name, const SSLDebugLevel level) const {
        // print the sslclient prefix
        Serial.print("(SSLClient)");
        // print the debug level
        switch (level) {
            case SSLDebugLevel::SSL_INFO: Serial.print("(SSL_INFO)"); break;
            case SSLDebugLevel::SSL_WARN: Serial.print("(SSL_WARN)"); break;
            case SSLDebugLevel::SSL_ERROR: Serial.print("(SSL_ERROR)"); break;
            default: Serial.print("(Unknown level)");
        }
        // print the function name
        Serial.print("(");
        Serial.print(func_name);
        Serial.print("): ");
    }

    /** @brief Prints the string associated with a write error */
    inline void m_print_ssl_error(const int ssl_error, const SSLDebugLevel level) const {
        if (level > m_debug) return;
        m_print_prefix(__func__, level);
        switch (static_cast<SSLError>(ssl_error)) {
            case SSLError::SSL_OK: Serial.println("SSL_OK"); break;
            case SSLError::SSL_CLIENT_CONNECT_FAIL: Serial.println("SSL_CLIENT_CONNECT_FAIL"); break;
            case SSLError::SSL_BR_CONNECT_FAIL: Serial.println("SSL_BR_CONNECT_FAIL"); break;
            case SSLError::SSL_CLIENT_WRTIE_ERROR: Serial.println("SSL_CLIENT_WRITE_FAIL"); break;
            case SSLError::SSL_BR_WRITE_ERROR: Serial.println("SSL_BR_WRITE_ERROR"); break;
            case SSLError::SSL_INTERNAL_ERROR: Serial.println("SSL_INTERNAL_ERROR"); break;
            case SSLError::SSL_OUT_OF_MEMORY: Serial.println("SSL_OUT_OF_MEMORY"); break;
        }
    }

    /** @brief Print the text string associated with a BearSSL error code */
    inline void m_print_br_error(const unsigned br_error_code, const SSLDebugLevel level) const {
        if (level > m_debug) return;
        m_print_prefix(__func__, level);
        switch (br_error_code) {
            case BR_ERR_BAD_PARAM: Serial.println("Caller-provided parameter is incorrect."); break;
            case BR_ERR_BAD_STATE: Serial.println("Operation requested by the caller cannot be applied with the current context state (e.g. reading data while outgoing data is waiting to be sent)."); break;
            case BR_ERR_UNSUPPORTED_VERSION: Serial.println("Incoming protocol or record version is unsupported."); break;
            case BR_ERR_BAD_VERSION: Serial.println("Incoming record version does not match the expected version."); break;
            case BR_ERR_BAD_LENGTH: Serial.println("Incoming record length is invalid."); break;
            case BR_ERR_TOO_LARGE: Serial.println("Incoming record is too large to be processed, or buffer is too small for the handshake message to send."); break;
            case BR_ERR_BAD_MAC: Serial.println("Decryption found an invalid padding, or the record MAC is not correct."); break;
            case BR_ERR_NO_RANDOM: Serial.println("No initial entropy was provided, and none can be obtained from the OS."); break;
            case BR_ERR_UNKNOWN_TYPE: Serial.println("Incoming record type is unknown."); break;
            case BR_ERR_UNEXPECTED: Serial.println("Incoming record or message has wrong type with regards to the current engine state."); break;
            case BR_ERR_BAD_CCS: Serial.println("ChangeCipherSpec message from the peer has invalid contents."); break;
            case BR_ERR_BAD_ALERT: Serial.println("Alert message from the peer has invalid contents (odd length)."); break;
            case BR_ERR_BAD_HANDSHAKE: Serial.println("Incoming handshake message decoding failed."); break;
            case BR_ERR_OVERSIZED_ID: Serial.println("ServerHello contains a session ID which is larger than 32 bytes."); break;
            case BR_ERR_BAD_CIPHER_SUITE: Serial.println("Server wants to use a cipher suite that we did not claim to support. This is also reported if we tried to advertise a cipher suite that we do not support."); break;
            case BR_ERR_BAD_COMPRESSION: Serial.println("Server wants to use a compression that we did not claim to support."); break;
            case BR_ERR_BAD_FRAGLEN: Serial.println("Server's max fragment length does not match client's."); break;
            case BR_ERR_BAD_SECRENEG: Serial.println("Secure renegotiation failed."); break;
            case BR_ERR_EXTRA_EXTENSION: Serial.println("Server sent an extension type that we did not announce, or used the same extension type several times in a single ServerHello."); break;
            case BR_ERR_BAD_SNI: Serial.println("Invalid Server Name Indication contents (when used by the server, this extension shall be empty)."); break;
            case BR_ERR_BAD_HELLO_DONE: Serial.println("Invalid ServerHelloDone from the server (length is not 0)."); break;
            case BR_ERR_LIMIT_EXCEEDED: Serial.println("Internal limit exceeded (e.g. server's public key is too large)."); break;
            case BR_ERR_BAD_FINISHED: Serial.println("Finished message from peer does not match the expected value."); break;
            case BR_ERR_RESUME_MISMATCH: Serial.println("Session resumption attempt with distinct version or cipher suite."); break;
            case BR_ERR_INVALID_ALGORITHM: Serial.println("Unsupported or invalid algorithm (ECDHE curve, signature algorithm, hash function)."); break;
            case BR_ERR_BAD_SIGNATURE: Serial.println("Invalid signature in ServerKeyExchange or CertificateVerify message."); break;
            case BR_ERR_WRONG_KEY_USAGE: Serial.println("Peer's public key does not have the proper type or is not allowed for the requested operation."); break;
            case BR_ERR_NO_CLIENT_AUTH: Serial.println("Client did not send a certificate upon request, or the client certificate could not be validated."); break;
            case BR_ERR_IO: Serial.println("I/O error or premature close on transport stream."); break;
            case BR_ERR_X509_INVALID_VALUE: Serial.println("Invalid value in an ASN.1 structure."); break;
            case BR_ERR_X509_TRUNCATED: Serial.println("Truncated certificate or other ASN.1 object."); break;
            case BR_ERR_X509_EMPTY_CHAIN: Serial.println("Empty certificate chain (no certificate at all)."); break;
            case BR_ERR_X509_INNER_TRUNC: Serial.println("Decoding error: inner element extends beyond outer element size."); break;
            case BR_ERR_X509_BAD_TAG_CLASS: Serial.println("Decoding error: unsupported tag class (application or private)."); break;
            case BR_ERR_X509_BAD_TAG_VALUE: Serial.println("Decoding error: unsupported tag value."); break;
            case BR_ERR_X509_INDEFINITE_LENGTH: Serial.println("Decoding error: indefinite length."); break;
            case BR_ERR_X509_EXTRA_ELEMENT: Serial.println("Decoding error: extraneous element."); break;
            case BR_ERR_X509_UNEXPECTED: Serial.println("Decoding error: unexpected element."); break;
            case BR_ERR_X509_NOT_CONSTRUCTED: Serial.println("Decoding error: expected constructed element, but is primitive."); break;
            case BR_ERR_X509_NOT_PRIMITIVE: Serial.println("Decoding error: expected primitive element, but is constructed."); break;
            case BR_ERR_X509_PARTIAL_BYTE: Serial.println("Decoding error: BIT STRING length is not multiple of 8."); break;
            case BR_ERR_X509_BAD_BOOLEAN: Serial.println("Decoding error: BOOLEAN value has invalid length."); break;
            case BR_ERR_X509_OVERFLOW: Serial.println("Decoding error: value is off-limits."); break;
            case BR_ERR_X509_BAD_DN: Serial.println("Invalid distinguished name."); break;
            case BR_ERR_X509_BAD_TIME: Serial.println("Invalid date/time representation."); break;
            case BR_ERR_X509_UNSUPPORTED: Serial.println("Certificate contains unsupported features that cannot be ignored."); break;
            case BR_ERR_X509_LIMIT_EXCEEDED: Serial.println("Key or signature size exceeds internal limits."); break;
            case BR_ERR_X509_WRONG_KEY_TYPE: Serial.println("Key type does not match that which was expected."); break;
            case BR_ERR_X509_BAD_SIGNATURE: Serial.println("Signature is invalid."); break;
            case BR_ERR_X509_TIME_UNKNOWN: Serial.println("Validation time is unknown."); break;
            case BR_ERR_X509_EXPIRED: Serial.println("Certificate is expired or not yet valid."); break;
            case BR_ERR_X509_DN_MISMATCH: Serial.println("Issuer/Subject DN mismatch in the chain."); break;
            case BR_ERR_X509_BAD_SERVER_NAME: Serial.println("Expected server name was not found in the chain."); break;
            case BR_ERR_X509_CRITICAL_EXTENSION: Serial.println("Unknown critical extension in certificate."); break;
            case BR_ERR_X509_NOT_CA: Serial.println("Not a CA, or path length constraint violation."); break;
            case BR_ERR_X509_FORBIDDEN_KEY_USAGE: Serial.println("Key Usage extension prohibits intended usage."); break;
            case BR_ERR_X509_WEAK_PUBLIC_KEY: Serial.println("Public key found in certificate is too small."); break;
            case BR_ERR_X509_NOT_TRUSTED: Serial.println("Chain could not be linked to a trust anchor. See https://github.com/OPEnSLab-OSU/SSLClient/blob/master/TrustAnchors.md"); break;
            case 296: Serial.println("Server denied access (did you setup mTLS correctly?)"); break;
            default: Serial.print("Unknown error code: "); Serial.println(br_error_code); break;
        }
    }

    /** @brief Print the text string associated with the BearSSL state */
    inline void m_print_br_state(const unsigned br_state, const SSLDebugLevel level) const {
        const char* func_name = __func__;
        if (level > m_debug) return;
        m_print_prefix(func_name, level);
        m_info("State: ", func_name);
        if (br_state == 0) Serial.println("    Invalid");
        else if (br_state & BR_SSL_CLOSED) Serial.println("   Connection closed");
        else {
            if (br_state & BR_SSL_SENDREC) Serial.println("   SENDREC");
            if (br_state & BR_SSL_RECVREC) Serial.println("   RECVREC");
            if (br_state & BR_SSL_SENDAPP) Serial.println("   SENDAPP");
            if (br_state & BR_SSL_RECVAPP) Serial.println("   RECVAPP");
        }
    }

    /** @brief debugging print function, only prints if m_debug is true */
    template<typename T>
    void m_print(const T str, const char* func_name, const SSLDebugLevel level) const { 
        // check the current debug level and serial status
        if (level > m_debug || !Serial) return;
        // print prefix
        m_print_prefix(func_name, level);
        // print the message
        Serial.println(str);
    }

    /** @brief Prints a info message to serial, if info messages are enabled */
    template<typename T>
    void m_info(const T str, const char* func_name) const { m_print(str, func_name, SSLDebugLevel::SSL_INFO); }

    template<typename T>
    void m_warn(const T str, const char* func_name) const { m_print(str, func_name, SSLDebugLevel::SSL_WARN); }

    template<typename T>
    void m_error(const T str, const char* func_name) const { m_print(str, func_name, SSLDebugLevel::SSL_ERROR); }

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
    const SSLDebugLevel m_debug;
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
    unsigned char m_iobuf[BufferSize];
    // store the index of where we are writing in the buffer
    // so we can send our records all at once to prevent
    // weird timing issues
    size_t m_write_idx;
    // store the last BearSSL state so we can print changes to the console
    unsigned m_br_last_state;
};

// Using statement to prevent breaking API changes
// and make simply creating a SSLClient without any template arguments possible.
using SSLClient = SSLClientSized<>;

#endif /** SSLClient_H_ */

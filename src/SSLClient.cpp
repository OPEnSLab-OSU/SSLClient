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

#include "SSLClient.h"

/* see SSLClient.h */
SSLClient::SSLClient(   Client& client, 
                        const br_x509_trust_anchor *trust_anchors, 
                        const size_t trust_anchors_num, 
                        const int analog_pin, 
                        const size_t max_sessions,
                        const DebugLevel debug)
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

/* see SSLClient.h*/
int SSLClient::connect(IPAddress ip, uint16_t port) {
    const char* func_name = __func__;
    // connection check
    if (get_arduino_client().connected())
        m_warn("Arduino client is already connected? Continuing anyway...", func_name);
    // reset indexs for saftey
    m_write_idx = 0;
    // Warning for security
    m_warn("Using a raw IP Address for an SSL connection bypasses some important verification steps. You should use a domain name (www.google.com) whenever possible.", func_name);
    // first we need our hidden client member to negotiate the socket for us,
    // since most times socket functionality is implemented in hardeware.
    if (!get_arduino_client().connect(ip, port)) {
        m_error("Failed to connect using m_client. Are you connected to the internet?", func_name);
        setWriteError(SSL_CLIENT_CONNECT_FAIL);
        return 0;
    }
    m_info("Base client connected!", func_name);
    return m_start_ssl(nullptr);
}

/* see SSLClient.h*/
int SSLClient::connect(const char *host, uint16_t port) {
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
        setWriteError(SSL_CLIENT_CONNECT_FAIL);
        return 0;
    }
    m_info("Base client connected!", func_name);
    // start ssl!
    return m_start_ssl(host, getSession(host));
}

/* see SSLClient.h*/
size_t SSLClient::write(const uint8_t *buf, size_t size) {
    const char* func_name = __func__;
    // super debug
    if (m_debug >= DebugLevel::SSL_DUMP) Serial.write(buf, size);
    // check if the socket is still open and such
    if (!m_soft_connected(func_name) || !buf || !size) return 0;
    // add to the bearssl io buffer, simply appending whatever we want to write
    size_t alen;
    unsigned char *br_buf = br_ssl_engine_sendapp_buf(&m_sslctx.eng, &alen);
    size_t cur_idx = 0;
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

/* see SSLClient.h*/
int SSLClient::available() {
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

/* see SSLClient.h */
int SSLClient::read(uint8_t *buf, size_t size) {
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

/* see SSLClient.h */
int SSLClient::peek() {
    // check that the engine is ready to read
    if (available() <= 0) return -1; 
    // read the buffer, send the ack, and return the bytes read
    size_t alen;
    uint8_t read_num;
    read_num = br_ssl_engine_recvapp_buf(&m_sslctx.eng, &alen)[0];
    // tell the user we read that many bytes
    return (int)read_num;
}

/* see SSLClient.h */
void SSLClient::flush() {
    if (m_write_idx > 0) {
        if(m_run_until(BR_SSL_RECVAPP) < 0) {
            m_error("Could not flush write buffer!", __func__);
            int error = br_ssl_engine_last_error(&m_sslctx.eng);
            if(error != BR_ERR_OK) 
                m_print_br_error(error, SSL_ERROR);
            if (getWriteError()) 
                m_print_ssl_error(getWriteError(), SSL_ERROR);
        }
    }
}

/* see SSLClient.h */
void SSLClient::stop() {
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

/* see SSLClient.h */
uint8_t SSLClient::connected() {
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
            setWriteError(SSL_CLIENT_WRTIE_ERROR);
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
        m_print_ssl_error(getWriteError(), SSL_ERROR);
    }
    return c_con && br_con;
}

/* see SSLClient.h */
SSLSession* SSLClient::getSession(const char* host) {
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

/* see SSLClient.h */
void SSLClient::removeSession(const char* host) {
    const char* func_name = __func__;
    int temp_index = m_get_session_index(host);
    if (temp_index >= 0) {
        m_info(" Deleted session ", func_name);
        m_info(temp_index, func_name);
        m_sessions.erase(m_sessions.begin() + static_cast<size_t>(temp_index));
    }
}

/* see SSLClient.h */
void SSLClient::setMutualAuthParams(const SSLClientParameters& params) {
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

/* see SSLClient.h */
void SSLClient::setVerificationTime(uint32_t days, uint32_t seconds) {
    br_x509_minimal_set_time(&m_x509ctx, days, seconds);
}

bool SSLClient::m_soft_connected(const char* func_name) {
    // check if the socket is still open and such
    if (getWriteError()) {
        m_error("Cannot operate if the write error is not reset: ", func_name); 
        m_print_ssl_error(getWriteError(), SSL_ERROR);
        return false;
    }
    // check if the ssl engine is still open
    if(!m_is_connected || br_ssl_engine_current_state(&m_sslctx.eng) == BR_SSL_CLOSED) {
        m_error("Cannot operate on a closed SSL connection.", func_name);
        int error = br_ssl_engine_last_error(&m_sslctx.eng);
        if(error != BR_ERR_OK) m_print_br_error(error, SSL_ERROR);   
        return false;
    }
    return true;
}

/* see SSLClient.h */
int SSLClient::m_start_ssl(const char* host, SSLSession* ssl_ses) {
    const char* func_name = __func__;
    // clear the write error
    setWriteError(SSL_OK);
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
        m_print_br_error(br_ssl_engine_last_error(&m_sslctx.eng), SSL_ERROR);
        setWriteError(SSL_BR_CONNECT_FAIL);
        return 0;
    }
    // initialize the SSL socket over the network
    // normally this would happen in write, but I think it makes
    // a little more structural sense to put it here
    if (m_run_until(BR_SSL_SENDAPP) < 0) {
		m_error("Failed to initlalize the SSL layer", func_name);
        m_print_br_error(br_ssl_engine_last_error(&m_sslctx.eng), SSL_ERROR);
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

/* see SSLClient.h */
int SSLClient::m_run_until(const unsigned target) {
    const char* func_name = __func__;
    unsigned lastState = 0;
    size_t lastLen = 0;
    const unsigned long start = millis();
    for (;;) {
        unsigned state = m_update_engine();
	    // error check
        if (state == BR_SSL_CLOSED || getWriteError() != SSL_OK) {
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
            setWriteError(SSL_BR_WRITE_ERROR);
            stop();
            return -1;
        }
        // debug
        if (state != lastState || lastState == 0) {
            lastState = state;
            m_info("m_run changed state:", func_name);
            m_print_br_state(state, DebugLevel::SSL_INFO);
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
                setWriteError(SSL_BR_WRITE_ERROR);
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

/* see SSLClient.h*/
unsigned SSLClient::m_update_engine() {
    const char* func_name = __func__;
    for(;;) {
        // get the state
        unsigned state = br_ssl_engine_current_state(&m_sslctx.eng);
        // debug
        if (m_br_last_state == 0 || state != m_br_last_state) {
            m_br_last_state = state;
            m_print_br_state(state, DebugLevel::SSL_INFO);
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
                    setWriteError(SSL_CLIENT_WRTIE_ERROR);
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
                setWriteError(SSL_BR_WRITE_ERROR);
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
                    setWriteError(SSL_BR_WRITE_ERROR);
                    stop();
                    return 0;
                }
                // sanity check
                if (alen < m_write_idx) {
                    m_error("Alen is less than m_write_idx", func_name);
                    setWriteError(SSL_INTERNAL_ERROR);
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
                    setWriteError(SSL_CLIENT_WRTIE_ERROR);
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

/* see SSLClientImpl.h */
int SSLClient::m_get_session_index(const char* host) const {
    const char* func_name = __func__;
    if(host == nullptr) return -1;
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

/* See SSLClient.h */
void SSLClient::m_print_prefix(const char* func_name, const DebugLevel level) const
{
    // print the sslclient prefix
    Serial.print("(SSLClient)");
    // print the debug level
    switch (level) {
        case SSL_INFO: Serial.print("(SSL_INFO)"); break;
        case SSL_WARN: Serial.print("(SSL_WARN)"); break;
        case SSL_ERROR: Serial.print("(SSL_ERROR)"); break;
        default: Serial.print("(Unknown level)");
    }
    // print the function name
    Serial.print("(");
    Serial.print(func_name);
    Serial.print("): ");
}

/* See SSLClient.h */
void SSLClient::m_print_ssl_error(const int ssl_error, const DebugLevel level) const {
    if (level > m_debug) return;
    m_print_prefix(__func__, level);
    switch(ssl_error) {
        case SSL_OK: Serial.println("SSL_OK"); break;
        case SSL_CLIENT_CONNECT_FAIL: Serial.println("SSL_CLIENT_CONNECT_FAIL"); break;
        case SSL_BR_CONNECT_FAIL: Serial.println("SSL_BR_CONNECT_FAIL"); break;
        case SSL_CLIENT_WRTIE_ERROR: Serial.println("SSL_CLIENT_WRITE_FAIL"); break;
        case SSL_BR_WRITE_ERROR: Serial.println("SSL_BR_WRITE_ERROR"); break;
        case SSL_INTERNAL_ERROR: Serial.println("SSL_INTERNAL_ERROR"); break;
        case SSL_OUT_OF_MEMORY: Serial.println("SSL_OUT_OF_MEMORY"); break;
    }
}

/* See SSLClient.h */
void SSLClient::m_print_br_error(const unsigned br_error_code, const DebugLevel level) const {
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


void SSLClient::m_print_br_state(const unsigned state, const DebugLevel level) const {
    const char* func_name = __func__;
    if (level > m_debug) return;
    m_print_prefix(func_name, level);
    m_info("State: ", func_name);
    if(state == 0) Serial.println("    Invalid");
    else if (state & BR_SSL_CLOSED) Serial.println("   Connection closed");
    else {
        if (state & BR_SSL_SENDREC) Serial.println("   SENDREC");
        if (state & BR_SSL_RECVREC) Serial.println("   RECVREC");
        if (state & BR_SSL_SENDAPP) Serial.println("   SENDAPP");
        if (state & BR_SSL_RECVAPP) Serial.println("   RECVAPP");
    }
}
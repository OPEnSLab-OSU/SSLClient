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

/** see SSLClientImpl.h */
SSLClientImpl::SSLClientImpl(Client* client, const br_x509_trust_anchor *trust_anchors, const size_t trust_anchors_num, const int analog_pin, const bool debug)
    : m_client(client)
    , m_trust_anchors(trust_anchors)
    , m_trust_anchors_num(trust_anchors_num)
    , m_analog_pin(analog_pin)
    , m_debug(debug)
    , m_write_idx(0) {
    
    // zero the iobuf just in case it's still garbage
    memset(m_iobuf, 0, sizeof m_iobuf);
    // initlalize the various bearssl libraries so they're ready to go when we connect
    br_client_init_TLS12_only(&m_sslctx, &m_x509ctx, m_trust_anchors, m_trust_anchors_num);
    // br_ssl_client_init_full(&m_sslctx, &m_x509ctx, m_trust_anchors, m_trust_anchors_num);
    // check if the buffer size is half or full duplex
    constexpr auto duplex = sizeof m_iobuf <= BR_SSL_BUFSIZE_MONO ? 0 : 1;
    br_ssl_engine_set_buffer(&m_sslctx.eng, m_iobuf, sizeof m_iobuf, duplex);
}

/* see SSLClientImpl.h*/
int SSLClientImpl::connect(IPAddress ip, uint16_t port) {
    // reset indexs for saftey
    m_write_idx = 0;
    // Warning for security
    m_print("Warning! Using a raw IP Address for an SSL connection bypasses some important verification steps\nYou should use a domain name (www.google.com) whenever possible.");
    // first we need our hidden client member to negotiate the socket for us,
    // since most times socket functionality is implemented in hardeware.
    if (!m_client->connect(ip, port)) {
        m_print("Error: Failed to connect using m_client");
        setWriteError(SSL_CLIENT_CONNECT_FAIL);
        return 0;
    }
    m_print("Base ethernet client connected!");
    return m_start_ssl();
}

/* see SSLClientImpl.h*/
int SSLClientImpl::connect(const char *host, uint16_t port) {
    // reset indexs for saftey
    m_write_idx = 0;
    // first we need our hidden client member to negotiate the socket for us,
    // since most times socket functionality is implemented in hardeware.
    if (!m_client->connect(host, port)) {
        m_print("Error: Failed to connect using m_client");
        setWriteError(SSL_CLIENT_CONNECT_FAIL);
        return 0;
    }
    m_print("Base ethernet client connected!");
    return m_start_ssl(host);
}

/** see SSLClientImpl.h*/
size_t SSLClientImpl::write(const uint8_t *buf, size_t size) {
    // check if the socket is still open and such
    if(br_ssl_engine_current_state(&m_sslctx.eng) == BR_SSL_CLOSED || getWriteError()) {
        m_print("Client is not connected! Perhaps something has happened?");       
        return 0;
    }
    // add to the bearssl io buffer, simply appending whatever we want to write
    size_t alen;
    unsigned char *br_buf = br_ssl_engine_sendapp_buf(&m_sslctx.eng, &alen);
    size_t cur_idx = 0;
    // while there are still elements to write
    while (cur_idx < size) {
        // run until the ssl socket is ready to write, unless we've already written
        // to the buffer in which we conclude it's already safe to write
        if(m_write_idx == 0) {
            if (m_run_until(BR_SSL_SENDAPP) < 0) {
                m_print("Error: could not run until sendapp");
                setWriteError(SSL_BR_WRITE_ERROR);
                return 0;
            }
            // reset the buffer pointer
            br_ssl_engine_sendapp_buf(&m_sslctx.eng, &alen);
        }
        // sanity check
        if(br_buf == NULL || alen == 0) {
            m_print("Error: recieved null buffer or zero alen in write");
            setWriteError(SSL_BR_WRITE_ERROR);
            return 0;
        }
        // if we're about to fill the buffer, we need to send the data and then wait
        // for another oppurtinity to send
        const size_t cpamount = m_write_idx + (size - cur_idx) > alen ? alen : size - cur_idx;
        memcpy(br_buf + m_write_idx, buf + cur_idx, cpamount);
        // if we filled the buffer, reset m_write_idx
        if (cpamount == alen) m_write_idx = 0;
        // else increment
        else m_write_idx += cpamount;
        // increment the buffer pointer
        cur_idx += cpamount;
    } 
    // works oky
    return size;
}

/** see SSLClientImpl.h*/
int SSLClientImpl::available() {
    // connection check
    if (br_ssl_engine_current_state(&m_sslctx.eng) == BR_SSL_CLOSED || getWriteError()) {
        m_print("Warn: Cannot check available of disconnected client");
        return 0;
    }
    // run the SSL engine until we are waiting for either user input or a server response
    unsigned state = m_update_engine();
    if (state == 0) {
        m_print("Error: SSL engine failed: ");
        m_print(br_ssl_engine_last_error(&m_sslctx.eng));
        setWriteError(SSL_BR_WRITE_ERROR);
    }
    else if(state & BR_SSL_RECVAPP) {
        // return how many received bytes we have
        size_t alen;
        br_ssl_engine_recvapp_buf(&m_sslctx.eng, &alen);
        return (int)(alen);
    }
    else if (state == BR_SSL_CLOSED) m_print("Error: Tried to check available when engine is closed");
    // flush the buffer if it's stuck in the SENDAPP state
    else if (state & BR_SSL_SENDAPP) br_ssl_engine_flush(&m_sslctx.eng, 0);
    // other state, or client is closed
    return 0;
}

/** see SSLClientImpl.h */
int SSLClientImpl::read(uint8_t *buf, size_t size) {
    // check that the engine is ready to read
    if (available() <= 0) return -1;
    // read the buffer, send the ack, and return the bytes read
    size_t alen;
    unsigned char* br_buf = br_ssl_engine_recvapp_buf(&m_sslctx.eng, &alen);
    const size_t read_amount = size > alen ? alen : size;
    memcpy(buf, br_buf, read_amount);
    // tell engine we read that many bytes
    br_ssl_engine_recvapp_ack(&m_sslctx.eng, read_amount);
    // tell the user we read that many bytes
    return read_amount;
}

/** see SSLClientImpl.h */
int SSLClientImpl::peek() {
    // check that the engine is ready to read
    if (available() <= 0) return -1; 
    // read the buffer, send the ack, and return the bytes read
    size_t alen;
    uint8_t read_num;
    read_num = br_ssl_engine_recvapp_buf(&m_sslctx.eng, &alen)[0];
    // tell the user we read that many bytes
    return (int)read_num;
}

/** see SSLClientImpl.h*/
void SSLClientImpl::flush() {
    // trigger a flush, incase there's any leftover data
    br_ssl_engine_flush(&m_sslctx.eng, 0);
    // run until application data is ready for pickup
    if(m_run_until(BR_SSL_RECVAPP) < 0) m_print("Error: could not flush write buffer!");
}

/** see SSLClientImpl.h*/
void SSLClientImpl::stop() {
    // tell the SSL connection to gracefully close
    br_ssl_engine_close(&m_sslctx.eng);
    while (br_ssl_engine_current_state(&m_sslctx.eng) != BR_SSL_CLOSED) {
		/*
		 * Discard any incoming application data.
		 */
		size_t len;

		m_run_until(BR_SSL_RECVAPP);
		if (br_ssl_engine_recvapp_buf(&m_sslctx.eng, &len) != NULL) {
			br_ssl_engine_recvapp_ack(&m_sslctx.eng, len);
		}
	}
    // close the ethernet socket
    m_client->stop();
}

uint8_t SSLClientImpl::connected() {
    // check all of the error cases 
    const auto c_con = m_client->connected();
    const auto br_con = br_ssl_engine_current_state(&m_sslctx.eng) != BR_SSL_CLOSED;
    const auto wr_ok = getWriteError() == 0;
    // if we're in an error state, close the connection and set a write error
    if ((br_con && !c_con) || !wr_ok) {
        m_print("Error: Socket was unexpectedly interrupted");
        m_print("Terminated with: ");
        m_print(m_client->getWriteError());
        setWriteError(SSL_CLIENT_WRTIE_ERROR);
        stop();
    }
    return c_con && br_con && wr_ok;
}

/** see SSLClientImpl.h */
int SSLClientImpl::m_start_ssl(const char* host) {
    // get some random data by reading the analog pin we've been handed
    // we want 128 bits to be safe, as recommended by the bearssl docs
    uint8_t rng_seeds[16];
    // take the bottom 8 bits of the analog read
    for (uint8_t i = 0; i < sizeof rng_seeds; i++) rng_seeds[i] = static_cast<uint8_t>(analogRead(m_analog_pin));
    br_ssl_engine_inject_entropy(&m_sslctx.eng, rng_seeds, sizeof rng_seeds);
    auto ret = br_ssl_client_reset(&m_sslctx, host, 1);
    if (!ret) {
        m_print("Error: reset failed");
        m_print(br_ssl_engine_last_error(&m_sslctx.eng));
    } 
    // initlalize the SSL socket over the network
    // normally this would happen in br_sslio_write, but I think it makes
    // a little more structural sense to put it here
    if (m_run_until(BR_SSL_SENDAPP) < 0) {
		m_print("Error: Failed to initlalize the SSL layer");
        m_print(br_ssl_engine_last_error(&m_sslctx.eng));
        setWriteError(SSL_BR_CONNECT_FAIL);
        return 0;
	}
    // all good to go! the SSL socket should be up and running
    m_print("SSL Initialized");
    m_print(m_sslctx.eng.selected_protocol);
    setWriteError(SSL_OK);
    return 1;
}

/** see SSLClientImpl.h*/
int SSLClientImpl::m_run_until(const unsigned target) {
    unsigned lastState = 0;
    size_t lastLen = 0;
    for (;;) {
        unsigned state = m_update_engine();
		// error check
        if (state == BR_SSL_CLOSED || getWriteError()) {
            m_print("Error: tried to run_until when the engine is closed");
            return -1;
        }
        // debug
        if (state != lastState) {
            lastState = state;
            m_print("m_run stuck:");
            printState(state);
        }
        if (state & BR_SSL_RECVREC) {
            size_t len;
            unsigned char * buf = br_ssl_engine_recvrec_buf(&m_sslctx.eng, &len);
            if (lastLen != len) {
                m_print("Expected bytes count: ");
                m_print(lastLen = len);
            }
        }
        /*
		 * If we reached our target, then we are finished.
		 */
		if (state & target) return 0;

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
            if (br_ssl_engine_recvapp_buf(&m_sslctx.eng, &len) != NULL) {
                m_write_idx = 0;
                m_print("Warn: discarded unread data to favor a write operation");
                br_ssl_engine_recvapp_ack(&m_sslctx.eng, len);
                continue;
            }
            else {
                m_print("Error: ssl engine state is RECVAPP, however the buffer was null!");
                setWriteError(SSL_BR_WRITE_ERROR);
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

/** see SSLClientImpl.h*/
unsigned SSLClientImpl::m_update_engine() {
    for(;;) {
        // get the state
        unsigned state = br_ssl_engine_current_state(&m_sslctx.eng);
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
            wlen = m_client->write(buf, len);
            // let the chip recover
            if (wlen < 0) {
                m_print("Error writing to m_client");
                /*
                    * If we received a close_notify and we
                    * still send something, then we have our
                    * own response close_notify to send, and
                    * the peer is allowed by RFC 5246 not to
                    * wait for it.
                    */
                if (!&m_sslctx.eng.shutdown_recv) {
                   return 0;
                }
                setWriteError(SSL_BR_WRITE_ERROR);
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
                m_print("Error m_write_idx > 0 but the ssl engine is not ready for data");
                setWriteError(SSL_BR_WRITE_ERROR);
                return 0;
            }
            // else time to send the application data
            else if (state & BR_SSL_SENDAPP) {
	            size_t alen;
                unsigned char *buf = br_ssl_engine_sendapp_buf(&m_sslctx.eng, &alen);
                // engine check
                if (alen == 0 || buf == NULL) {
                    m_print("Error: engine set write flag but returned null buffer");
                    setWriteError(SSL_BR_WRITE_ERROR);
                    return 0;
                }
                // sanity check
                if (alen < m_write_idx) {
                    m_print("Error: alen is less than m_write_idx");
                    setWriteError(SSL_INTERNAL_ERROR);
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
            const auto avail = m_client->available();
            if (avail >= len) {
                m_print("Read bytes from client: ");
                m_print(avail);
                m_print(len);
                
                // I suppose so!
                int rlen = m_client->read(buf, len);
                if (rlen <= 0) {
                    m_print("Error reading bytes from m_client");
                    setWriteError(SSL_BR_WRITE_ERROR);
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
                // add a delay since spamming m_client->availible breaks the poor wiz chip
                delay(10);
                return state;
            }
        }
        // if it's not any of the above states, then it must be waiting to send or recieve app data
        // in which case we return 
        return state;
    }
}
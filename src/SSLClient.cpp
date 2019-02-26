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

/** see SSLClient.h */
SSLClient::SSLClient(const C &client, const br_x509_trust_anchor *trust_anchors, const size_t trust_anchors_num, const bool debug) {
    // initlalize the various bearssl libraries so they're ready to go when we connect
    br_client_init_TLS12_only(&m_sslctx, &m_x509ctx, m_trust_anchors, m_trust_anchors_num);
    // check if the buffer size is half or full duplex
    constexpr auto duplex = sizeof iobuf <= BR_SSL_BUFSIZE_MONO ? 0 : 1;
    br_ssl_engine_set_buffer(&m_sslctx, m_iobuf, sizeof m_iobuf, duplex);
    br_sslio_init(&m_ioctx, &m_sslctx.eng, m_readraw, NULL, m_writeraw, NULL);
}

/* see SSLClient.h */
virtual int SSLClient::connect(IPAddress ip, uint16_t port) {
    // Warning for security
    m_print("Warning! Using a raw IP Address for an SSL connection bypasses some important verification steps\nYou should use a domain name (www.google.com) whenever possible.");
    // first we need our hidden client member to negotiate the socket for us,
    // since most times socket functionality is implemented in hardeware.
    if (!this->m_client.connect(ip, port)) {
        m_print("Failed to connect using m_client");
        setWriteError(SSL_CLIENT_CONNECT_FAIL);
        return 0;
    }
    // reset the client context, and look for previous sessions
    br_ssl_client_reset(&sc, NULL, 1);
    // initlalize the SSL socket over the network
    // normally this would happen in br_sslio_write, but I think it makes
    // a little more structural sense to put it here
    if (m_run_until(ctx, BR_SSL_SENDAPP) < 0) {
		m_print("Failed to initlalize the SSL layer");
        setWriteError(SSL_BR_CONNECT_FAIL);
        return 0;
	}
    // all good to go! the SSL socket should be up and running
    m_print("SSL Initialized");
    setWriteError(SSL_OK);
    return 1;
}

/* see SSLClient.h */
virtual int SSLClient::connect(const char *host, uint16_t port) {
    // first we need our hidden client member to negotiate the socket for us,
    // since most times socket functionality is implemented in hardeware.
    if (!this->m_client.connect(host, port)) {
        m_print("Failed to connect using m_client");
        setWriteError(SSL_CLIENT_CONNECT_FAIL);
        return 0;
    }
    // reset the client context, and look for previous sessions
    br_ssl_client_reset(&sc, host, 1);
    // initlalize the SSL socket over the network
    // normally this would happen in br_sslio_write, but I think it makes
    // a little more structural sense to put it here
    if (m_run_until(BR_SSL_SENDAPP) < 0) {
		m_print("Failed to initlalize the SSL layer");
        setWriteError(SSL_BR_CONNECT_FAIL);
        return 0;
	}
    // all good to go! the SSL socket should be up and running
    m_print("SSL Initialized");
    setWriteError(SSL_OK);
    return 1;
}

/** see SSLClient.h  TODO: fix */
virtual size_t SSLClient::write(const uint8_t *buf, size_t size) {
    // check if the socket is still open and such
    if(!m_client.connected()) {
        m_print("Client is not connected! Perhaps something has happened?");
        setWriteError(SSL_CLIENT_CONNECT_FAIL);
        return 0;
    }
    // write to the ssl socket using bearssl, and error check
    const auto status = br_sslio_write_all(&m_ioctx, buf, size);
    if (status != size) {
        if (status < 0) {
            m_print("Encountered a write error:");
            if (m_client.getWriteError()) {
                m_print("m_client write error");
                setWriteError(SSL_CLIENT_WRTIE_ERROR);
            }
            else {
                m_print("bearssl write error: ");
                m_print(err = br_ssl_engine_last_error(&m_sslctx.eng));
                setWriteError(SSL_BR_WRITE_ERROR);
            }
            return 0;
        }
        m_print("Warn: Wrote less than status! Something might be wrong");
    }
    return status;
}

virtual int SSLClient::available() {
    if (!m_client.connected()) {
        m_print("Cannot check available of disconnected client!");
        return 0;
    }
    // run the SSL engine until we are waiting for either user input or a server response
    unsigned state = m_update_engine();
    if(state & BR_SSL_RECVAPP) {
        // return how many received bytes we have
        size_t alen;
        br_ssl_engine_recvapp_buf(ctx->engine, &alen);
        return (int)alen;
    }
    else if (state == BR_SSL_CLOSED) m_print("Tried to check available when engine is closed!");
    // flush the buffer if it's stuck in the SENDAPP state
    else if (state & BR_SSL_SENDAPP) br_ssl_engine_flush(m_sslctx->engine, 0);
    else if (state == 0) {
        m_print("SSL engine failed: ");
        m_print(br_ssl_engine_last_error(&m_sslctx));
        setWriteError(SSL_BR_WRITE_ERROR);
    }
    // other state, or client is closed
    return 0;
}

int SSLClient::m_run_until(const unsigned target) {
    for (;;) {
        unsigned state = m_update_engine();
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
		 * This is unrecoverable here, so we report an error.
		 */
		if (state & BR_SSL_RECVAPP && target & BR_SSL_SENDAPP) return -1;

		/*
		 * We can reach that point if the target RECVAPP, and
		 * the state contains SENDAPP only. This may happen with
		 * a shared in/out buffer. In that case, we must flush
		 * the buffered data to "make room" for a new incoming
		 * record.
		 */
		if (state & SENDAPP && target & RECVAPP) br_ssl_engine_flush(m_sslctx->engine, 0);
	}
}

unsigned SSLClient::m_update_engine() {
    for(;;) {
        // get the state
        unsigned state = br_ssl_engine_current_state(m_sslctx->engine);
        if (state & BR_SSL_CLOSED) return state;
        /*
        * If there is some record data to send, do it. This takes
        * precedence over everything else.
        */
        if (state & BR_SSL_SENDREC) {
            unsigned char *buf;
            size_t len;
            int wlen;

            buf = br_ssl_engine_sendrec_buf(ctx->engine, &len);
            wlen = m_client.write(buf, len);
            if (wlen < 0) {
                /*
                    * If we received a close_notify and we
                    * still send something, then we have our
                    * own response close_notify to send, and
                    * the peer is allowed by RFC 5246 not to
                    * wait for it.
                    */
                if (!ctx->engine->shutdown_recv) {
                    br_ssl_engine_fail(
                        ctx->engine, BR_ERR_IO);
                }
                setWriteError(SSL_BR_WRITE_ERROR);
                return 0;
            }
            if (wlen > 0) {
                br_ssl_engine_sendrec_ack(ctx->engine, wlen);
            }
            continue;
        }
        
        /*
         * If there is some record data to recieve, check if we've
         * recieved it so far. If we have, then we can update the state.
         * else we can return that we're still waiting for the server.
         */
        if (state & BR_SSL_RECVREC) {
			size_t len;
			unsigned char * buf = br_ssl_engine_recvrec_buf(ctx->engine, &len);
            // do we have the record you're looking for?
            if (m_client.available() >= len) {
                // I suppose so!
                int rlen = m_client.readBytes((char *)buf, len);
                if (rlen < 0) {
                    br_ssl_engine_fail(ctx->engine, BR_ERR_IO);
                    setWriteError(SSL_BR_WRITE_ERROR);
                    return 0;
                }
                if (rlen > 0) {
                    br_ssl_engine_recvrec_ack(ctx->engine, rlen);
                }
                continue;
            }
            // guess not, tell the state we're waiting still
			else return state;
        }
        // if it's not any of the above states, then it must be waiting to send or recieve app data
        // in which case we return 
        return state;
    }
}
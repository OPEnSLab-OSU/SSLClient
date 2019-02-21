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
    br_ssl_engine_set_buffer(&m_sslctx, m_iobuf, sizeof m_iobuf, 0);
    br_sslio_init(&m_ioctx, &m_sslctx.eng, m_readraw, NULL, m_writeraw, NULL);
}

/* see SSLClient.h */
virtual int SSLClient::connect(IPAddress ip, uint16_t port) {
    // Warning for security
    m_print("Warning! Using a raw IP Address for an SSL connection bypasses some important verification steps\nYou should use a domain name (www.google.com) whenever possible.")
    // first we need our hidden client member to negotiate the socket for us,
    // since most times socket functionality is implemented in hardeware.
    if (!this->m_client.connect(ip, port)) {
        m_print("Failed to connect using m_client");
        return 0;
    }
    // reset the client context, and look for previous sessions
    // in this case we also provide NULL host since we only have an IP
    br_ssl_client_reset(&sc, NULL, 1);
    // initlalize the SSL socket over the network
    // normally this would happen in br_sslio_write, but I think it makes
    // a little more structural sense to put it here
    if (br_run_until(ctx, BR_SSL_SENDAPP) < 0) {
		m_print("Failed to initlalize the SSL layer");
        return 0;
	}
    // all good to go! the SSL socket should be up and running
    m_print("SSL Initialized");
    return 1;
}

/* see SSLClient.h */
virtual int SSLClient::connect(const char *host, uint16_t port) {
    // first we need our hidden client member to negotiate the socket for us,
    // since most times socket functionality is implemented in hardeware.
    if (!this->m_client.connect(host, port)) {
        m_print("Failed to connect using m_client");
        return 0;
    }
    // reset the client context, and look for previous sessions
    br_ssl_client_reset(&sc, host, 1);
    // initlalize the SSL socket over the network
    // normally this would happen in br_sslio_write, but I think it makes
    // a little more structural sense to put it here
    if (br_run_until(ctx, BR_SSL_SENDAPP) < 0) {
		m_print("Failed to initlalize the SSL layer");
        return 0;
	}
    // all good to go! the SSL socket should be up and running
    m_print("SSL Initialized");
    return 1;
}

virtual size_t SSLClient::write(const uint8_t *buf, size_t size) {
    // check if the socket is still open and such
    
    // write to the ssl socket using bearssl, and error check
    int status = br_sslio_write_all(&m_ioctx, buf, len);
    if (status < 0 ) 
}
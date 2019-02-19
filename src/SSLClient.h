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

public:

    /** Ctor
     * Creates a new dynamically allocated Client object based on the
     * one passed to client
     * We copy the client because we aren't sure the Client object
     * is going to exists past the inital creation of the SSLClient.
     * @param client the (Ethernet)client object
     */
    SSLClient(const C &client):
        m_client(client)
    {
    }

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
    virtual int connect(IPAddress ip, uint16_t port);
	virtual int connect(const char *host, uint16_t port);
    virtual size_t write(uint8_t);
	virtual size_t write(const uint8_t *buf, size_t size);
	virtual int available();
	virtual int read();
	virtual int read(uint8_t *buf, size_t size);
	virtual int peek();
	virtual void flush();
	virtual void stop();
	virtual uint8_t connected();
    
    /** get the client object */
    C& getClient() { return m_client; }

private:
    // create a copy of the class
    C m_client;
};

#endif /** SSLClient_H_ */
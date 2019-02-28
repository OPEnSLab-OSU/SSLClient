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
 * 
 * This file specifically controls the class templating used to allow SSLClient to interface
 * with all of the CLient-based classes. To see details on the implementations of the functions
 * in SSLClient, please see {@link ./SSLClientImpl.h}.
 */

#include <type_traits>
#include "Client.h"
#include "SSLClientImpl.h"

#ifndef SSLClient_H_
#define SSLClient_H_

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
    SSL_INTERNAL_ERROR
};

/**
 * \brief This class serves as a templating proxy class for the SSLClientImpl to do the real work.
 * 
 * A problem arose when writing this class: I wanted the user to be able to construct
 * this class in a single line of code (e.g. SSLClient(EthernetClient())), but I also
 * wanted to avoid the use of dynamic memory if possible. In an attempt to solve this
 * problem I used a templated classes. However, becuase of the Arduino build process 
 * this meant that the implementations for all the functions had to be in a header 
 * file (a weird effect of using templated classes and linking) which would slow down
 * the build quite a bit. As a comprimise, I instead decided to build the main class (SSLCLient)
 * as a templated class, and have use a not templated implementation class (SSLClientImpl)
 * that would be able to reside in a seperate file. This gets the best of both worlds
 * from the client side, however from the developer side it can be a bit confusing.
 */

template <class C>
class SSLClient : public SSLClientImpl {
/** static type checks
 * I'm a java developer, so I want to ensure that my inheritance is safe.
 * These checks ensure that all the functions we use on class C are
 * actually present on class C. It does this by first checking that the
 * class inherits from Client, and then that it contains a status() function.
 */
static_assert(std::is_base_of<Client, C>::value, "C must be a Client Class!");
// static_assert(std::is_function<decltype(C::status)>::value, "C must have a status() function!");

public:
    /**
     * @brief copies the client object, and passes the various parameters to the SSLCLientImpl functions.
     * 
     * We copy the client because we aren't sure the Client object
     * is going to exists past the inital creation of the SSLClient.
     * 
     * @pre The client class must be able to access the internet, as SSLClient
     * cannot manage this for you. Additionally it is recommended that the analog_pin
     * be set to input.
     * 
     * @param trust_anchors Trust anchors used in the verification 
     * of the SSL server certificate, generated using the `brssl` command
     * line utility. For more information see the samples or bearssl.org
     * @param trust_anchors_num The number of trust anchors stored
     * @param analog_pin An analog pin to pull random bytes from, used in seeding the RNG
     * @param debug whether to enable or disable debug logging, must be constexpr
     */
    explicit SSLClient(const C& client, const br_x509_trust_anchor *trust_anchors, const size_t trust_anchors_num, const int analog_pin, const bool debug = true)
    : SSLClientImpl(NULL, trust_anchors, trust_anchors_num, analog_pin, debug) 
    , m_client(client)
    {
        // since we are copying the client in the ctor, we have to set
        // the client pointer after the class is constructed
        set_client(&m_client);
    }
    
    /** 
     * The special functions most clients have are below
     * Most of them smply pass through
     */
	virtual int availableForWrite(void) { return m_client.availableForWrite(); }
	virtual operator bool() { return connected() > 0; }
	virtual bool operator==(const bool value) { return bool() == value; }
	virtual bool operator!=(const bool value) { return bool() != value; }
	virtual bool operator==(const C& rhs) { return m_client == rhs; }
	virtual bool operator!=(const C& rhs) { return m_client != rhs; }
	virtual uint16_t localPort() { return m_client.localPort(); }
	virtual IPAddress remoteIP() { return m_client.remoteIP(); }
	virtual uint16_t remotePort() { return m_client.remotePort(); }
	virtual void setConnectionTimeout(uint16_t timeout) { m_client.setConnectionTimeout(timeout); }

    //! get the client object
    C& getClient() { return m_client; }

private:
    // create a copy of the client
    C m_client;
};

#endif /** SSLClient_H_ */
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
 * which is also used in the Arduino ESP8266 core. SSLClient will serve to implement the
 * BearSSL functionality inbetween EthernetClient and the User, such that the user.
 * 
 * This file specifically controls the class templating used to allow SSLClient to interface
 * with all of the CLient-based classes. To see details on the implementations of the functions
 * in SSLClient, please see {@link ./SSLClientImpl.h}.
 */

#include <type_traits>
#include "Client.h"
#include "SSLClientImpl.h"
#include "SSLSession.h"

#ifndef SSLClient_H_
#define SSLClient_H_

/**
 * \brief The main SSLClient class
 *  
 * TODO: fix this blurb
 * 
 * This class serves as a templating proxy class for the SSLClientImpl to do the real work.
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

template <class C, size_t SessionCache = 1>
class SSLClient : public SSLClientImpl {
/** 
 * static checks
 * I'm a java developer, so I want to ensure that my inheritance is safe.
 * These checks ensure that all the functions we use on class C are
 * actually present on class C. It does this by checking that the
 * class inherits from Client.
 * 
 * Additionally, I ran into a lot of memory issues with large sessions caches.
 * Since each session contains at max 352 bytes of memory, they eat of the
 * stack quite quickly and can cause overflows. As a result, I have added a
 * warning here to discourage the use of more than 3 sessions at a time. Any
 * amount past that will require special modification of this library, and 
 * assumes you know what you are doing.
 */
static_assert(std::is_base_of<Client, C>::value, "SSLClient can only accept a type with base class Client!");
static_assert(SessionCache > 0 && SessionCache < 255, "There can be no less than one and no more than 255 sessions in the cache!");
static_assert(SessionCache <= 3, "You need to decrease the size of m_iobuf in order to have more than 3 sessions at once, otherwise memory issues will occur.");

public:
    /**
     * @brief copies the client object, and passes the various parameters to the SSLCLientImpl functions.
     * 
     * We copy the client because we aren't sure the Client object
     * is going to exists past the inital creation of the SSLClient.
     * 
     * @pre You will need to generate an array of trust_anchors (root certificates)
     * based off of the domains you want to make SSL connections to. Check out the
     * Wiki on the pycert-bearssl tool for a simple way to do this.
     * @pre The analog_pin should be set to input.
     * 
     * @param trust_anchors Trust anchors used in the verification 
     * of the SSL server certificate, generated using the `brssl` command
     * line utility. For more information see the samples or bearssl.org
     * @param trust_anchors_num The number of trust anchors stored
     * @param analog_pin An analog pin to pull random bytes from, used in seeding the RNG
     * @param debug whether to enable or disable debug logging, must be constexpr
     */
    explicit SSLClient(const C& client, const br_x509_trust_anchor *trust_anchors, const size_t trust_anchors_num, const int analog_pin, const DebugLevel debug = SSL_WARN)
    : SSLClientImpl(NULL, trust_anchors, trust_anchors_num, analog_pin, NULL, debug) 
    , m_client(client)
    , m_sessions{SSLSession()}
    {
        // since we are copying the client in the ctor, we have to set
        // the client pointer after the class is constructed
        set_client(&m_client, m_sessions);
        // set the timeout to a reasonable number (it can always be changes later)
        // SSL Connections take a really long time so we don't want to time out a legitimate thing
        setTimeout(10 * 1000);
    }
    
    //========================================
    //= Functions implemented in SSLClientImpl
    //========================================

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
     * handshake succeeds or fails, as found in most Arduino libraries.
     * 
     * The implementation for this function can be found in SSLClientImpl::connect_impl(IPAddress, uint16_t)
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
    virtual int connect(IPAddress ip, uint16_t port) { return connect_impl(ip, port); }

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
     * The implementation for this function can be found in SSLClientImpl::connect_impl(const char*, uint16_t)
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
	virtual int connect(const char *host, uint16_t port) { return connect_impl(host, port); }

    /** @see SSLClient::write(uint8_t*, size_t) */
    virtual size_t write(uint8_t b) { return write_impl(&b, 1); }
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
	virtual size_t write(const uint8_t *buf, size_t size) { return write_impl(buf, size); }

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
     * The implementation for this function can be found in SSLClientImpl::available
     * 
     * @pre SSLClient::connected must be true.
     * 
     * @returns The number of bytes availible (can be zero), or zero if any of the pre
     * conditions aren't satisfied.
     */
	virtual int available() { return available_impl(); }

    /** 
     * @brief Read a single byte, or -1 if none is available.
     * @see SSLClient::read(uint8_t*, size_t) 
     */
	virtual int read() { uint8_t read_val; return read(&read_val, 1) > 0 ? read_val : -1; };
    /**
     * @brief Read size bytes from the SSL socket buffer, copying them into *buf, and return the number of bytes read.
     * 
     * This function checks if bytes are ready to be read by calling SSLClient::availible,
     * and if so copies size number of bytes from the IO buffer into the buf pointer, and deletes
     * that number of bytes from the SSLClient buffer. Data read using this function will not 
     * include any SSL or socket commands, as the Client and BearSSL will capture those and 
     * process them seperatley.
     * 
     * It should be noted that a common problem I encountered with SSL connections is
     * buffer overflow, caused by the server sending too much data at once. This problem
     * is caused by the microcontroller being unable to copy and decrypt data faster
     * than it is being recieved, forcing some data to be discarded. This usually puts BearSSL
     * in an invalid state in which it is unable to recover, causing SSLClient to close
     * the connection with a write error. If you are experiencing frequent timeout problems,
     * this could be the reason why.
     * 
     * In order to remedy this problem the device must be able to read the data faster than
     * it is being recieved, or have a cache large enough to store the entire recieve payload.
     * Since SSL's encryption forces the device to read slowly, this means we must increase 
     * the cache size. Depending on your platform, there are a number of ways this can be
     * done:
     * - Sometimes your communication sheild will have an internal buffer, which can be expanded
     *   through the driver code. This is the case with the Arduino Ethernet library (in the form
     *   of the MAX_SOCK_NUM and ETHERNET_LARGE_BUFFERS macros), however the library must be 
     *   modified for the change to take effect.
     * - SSLClient has an internal buffer SSLClientImpl::m_iobuf, which can be expanded. This will have very
     *   limited usefulness, however, as BearSSL limits the amount of data that can be processed
     *   based on the stage in the SSL handshake.
     * - If none of the above are viable, it is possible to implement your own Client class which
     *   has an internal buffer much larger than both the driver and BearSSL. This would require
     *   in-depth knowlege of programming and the communication shield you are working with.
     * Another important question to ask with this problem is: do I need to acsess this website?
     * Often times there are other ways to get data that we need that do the same thing,
     * and these other ways may offer smaller and more managable response payloads.
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
	virtual int read(uint8_t *buf, size_t size) { return read_impl(buf, size); }

    /** 
     * @brief view the first byte of the buffer, without removing it from the SSLClient Buffer
     * The implementation for this function can be found in SSLClientImpl::peek 
     * @pre SSLClient::available must be >0
     * @returns The first byte recieved, or -1 if the preconditions are not satisfied (warning: 
     * do not use if your data may be -1, as the return value is ambigious)
     */
    virtual int peek() { return peek_impl(); }

    /**
     * @brief Force writing the buffered bytes from SSLClient::write to the network.
     * This function is blocking until all bytes from the buffer are written. For
     * an explanation of how writing with SSLClient works, please see SSLCLient::write.
     * The implementation for this function can be found in SSLClientImpl::flush.
     */
	virtual void flush() { return flush_impl(); }

    /**
     * @brief Close the connection
     * If the SSL session is still active, all incoming data is discarded and BearSSL will attempt to
     * close the session gracefully (will write to the network), and then call m_client::stop. If the session is not active or an
     * error was encountered previously, this function will simply call m_client::stop.
     * The implementation for this function can be found in SSLClientImpl::peek.
     */
	virtual void stop() { return stop_impl(); }

    /**
     * @brief Check if the device is connected.
     * Use this function to determine if SSLClient is still connected and a SSL connection is active.
     * It should be noted that SSLClient::availible should be prefered over this function for rapid
     * polling--both functions send and recieve data to the Client device, however SSLClient::availible
     * has some delays built in to protect the Client device from being polled too frequently. 
     * 
     * The implementation for this function can be found in SSLClientImpl::connected_impl.
     * 
     * @returns 1 if connected, 0 if not
     */
	virtual uint8_t connected() { return connected_impl(); }

    //========================================
    //= Functions Not in the Client Interface
    //========================================

    /**
     * @brief Get a sesssion reference corressponding to a host and IP, or a reference to a emptey session if none exist
     * 
     * If no session corresponding to the host and ip exist, then this function will cycle through
     * sessions in a rotating order. This allows the ssession cache to continuially store sessions,
     * however it will also result in old sessions being cleared and returned. In general, it is a
     * good idea to use a SessionCache size equal to the number of domains you plan on connecting to.
     * 
     * The implementation for this function can be found at SSLClientImpl::get_session_impl.
     * 
     * @param host A hostname c string, or NULL if one is not availible
     * @param ip An IP address
     * @returns A reference to an SSLSession object
     */
    virtual SSLSession& getSession(const char* host, const IPAddress& addr) { return get_session_impl(host, addr); }

    /**
     * @brief Clear the session corresponding to a host and IP
     * 
     * The implementation for this function can be found at SSLClientImpl::remove_session_impl.
     * 
     * @param host A hostname c string, or NULL if one is not availible
     * @param ip An IP address
     */
    virtual void removeSession(const char* host, const IPAddress& addr) { return remove_session_impl(host, addr); }

    /**
     * @brief Get the meximum number of SSL sessions that can be stored at once
     * @returns The SessionCache template parameter.
     */
    virtual size_t getSessionCount() const { return SessionCache; }

    /** 
     * @brief Equivalent to SSLClient::connected() > 0
     * @returns true if connected, false if not
     */
	virtual operator bool() { return connected() > 0; }
    /** {@link SSLClient::bool()} */
	virtual bool operator==(const bool value) { return bool() == value; }
    /** {@link SSLClient::bool()} */
	virtual bool operator!=(const bool value) { return bool() != value; }
    /** @brief Returns whether or not two SSLClient objects have the same underlying client object */
	virtual bool operator==(const C& rhs) { return m_client == rhs; }
    /** @brief Returns whether or not two SSLClient objects do not have the same underlying client object */
	virtual bool operator!=(const C& rhs) { return m_client != rhs; }
    /** @brief Returns the local port, if the Client class has a localPort() function. Else return 0. */
	virtual uint16_t localPort() {
        if (std::is_member_function_pointer<decltype(&C::localPort)>::value) return m_client.localPort();
        else {
            m_warn("Client class has no localPort function, so localPort() will always return 0", __func__);
            return 0;
        } 
    }
    /** @brief Returns the remote IP, if the Client class has a remoteIP() function. Else return INADDR_NONE. */
	virtual IPAddress remoteIP() { 
        if (std::is_member_function_pointer<decltype(&C::remoteIP)>::value) return m_client.remoteIP();
        else {
            m_warn("Client class has no remoteIP function, so remoteIP() will always return INADDR_NONE. This means that sessions caching will always be disabled.", __func__);
            return INADDR_NONE;
        } 
    }
    /** @brief Returns the remote port, if the Client class has a remotePort() function. Else return 0. */
	virtual uint16_t remotePort() {
        if (std::is_member_function_pointer<decltype(&C::remotePort)>::value) return m_client.remotePort();
        else {
            m_warn("Client class has no remotePort function, so remotePort() will always return 0", __func__);
            return 0;
        } 
    }

    /** @brief returns a refernence to the client object stored in this class. Take care not to break it. */
    C& getClient() { return m_client; }

protected:
    //virtual Client& get_arduino_client() { return m_client; }
    //virtual SSLSession* get_session_array() { return m_sessions; }

private:
    // create a copy of the client
    C m_client;
    // also store an array of SSLSessions, so we can resume communication with multiple websites
    SSLSession m_sessions[SessionCache];
};

#endif /** SSLClient_H_ */
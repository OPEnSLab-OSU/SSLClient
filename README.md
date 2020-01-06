# SSLClient

[![Build Status](https://travis-ci.org/OPEnSLab-OSU/SSLClient.svg?branch=master)](https://travis-ci.org/OPEnSLab-OSU/SSLClient)

**SSLClient requires at least 110kb flash and 7kb RAM, and will not compile otherwise. This means that most Arduino boards are not supported. Check your board's specifications before attempting to use this library.**

You can also view this README in [doxygen](https://openslab-osu.github.io/SSLClient/html/index.html).

SSLClient is a simple library to add [TLS 1.2](https://www.websecurity.symantec.com/security-topics/what-is-ssl-tls-https) functionality to any network library implementing the [Arduino Client interface](https://www.arduino.cc/en/Reference/ClientConstructor), including the Arduino [EthernetClient](https://www.arduino.cc/en/Reference/EthernetClient) and [WiFiClient](https://www.arduino.cc/en/Reference/WiFiClient) classes (though it is better to prefer WiFClient.connectSSL if implemented). In other words, SSLClient implements encrypted communication through SSL on devices that do not otherwise support it.

SSLClient has been tested on the SAMD21, ESP32, and STM32 (in progress). SSClient does not currently support the ESP8266 (see [this issue](https://github.com/OPEnSLab-OSU/SSLClient/issues/5#issuecomment-569968546)).

## Overview

Using SSLClient should be similar to using any other Arduino-based Client class, since this library was developed around compatibility with [EthernetClient](https://www.arduino.cc/en/Reference/EthernetClient). There are a few extra things, however, that you will need to get started:

1. A board with a lot of resources (>110kb flash and >7kb RAM), and a network peripheral with a large internal buffer (>7kb). This library was tested with the [Adafruit Feather M0](https://www.adafruit.com/product/2772) (256K flash, 32K RAM) and the [Adafruit Ethernet Featherwing](https://www.adafruit.com/product/3201) (16kb Buffer), and we still had to modify the Arduino Ethernet library to support larger internal buffers per socket (see the [Implementation Gotchas](#sslclient-with-ethernet)).
2. A header containing array of trust anchors, which will look like [this file](./readme/cert.h). These are used to verify the SSL connection later on, and without them you will be unable to use this library. Check out [this document](./TrustAnchors.md) on how to generate this file for your project, and for more information about what a trust anchor is.
3. A Client class associated with a network interface. We tested this library using [EthernetClient](https://www.arduino.cc/en/Reference/EthernetClient), however in theory it will work for any class implementing Client.
4. An analog pin, used for generating random data at the start of the connection (see the [Implementation Gotchas](#implementation-gotchas)).

Once all those are ready, you can create a simple SSLClient object like this:
```C++
BaseClientType baseClientInstance;
SSLClient client(baseClientInstance, TAs, (size_t)TAs_NUM, AnalogPin);
```
Where:
* BaseClientType - The type of baseClientInstance
* BaseClientInstance - An instance of the class you are using for SSLClient (the class associated with the network interface, from step 3). It is important that this instance be stored *outside* the SSLClient declaration (for instance, `SSLClient(BaseClientType() ...)` wouldn't work).
* TAs - The name of the trust anchor array created in step 2. If you generated a header using the tutorial this will probably be `TAs`.
* TAs_NUM -  The number of trust anchors in TAs. If you generated a header using the tutorial this will probably be `TAs_NUM`.
* AnalogPin - The analog pin to pull random data from (step 4).
 
 For example, if I am using EthernetClient, a generated array of 2 trust anchors, and the analog pin A7, I would declare an SSLClient instance using:
 ```C++
EthernetClient baseClient;
SSLClient client(baseClient, TAs, 2, A7);
 ```
Once that is setup, simply use SSLClient as you would the base client class:
```C++
// connect to ardiuino.cc over ssl (port 443 for websites)
client.connect("www.arduino.cc", 443);
// Make a HTTP request
client.println("GET /asciilogo.txt HTTP/1.1");
client.println("User-Agent: AdafruitFeatherM0WiFi");
client.print("Host: ");
client.println(server);
client.println("Connection: close");
client.println();
client.flush();
// read and print the data
...
```
**Note**: `client.connect("www.arduino.cc", 443)` can take 5-15 seconds to finish. This an unavoidable consequence of the SSL protocol, and is detailed in [Implementation Notes](#resources).

For more information on SSLClient, check out the [examples](./examples), [API documentation](https://openslab-osu.github.io/SSLClient/html/index.html), or the rest of this README.

## How It Works

SSLClient was created to integrate SSL seamlessly with the Arduino infrastructure, and so it does just that: implementing the brilliant [BearSSL](https://bearssl.org/) as a proxy in front of any Arduino socket library. BearSSL is designed with low flash footprint in mind, and as a result does little verification of improper programming, relying on the developer to ensure the code is correct. Since SSLClient is built specifically for the Arduino ecosystem, most of SSLClient's code adds those programming checks back in, making debugging a fast and simple process.

## Other Features

### Logging
SSLClient also allows for changing the debugging level by adding an additional parameter to the constructor:
```C++
EthernetClient baseClient;
SSLClient client(baseClient, TAs, (size_t)2, A7, 1, SSLClient::SSL_INFO);
```
Logging is always outputted through the [Arduino Serial interface](https://www.arduino.cc/reference/en/language/functions/communication/serial/), so you'll need to setup Serial before you can view the SSL logs. Log levels are enumerated in ::DebugLevel. The log level is set to `SSL_WARN` by default.

### Errors
When SSLClient encounters an error, it will attempt to terminate the SSL session gracefully if possible, and then close the socket. Simple error information can be found from SSLClient::getWriteError(), which will return a value from the ::Error enum. For more detailed diagnostics, you can look at the serial logs, which will be displayed if the log level is at `SSL_ERROR` or lower.

### Write Buffering
As you may have noticed in the documentation for SSLClient::write, calling this function does not actually write to the network. Instead, you must call SSLClient::available or SSLClient::flush, which will detect that the buffer is ready and write to the network (see SSLClient::write for details).

This was implemented as a buffered function because examples in Arduino libraries will often write to the network like so:
```C++
EthernetClient client;
// ...
// connect to ardiuino.cc over ssl (port 443 for websites)
client.connect("www.arduino.cc", 443);
// ...
// write an http request to the network
client.write("GET /asciilogo.txt HTTP/1.1\r\n");
client.write("Host: arduino.cc\r\n");
client.write("Connection: close\r\n");
// wait for response
while (!client.available()) { /* ... */ }
// ...
```
Notice that every single write() call immediately writes to the network, which is fine with most network clients. With SSL, however, if we are encrypting and writing to the network every write() call, this will result in a lot of small encryption tasks. Encryption takes a lot of time and code, so to reduce the overhead of an SSL connection, SSLClient::write implicitly buffers until the developer states that they are waiting for data to be received with SSLClient::available. A simple example can be found below:

```C++
EthernetClient baseClient;
SSLClient client(baseClient, TAs, (size_t)2, A7);
// ...
// connect to ardiuino.cc over ssl (port 443 for websites)
client.connect("www.arduino.cc", 443);
// ...
// add http request to the buffer
client.write("GET /asciilogo.txt HTTP/1.1\r\n");
client.write("Host: arduino.cc\r\n");
client.write("Connection: close\r\n");
// write the bytes to the network, then wait for response
while (!client.available()) { /* ... */ }
// ...
```

If you would like to trigger a network write manually without using the SSLClient::available, you can also call SSLClient::flush, which will write all data and return when finished.

### Session Caching
As detailed in the [resources section](#resources), SSL handshakes take an extended period (1-4sec) to negotiate. To remedy this problem, BearSSL is able to keep a [SSL session cache](https://bearssl.org/api1.html#session-cache) of the clients it has connected to. If BearSSL successfully resumes an SSL session, it can reduce connection time to 100-500ms.

In order to use SSL session resumption:
 * The website you are connecting to must support it. Support is widespread, but you can verify easily using the [SSLLabs tool](https://www.ssllabs.com/ssltest/).
 *  You must reuse the same SSLClient object (SSL Sessions are stored in the object itself).
 *  You must reconnect to the exact same server.

SSLClient automatically stores an IP address and hostname in each session, ensuring that if you call `connect("www.google.com")` SSLClient will use the SSL session with that hostname. However, because some websites have multiple servers on a single IP address (github.com being an example), you may find that even if you are connecting to the same host the connection does not resume. This is a flaw in the SSL session protocol — though it has been resolved in TLS 1.3, the lack of widespread adoption of the new protocol prevents it from being used here. SSL sessions can also expire based on server criteria, which will result in a standard 4-10 second connection.

You can test whether or not a website can resume SSL Sessions using the [Session Example](./examples/Session_Example/Session_Example.ino) included with this library. Because of all the confounding factors of SSL Sessions, it is generally prudent while programming to assume the session will always fail to resume.

SSL sessions take a lot of memory to store, so by default SSLClient will only store one at a time. You can change this behavior by adding the following to your SSLClient declaration:
```C++
EthernetClient baseClient;
SSLClient client(baseClient, TAs, (size_t)2, A7, SomeNumber);
```
Where `SomeNumber` is the number of sessions you would like to store. For example this declaration can store 3 sessions:
```C++
EthernetClient baseClient;
SSLClient client(baseClient, TAs, (size_t)2, A7, 3);
```
Sessions are managed internally using the SSLSession::getSession function. This function will cycle through sessions in a rotating order, allowing the session cache to continually overwrite old sessions. In general, it is a good idea to use a SessionCache size equal to the number of domains you plan on connecting to.

If you need to clear a session, you can do so using the SSLSession::removeSession function.

## Implementation Gotchas

Some ideas that didn't quite fit in the API documentation.

### SSLClient with Ethernet
If you are using the [Arduino Ethernet library](https://github.com/arduino-libraries/Ethernet), you will need to modify the library to support the large buffer sizes required by SSL (detailed in [resources](#resources)). You can either modify the library yourself, or use [this fork of the Ethernet library with the modification](https://github.com/OPEnSLab-OSU/EthernetLarge). To use the fork, simply install the library using the "add a .zip library" button in Arduino, and replace `#include "Ethernet.h"` with `#include "EthernetLarge.h"` in your sketch. Alternatively if for some reason this solution does not work, you can apply the modification using the instructions below.

#### Manual Modification

 First find the location of the library in the directory where Arduino is installed (`C:\Program Files (x86)\Arduino` on Windows). Inside of this directory, navigate to `libraries\Ethernet\src` (`C:\Program Files (x86)\Arduino\libraries\Ethernet\src` on Windows). Modify `Ethernet.h` to replace these lines:
```C++
...
// Configure the maximum number of sockets to support.  W5100 chips can have
// up to 4 sockets.  W5200 & W5500 can have up to 8 sockets.  Several bytes
// of RAM are used for each socket.  Reducing the maximum can save RAM, but
// you are limited to fewer simultaneous connections.
#if defined(RAMEND) && defined(RAMSTART) && ((RAMEND - RAMSTART) <= 2048)
#define MAX_SOCK_NUM 4
#else
#define MAX_SOCK_NUM 8
#endif

// By default, each socket uses 2K buffers inside the Wiznet chip.  If
// MAX_SOCK_NUM is set to fewer than the chip's maximum, uncommenting
// this will use larger buffers within the Wiznet chip.  Large buffers
// can really help with UDP protocols like Artnet.  In theory larger
// buffers should allow faster TCP over high-latency links, but this
// does not always seem to work in practice (maybe Wiznet bugs?)
//#define ETHERNET_LARGE_BUFFERS
...
```
With this:
```C++
...
// Configure the maximum number of sockets to support.  W5100 chips can have
// up to 4 sockets.  W5200 & W5500 can have up to 8 sockets.  Several bytes
// of RAM are used for each socket.  Reducing the maximum can save RAM, but
// you are limited to fewer simultaneous connections.
#define MAX_SOCK_NUM 2

// By default, each socket uses 2K buffers inside the Wiznet chip.  If
// MAX_SOCK_NUM is set to fewer than the chip's maximum, uncommenting
// this will use larger buffers within the Wiznet chip.  Large buffers
// can really help with UDP protocols like Artnet.  In theory larger
// buffers should allow faster TCP over high-latency links, but this
// does not always seem to work in practice (maybe Wiznet bugs?)
#define ETHERNET_LARGE_BUFFERS
...
```
You may need to use `sudo` or administrator permissions to make this modification. We change `MAX_SOCK_NUM` and `ETHERNET_LARGE_BUFFERS` so the Ethernet hardware can allocate a larger space for SSLClient, however a downside of this modification is we are now only able to have two sockets concurrently. As most microprocessors barely have enough memory for one SSL connection, this limitation will rarely be encountered in practice.

### Seeding Random Data
The SSL protocol requires that SSLClient generate some random bits before connecting with a server. BearSSL provides a random number generator but requires a [some entropy for a seed](https://bearssl.org/apidoc/bearssl__ssl_8h.html#a7d8e8de2afd49d6794eae02f56f81152). Normally this seed is generated by taking the microsecond time using the internal clock, however since most microcontrollers are not build with this feature another source must be found. As a simple solution, SSLClient uses a floating analog pin as an external source of random data, passed through to the constructor in the `analog_pin` argument. Before every connection, SSLClient will take the bottom byte from 16 analog reads on `analog_pin`, and combine these bytes into a 16 byte random number, which is used as a seed for BearSSL. To ensure the most random data, it is recommended that this analog pin be either floating or connected to a location not modifiable by the microcontroller (i.e. a battery voltage readout). 

### Certificate Verification
SSLClient uses BearSSL's [minimal x509 verification engine](https://bearssl.org/x509.html#the-minimal-engine) to verify the certificate of an SSL connection. This engine requires the developer create a trust anchor array using values stored in trusted root certificates. Check out [this document](./TrustAnchors.md) for more details on this component of SSLClient.

BearSSL also features a [known certificate validation engine](https://bearssl.org/x509.html#the-known-key-engine), which only allows for a single domain in exchange for a significantly reduced resource usage (flash and CPU time). This functionality is planned to be implemented in the future.

### Resources
The SSL protocol recommends a device support many different encryption algorithms, as well as protocols for SSL itself. The complexity of both of those components results in many medium sized components forming an extremely large whole. Additionally, most embedded processors lack the sophisticated math hardware commonly found in a modern CPU, and as a result require more instructions to create the encryption algorithms SSL requires. This not only increases size but makes the algorithms slow and memory intensive.

To illustrate this, I will run some tests on various domains below. I haven't yet, but I will.

If flash footprint is becoming a problem, there are numerous debugging strings (~3kb estimated) that can be removed from `SSLClient.h`, `SSLClientImpl.h`, and `SSLClientImpl.cpp`. I have not figured out a way to configure compilation of these strings, so you will need to modify the library to remove them yourself.

### Read Buffer Overflow
SSL is a buffered protocol, and since most microcontrollers have limited resources (see [Resources](#resources)), SSLClient is limited in the size of its buffers. A common problem I encountered with SSL connections is buffer overflow, caused by the server sending too much data at once. This problem is caused by the microcontroller being unable to copy and decrypt data faster than it is being received, forcing some data to be discarded. This usually puts BearSSL in an unrecoverable state, forcing SSLClient to close the connection with a write error. If you are experiencing frequent timeout problems, this could be the reason why. 

In order to remedy this problem, the device must be able to read the data faster than it is being received, or alternatively have a cache large enough to store the entire payload. Since SSL's encryption forces the device to read slowly, this means we must increase the cache size. Depending on your platform, there are a number of ways this can be done:
* Sometimes your communication shield will have an internal buffer, which can be expanded through the driver code. This is the case with the Arduino Ethernet library (in the form of the MAX_SOCK_NUM and ETHERNET_LARGE_BUFFERS macros), however the library must be modified for the change to take effect.
* SSLClient has an internal buffer SSLClientImpl::m_iobuf, which can be expanded. BearSSL limits the amount of data that can be processed based on the stage in the SSL handshake, and so this will change will have limited usefulness. 
* In some cases, a website will send so much data that even with the above solutions, SSLClient will be unable to keep up (a website with a lot of HTML is an example). In these cases you will have to find another method of retrieving the data you need.
* If none of the above are viable, it is possible to implement your own Client class which has an internal buffer much larger than both the driver and BearSSL. This would require in-depth knowledge of programming and the communication shield you are working with, as well as a microcontroller with a significant amount of RAM.

### Cipher Support
By default, SSLClient supports only TLS1.2 and the ciphers listed in [this file](./src/TLS12_only_profile.c) under `suites[]`, and the list is relatively small to keep the connection secure and the flash footprint down. These ciphers should work for most applications, however if for some reason you would like to use an older version of TLS or a different cipher, you can change the BearSSL profile being used by SSLClient to an [alternate one with support for older protocols](./src/bearssl/src/ssl/ssl_client_full.c). To do this, edit `SSLClientImpl::SSLClientImpl` to change these lines:
```C++
br_client_init_TLS12_only(&m_sslctx, &m_x509ctx, m_trust_anchors, m_trust_anchors_num);
// comment the above line and uncomment the line below if you're having trouble connecting over SSL
// br_ssl_client_init_full(&m_sslctx, &m_x509ctx, m_trust_anchors, m_trust_anchors_num);
```
to this:
```C++
// br_client_init_TLS12_only(&m_sslctx, &m_x509ctx, m_trust_anchors, m_trust_anchors_num);
// comment the above line and uncomment the line below if you're having trouble connecting over SSL
br_ssl_client_init_full(&m_sslctx, &m_x509ctx, m_trust_anchors, m_trust_anchors_num);
```
If for some unfortunate reason you need SSL 3.0 or SSL 2.0, you will need to modify the BearSSL profile to enable support. Check out the [BearSSL profiles documentation](https://bearssl.org/api1.html#profiles) and I wish you the best of luck.

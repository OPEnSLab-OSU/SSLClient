# SSLClient

![CI](https://github.com/OPEnSLab-OSU/SSLClient/workflows/CI/badge.svg)

SSLClient adds [TLS 1.2](https://www.websecurity.symantec.com/security-topics/what-is-ssl-tls-https) functionality to any network library implementing the [Arduino Client interface](https://www.arduino.cc/en/Reference/ClientConstructor), including the Arduino [EthernetClient](https://www.arduino.cc/en/Reference/EthernetClient) and [WiFiClient](https://www.arduino.cc/en/Reference/WiFiClient) classes. SSLClient was created to integrate TLS seamlessly with the Arduino infrastructure using [BearSSL](https://bearssl.org/) as an underlying TLS engine. Unlike [ArduinoBearSSL](https://github.com/arduino-libraries/ArduinoBearSSL), SSLClient is completly self-contained, and does not require any additional hardware (other than a network connection).

SSLClient officially supports SAMD21, SAM3X, ESP32, TIVA C, STM32F7, and Teensy >= 3.0; but it should work on any board with at least 110kB flash and 7kB RAM. SSClient does not currently support ESP8266 (see [this issue](https://github.com/OPEnSLab-OSU/SSLClient/issues/5#issuecomment-569968546)) or AVR due to memory constraints on both platforms.

You can also view this README in [doxygen](https://openslab-osu.github.io/SSLClient/index.html).

## Overview

Using SSLClient is similar to using any other Arduino-based Client class, as this library was developed around compatibility with [EthernetClient](https://www.arduino.cc/en/Reference/EthernetClient). There are a few extra things, however, that you will need to get started:

1. **Board and Network Peripheral** - Your board should have a lot of resources (>110kB flash and >7kB RAM), and your network peripheral should have a large internal buffer (>7kB). This library was tested with the [Adafruit Feather M0](https://www.adafruit.com/product/2772) (256K flash, 32K RAM) and the [Adafruit Ethernet Featherwing](https://www.adafruit.com/product/3201) (16kB Buffer), and we still had to modify the Arduino Ethernet library to support larger internal buffers per socket (see the [Implementation Gotchas](#sslclient-with-ethernet)).
2. **Trust Anchors** - You will need a header containing array of trust anchors ([example](./readme/cert.h)), which are used to verify the SSL connection later on. **This file must generated for every project.** Check out [TrustAnchors.md](./TrustAnchors.md#generating-trust-anchors) on how to generate this file for your project, and for more information about what a trust anchor is.
3. **Network Peripheral Driver Implementing `Client`** - Examples include `EthernetClient`, `WiFiClient`, and so on—SSLClient will run on top of any network driver exposing the `Client` interface.
4. **Analog Pin** - Used for generating random data at the start of the connection (see the [Implementation Gotchas](#implementation-gotchas)).

Once all those are ready, you can create an SSLClient object like this:
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
Given this client, simply use SSLClient as you would the base client class:
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
**Note**: `client.connect("www.arduino.cc", 443)` can take 5-15 seconds to finish on some low-power devices. This an unavoidable consequence of the SSL protocol, and is detailed more in [Implementation Gotchas](#resources).

For more information on SSLClient, check out the [examples](./examples), [API documentation](https://openslab-osu.github.io/SSLClient/html/index.html), or the rest of this README.

## Other Features

### Logging
SSLClient also allows for changing the debugging level by adding an additional parameter to the constructor:
```C++
EthernetClient baseClient;
SSLClient client(baseClient, TAs, (size_t)2, A7, 1, SSLClient::SSL_INFO);
```
Logging is always outputted through the [Arduino Serial interface](https://www.arduino.cc/reference/en/language/functions/communication/serial/), so you'll need to setup Serial before you can view the SSL logs. Log levels are enumerated in ::DebugLevel. The log level is set to `SSL_WARN` by default.

### Errors
When SSLClient encounters an error, it will attempt to terminate the SSL session gracefully if possible, and then close the socket. Simple error information can be found from SSLClient::getWriteError, which will return a value from the ::Error enum. For more detailed diagnostics, you can look at the serial logs, which will be displayed if the log level is at `SSL_ERROR` or lower.

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
Notice that every single `client.write()` call immediately writes to the network. This behavior is fine for most network clients; with SSL, however, it results in many small encryption tasks that consume resources. To reduce the overhead of an SSL connection, SSLClient::write implicitly buffers until the developer states that they are waiting for data to be received with SSLClient::available. A simple example can be found below:

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
As detailed in the [resources section](#resources), SSL handshakes take an extended period (1-4sec) to negotiate. BearSSL is able to keep a [SSL session cache](https://bearssl.org/api1.html#session-cache) of the clients it has connected to which can drastically reduce this time: if BearSSL successfully resumes an SSL session, connection time is typically 100-500ms.

In order to use SSL session resumption:
 * The website you are connecting to must support it. Support is widespread, and you can verify it using [SSLLabs](https://www.ssllabs.com/ssltest/).
 *  You must reuse the same SSLClient object (SSL Sessions are stored in the object itself).
 *  You must reconnect to the exact same server (detailed below).

> NOTE: SSLClient automatically stores an IP address and hostname in each session, ensuring that if you call `connect("www.google.com")` SSLClient will use the same SSL session for that hostname. Unfortunately some websites have multiple servers on a single IP address (github.com being an example), so you may find that even if you are connecting to the same host the connection will not resume. This is a flaw in the SSL session protocol—though it has been resolved in TLS 1.3, the lack of widespread adoption of the new protocol prevents it from being resolved here. 
> 
> SSL sessions can also expire based on server criteria (ex. timeout), which will result in a standard 4-10 second connection.

SSL sessions take memory to store, so by default SSLClient will only store one at a time. You can change this behavior by adding the following to your SSLClient declaration:
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

### mTLS

As of `v1.6.0`, SSLClient supports [mutual TLS authentication](https://developers.cloudflare.com/access/service-auth/mtls/). mTLS is a varient of TLS that verifies both the server and device identities before a connection, and is commonly used in IoT protocols as a secure layer (MQTT over TLS, HTTP over TLS, etc.).

To use mTLS with SSLClient you will need to a client certificate and client private key associated with the server you are attempting to connect to. Depending on your use case, you will either generate these yourself (ex. [Mosquito MQTT setup](http://www.steves-internet-guide.com/creating-and-using-client-certificates-with-mqtt-and-mosquitto/)), or have them generated for you (ex. [AWS IoT Certificate Generation](https://docs.aws.amazon.com/iot/latest/developerguide/create-device-certificate.html)). Given this cryptographic information, you can modify the standard SSLClient connection sketch to enable mTLS authentication:
```C++
...
/* Somewhere above setup() */

// The client certificate, can be PEM or DER format
// DER format will be an array of raw bytes, and PEM format will be a string
// PEM format is shown below
const char my_cert[] = 
"-----BEGIN CERTIFICATE-----\n"
"MIIDpDCCAowCCQC7mCk5Iu3YmDANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMC\n"
...
"-----END CERTIFICATE-----\n";

// The client private key, must be the same format as the client certificate
// Both RSA and ECC are supported, ECC is shown below
const char my_key[] = 
"-----BEGIN EC PRIVATE KEY-----\n"
...
"-----END EC PRIVATE KEY-----\n";

// This line will parse and store the above information so SSLClient can use it later
// Replace `fromPEM` with `fromDER` if you are using DER formatted certificates.
SSLClientParameters mTLS = SSLClientParameters::fromPEM(my_cert, sizeof(cert), my_key, sizeof(key));
SSLClient my_client(...);
...
void setup() {
    ...
    /* Before SSLClient connects */

    my_client.setMutualAuthParams(mTLS);
    ...
}
...
```

> NOTE: Certificates are finicky, and it is easy to make mistakes when generating a certificate chain yourself. If SSLClient raises an error that says `Expected server name not found in chain`, double check that the common name, distinguished name, and issuer name are being set correctly (check out [this article](https://medium.com/@superseb/get-your-certificate-chain-right-4b117a9c0fce) for how to do that). 

The client certificate must be formatted correctly (according to [BearSSL's specification](https://bearssl.org/apidoc/bearssl__pem_8h.html)) in order for mTLS to work. If the certificate is improperly formatted, SSLClient will attempt to make a regular TLS connection instead of an mTLS one, and fail to connect as a result. Because of this, if you are seeing errors similar to `"peer did not send certificate chain"` on your server, check that your certificate and key are formatted correctly (see https://github.com/OPEnSLab-OSU/SSLClient/issues/7#issuecomment-593704969). For more information on SSLClient's mTLS functionality, please see the [SSLClientParameters documentation](https://openslab-osu.github.io/SSLClient/class_s_s_l_client_parameters.html).

Note that both the above client certificate information *as well as* the correct trust anchors associated with the server are needed for the connection to succeed. Trust anchors will typically be generated from the CA used to generate the server certificate. More information on generating trust anchors can be found in [TrustAnchors.md](./TrustAnchors.md). 

## Implementation Gotchas

Some ideas that didn't quite fit in the API documentation.

### SSLClient with Ethernet
If you are using the [Arduino Ethernet library](https://github.com/arduino-libraries/Ethernet) you will need to modify the library to support the large buffer sizes required by SSL (detailed in [resources](#resources)). You can either modify the library yourself, or use [this fork of the Ethernet library with the modification](https://github.com/OPEnSLab-OSU/EthernetLarge). To use the fork: download a zipped copy of the fork through GiThub, use the "add a .zip library" button in Arduino to install the library, and replace `#include "Ethernet.h"` with `#include "EthernetLarge.h"` in your sketch. Alternatively if for some reason this solution does not work, you can apply the modification manually using the instructions below.

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

#### Time
The minimal x509 verification engine requires an accurate source of time to properly verify the creation and expiration dates of a certificate. As most embedded devices do not have a reliable source of time, by default SSLClient opts to use the compilation timestamp ([`__DATE__` and `__TIME__`](https://gcc.gnu.org/onlinedocs/cpp/Standard-Predefined-Macros.html)) as the "current time" during the verification process. While this approach reduces the complexity of using SSLClient, it is inherently insecure, and can cause errors if certificates are redeployed (see [#27](https://github.com/OPEnSLab-OSU/SSLClient/issues/27)): to accommodate these edge cases, SSLClient::setVerificationTime can be used to update the timestamp before connecting, resolving the above issues.

### Resources
The SSL/TLS protocol recommends a device support many different encryption and handshake algorithms. The complexity of these components results in many medium-footprint algorithms forming an extremely large whole. Compilation size of the [EthernetHTTPS](examples/EthernetHTTPS/EthernetHTTPS.ino) example in SSLClient `v1.6.11` for various boards is shown below:

| Board | Size 
| :--- | :--- |
| Arduino Zero | <pre>`RAM:   [===       ]  33.7% (used 11052 bytes from 32768 bytes)`<br/>`Flash: [===       ]  34.7% (used 90988 bytes from 262144 bytes)`</pre> |
| Arduino Due | <pre>`RAM:   [=         ]  11.7% (used 11548 bytes from 98304 bytes)`<br/>`Flash: [==        ]  16.7% (used 87572 bytes from 524288 bytes)`</pre> |
| Adafruit Feather M0 | <pre>`RAM:   [====      ]  40.4% (used 13240 bytes from 32768 bytes)`<br/>`Flash: [====      ]  40.0% (used 104800 bytes from 262144 bytes)`</pre> |
| ESP32 (Lolin32) | <pre>`RAM:   [=         ]   6.9% (used 22476 bytes from 327680 bytes)`<br/>`Flash: [==        ]  24.0% (used 314956 bytes from 1310720 bytes)`</pre> |
| Teensy 3.0 | <pre>`RAM:   [========  ]  78.2% (used 12812 bytes from 16384 bytes)`<br/>`Flash: [========  ]  79.8% (used 104532 bytes from 131072 bytes)`</pre> |
| Teensy 3.1 | <pre>`RAM:   [==        ]  19.9% (used 13020 bytes from 65536 bytes)`<br/>`Flash: [====      ]  40.6% (used 106332 bytes from 262144 bytes)`</pre> |
| Teensy 3.5 | <pre>`RAM:   [          ]   5.0% (used 12996 bytes from 262136 bytes)`<br/>`Flash: [==        ]  20.1% (used 105476 bytes from 524288 bytes)`</pre>
| Teensy 3.6 | <pre>`RAM:   [          ]   5.0% (used 13060 bytes from 262144 bytes)`<br/>`Flash: [=         ]  10.2% (used 106828 bytes from 1048576 bytes)`</pre> |
| Teensy 4.0 | <pre>`RAM:   [===       ]  25.9% (used 135860 bytes from 524288 bytes)`<br/>`Flash: [=         ]   5.7% (used 115344 bytes from 2031616 bytes)`</pre> |

In addition to the above, most embedded processors lack the sophisticated math hardware commonly found in a modern CPU, which results in slow and memory intensive execution of these algorithms. Because of this, it is recommended that SSLClient have 8kb of memory available on the stack during a connection, and 4-10 seconds should be allowed for the connection to complete. Note that this requirement is based on the SAMD21—more powerful processors (such as the ESP32) will see faster connection times.

> NOTE: If flash footprint is becoming a problem, there are numerous debugging strings (~3kB estimated) that can be removed from `SSLClient.h`, `SSLClientImpl.h`, and `SSLClientImpl.cpp`. Unfortunately I have not figured out a way to configure compilation of these strings, so you will need to modify the library to remove them yourself.

### Read Buffer Overflow
SSL is a buffered protocol, and since most microcontrollers have limited resources (see [Resources](#resources)), SSLClient is limited in the size of its buffers. A common problem I encountered with SSL connections is buffer overflow caused by the server sending too much data at once. This problem is caused by the microcontroller being unable to copy and decrypt data faster than it is being received—forcing some data to be discarded. This usually puts BearSSL in an unrecoverable state, forcing SSLClient to close the connection with a write error. If you are experiencing frequent timeout problems this could be the reason why. 

In order to remedy this problem, the device must be able to read the data faster than it is being received or have a cache large enough to store the entire payload. Since the device is typically already reading as fast as it can, we must increase the cache size in order to resolve this issue. Depending on your platform there are a number of ways this can be done:
* Sometimes your communication shield will have an internal buffer which can be expanded through the driver code: this is the case with the Arduino Ethernet library (in the form of the `MAX_SOCK_NUM` and `ETHERNET_LARGE_BUFFERS` macros show [here](#manual-modification)), but mileage may vary with other drivers.
* SSLClient has an internal buffer SSLClient::m_iobuf which can be expanded. Unfortunately, BearSSL limits the amount of data that can be put into the buffer based on the stage in the SSL handshake, and so increasing the buffer will have limited usefulness. 
* In some cases, a website will send so much data that even with the above solutions SSLClient will be unable to keep up. In these cases you will have to find another method of retrieving the data you need.
* If none of the above are viable, it is possible to implement your own Client class which has an internal buffer much larger than both the driver and BearSSL. This implementation would require in-depth knowledge of communication shield you are working with and a microcontroller with a significant amount of RAM, but would be the most robust solution available.

### Cipher Support
By default, SSLClient supports only TLS1.2 and the ciphers listed in [this file](./src/TLS12_only_profile.c) under `suites[]`, and the list is relatively small to keep the connection secure and the flash footprint down. These ciphers should work for most applications, however if for some reason you would like to use an older version of TLS or a different cipher you can change the BearSSL profile being used by SSLClient to an [alternate one with support for older protocols](./src/bearssl/src/ssl/ssl_client_full.c). To do this, edit `SSLClientImpl::SSLClientImpl` to change these lines:
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

### Security
Unlike BearSSL, SSLClient is not rigorously vetted to be secure. If your project has security requirements I recommend you utilize BearSSL directly.

### Known Issues
 * In some drivers (Ethernet), calls to `Client::flush` will hang if internet is available but there is no route to the destination. Unfortunately SSLClient cannot correct for this without modifying the driver itself, and as a result the recommended solution is ensuring you choose a driver with built-in timeouts to prevent freezing. [More information here](https://github.com/OPEnSLab-OSU/SSLClient/issues/13#issuecomment-643855923).
 * Previous to SSLClient `v1.6.11`, `SSLClient::write` would sometimes call `br_ssl_engine_sendapp_ack` with zero bytes, which resulted in a variety of issues including (but not limited to) and infinite recursion loop on the esp32 ([#9](https://github.com/OPEnSLab-OSU/SSLClient/issues/9), [#30](https://github.com/OPEnSLab-OSU/SSLClient/issues/30)).
 * Previous to SSLClient `v1.6.7`, calls to `SSLClient::stop` would sometimes hang the device. More information in issue https://github.com/OPEnSLab-OSU/SSLClient/issues/13.
 * Previous to SSLClient `v1.6.6`, calls to `SSLClient::connect` would fail if the driver indicated that a socket was already opened (`Client::connected` returned true). This behavior created unintentional permanent failures when `Client::stop` would fail to close the socket, and as a result was downgraded to a warning in v1.6.6.
 * Previous to SSLClient `v1.6.3`, calling `SSLClient::write` with more than 2kB of total data before flushing the write buffer would cause a buffer overflow.
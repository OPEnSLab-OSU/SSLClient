# SSLClient - Arduino Library For SSL

**SSLClient requires at least 110kb flash and 8kb RAM, and will not compile otherwise. This means that most Arduino boards are not supported. Check your board's specifications before attempting to use this library.**

SSLClient is a simple library to add [TLS 1.2](https://www.websecurity.symantec.com/security-topics/what-is-ssl-tls-https) functionality to any network library implementing the the [Arduino Client interface](https://www.arduino.cc/en/Reference/ClientConstructor), including the Arduino [EthernetClient](https://www.arduino.cc/en/Reference/EthernetClient) and [WiFiClient](https://www.arduino.cc/en/Reference/WiFiClient) classes (though it is better to prefer WiFClient.connectSSL if implemented). In other words, SSLClient implements encrypted communication through SSL on devices that do not otherwise support it.

## Overview

Using SSLClient should be similar to using any other Arduino-based Client class, since this library was developed around compatibility with [EthernetClient](https://www.arduino.cc/en/Reference/EthernetClient). There are a few things extra things, however, that you will need to get started:

1. A board with a lot of resources (>110kb flash and >8kb RAM), and a network peripheral with a large internal buffer (>8kb). This library was tested with the [Adafruit Feather M0](https://www.adafruit.com/product/2772) (256K flash, 32K RAM) and the [Adafruit Ethernet Featherwing](https://www.adafruit.com/product/3201) (16kb Buffer), and we still had to modify the Arduino Ethernet library to support larger internal buffers per socket (see the [Implementation Notes](#Implementation-Notes)).
2. A header containing array of trust anchors, which will look like [this file](./readme/cert.h). These are used to verify the SSL connection later on, and without them you will be unable to use this library. Check out [this document](./TrustAnchors.md) on how to generate this file for your project.
3. A Client class associated with a network interface. We tested this library using [EthernetClient](https://www.arduino.cc/en/Reference/EthernetClient), however in theory it will work for and class implementing Client.
4. An analog pin, used for generating random data at the start of the connection (see the [Implementation Notes](#Implementation-Notes)).

Once all those are ready, you can create a simple SSLClient object like this:
```C++
SSLClient<BaseClientType> client(BaseClientInstance, TAs, (size_t)TAs_NUM, AnalogPin);
```
Where:
* BaseClientType - The type of BaseClientInstance
* BaseClientInstance - An instance of the class you are using for SSLClient (the class associated with the network interface, from step 3)
* TAs - The name of the trust anchor array created in step 2. If you generated a header using the tutorial this will probably be `TAs`.
* TAs_NUM -  The number of trust anchors in TAs. If you generated a header using the tutorial this will probably be `TAs_NUM`.
* AnalogPin - The analog pin to pull random data from (step 4).
 
 For example, if I am using EthernetClient, a generated array of 2 trust anchors, and the analog pin A7, I would declare an SSLClient instance using:
 ```C++
SSLClient<EthernetClient> client(EthernetClient(), TAs, (size_t)2, A7);
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
**Note**: `client.connect("www.arduino.cc", 443)` can take 5-15 seconds to finish. This an unavoidable consequence of the SSL protocol, and is detailed in [Implementation Notes](#Implementation-Notes).

For more information on SSLClient, check out the [examples](./examples), [API documentation](./docs/index.html), or the rest of this README.

## How It Works

SSLClient was created to integrate SSL seamlessly with the Arduino infrastructure, and so it does just that: implementing the brilliant [BearSSL](link-here) as a proxy in front of any Arduino socket library. BearSSL is designed with low flash footprint in mind, and as a result does little verification of improper programming, relying on the developer to ensure the code is correct. Since SSLClient is built specifically for the Arduino ecosystem, most of the code adds those programming checks back in, helping debugging be a fast and simple process. The rest manages the state of BearSSL, and ensures a manageable memory footprint.

## Implementation Notes

Some ideas that didn't quite fit in the API documentation.

### Certificate Verification

SSLClient uses BearSSL's [minimal x509 verification engine](link-me) to verify the certificate of an SSL connection. This engine requires the developer create a trust anchor array using values stored in trusted root certificates. Check out [this document](./TrustAnchors.md) for more details on this component of SSLClient.

### Cipher Support

SSLClient supports only TLS1.2 and the ciphers listed in [this file under `suites[]`](./src/TLS12_only_profile) by default, and the list is relatively small to keep the connection secure and the flash footprint down. These ciphers should work for most applications, however if for some reason you would like to use an older version of TLS or a different cipher, you can change the BearSSL profile being used by SSLClient to an [alternate one with support for older protocols](./src/bearssl/src/ssl). To do this, edit `SSLClientImpl::SSLClientImpl` to change these lines:
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
If for some unfortunate reason you need SSL 3.0 or SSL 2.0, you will need to modify the BearSSL profile to enable support. Check out the [BearSSL Documentation](link-me) and I wish you the best of luck.

### Resources

The SSL protocol recommends a device support many different encryption algorithms, as well as protocols for SSL itself. The complexity of both of those components results in many medium sized components forming an extremely large whole. Additionally, most embedded processors lack the sophisticated math hardware commonly found in a modern CPU, and as a result require more instructions to create the encryption algorithms SSL requires. This not only increases size but makes the algorithms slow and memory intensive.

To illustrate this, I will run some tests on various domains below. I haven't yet, but I will.

If flash footprint is becoming a problem, there are numerous debugging strings (~3kb estimated) that can be removed from `SSLClient.h`, `SSLClientImpl.h`, and `SSLClientImpl.cpp`. I have not figured out a way to configure compilation of these strings, so you will need to modify the library to remove them yourself.

### Logging
SSLClient also allows for changing the debugging level by adding an additional parameter to the constructor:
```C++
SSLClient<EthernetClient> client(EthernetClient(), TAs, (size_t)2, A7, SSL_INFO);
```
Logging is always outputted through the [Arduino Serial interface](https://www.arduino.cc/reference/en/language/functions/communication/serial/), so you'll need to setup Serial before you can view the SSL logs. Log levels are enumerated in [Error](./src/SSLClientImpl.h). The log level is set to `SSL_WARN` by default.
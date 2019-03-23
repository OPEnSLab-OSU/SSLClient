# SSLClient - Arduino Library For SSL

**SSLClient requires at least 110kb flash and 8kb RAM, and will not compile otherwise. This means that most Arduino boards are not supported. Check your board's specifications before attempting to use this library.**

SSLClient is a simple library to add SSL [TLS 1.2](https://www.websecurity.symantec.com/security-topics/what-is-ssl-tls-https) functionality to any network library implementing the the [Arduino Client interface](https://www.arduino.cc/en/Reference/ClientConstructor), including the Arduino [EthernetClient](https://www.arduino.cc/en/Reference/EthernetClient) and [WiFiClient](https://www.arduino.cc/en/Reference/WiFiClient) classes (though it is better to prefer WiFClient.connectSSL if implemented). In other words, SSLClient implements encrypted communication through SSL on devices that do not otherwise support it.

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
// connect to ardiuino.cc over ssl
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


### Logging
SSLClient also allows for changing the debugging level by adding an additional parameter to the constructor.
```C++
SSLClient<EthernetClient> client(EthernetClient(), TAs, (size_t)2, A7, SSL_INFO);
```
 The log levels are Logging is always outputted through the [Arduino Serial interface](https://www.arduino.cc/reference/en/language/functions/communication/serial/), so you'll need to setup Serial before you can view the SSL logs.

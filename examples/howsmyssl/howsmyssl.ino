/*
  Web client

  This sketch connects to a website (http://www.howsmyssl.com/a/check)
  using an Arduino Wiznet Ethernet shield or STM32 built-in Ethernet.
  Tested on ST Micro Nucleo-F767ZI.

  The JSON output looks like this when pretty printed. "Probably Okay"
  is the highest rating.
  {
  "given_cipher_suites": [
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
  ],
  "ephemeral_keys_supported": true,
  "session_ticket_supported": false,
  "tls_compression_supported": false,
  "unknown_cipher_suite_supported": false,
  "beast_vuln": false,
  "able_to_detect_n_minus_one_splitting": false,
  "insecure_cipher_suites": {},
  "tls_version": "TLS 1.2",
  "rating": "Probably Okay"
  }

  Circuit:
   Ethernet shield attached to pins 10, 11, 12, 13

  created 18 Dec 2009
  by David A. Mellis
  modified 9 Apr 2012
  by Noah Koontz, based on work by Adrian McEwen and Tom Igoe

  Modified 16 Oct 2019 by gdsports625@gmail.com for STM32duino_STM32Ethernet
*/

// NOTE: This example REQUIRES the EthernetLarge library.
// You can get it here: https://github.com/OPEnSLab-OSU/EthernetLarge

#if defined(ARDUINO_NUCLEO_F767ZI)
extern "C" {
  // This must exist to keep the linker happy but is never called.
  int _gettimeofday( struct timeval *tv, void *tzvp )
  {
    Serial.println("_gettimeofday dummy");
    uint64_t t = 0;  // get uptime in nanoseconds
    tv->tv_sec = t / 1000000000;  // convert to seconds
    tv->tv_usec = ( t % 1000000000 ) / 1000;  // get remaining microseconds
    return 0;  // return non-zero for error
  } // end _gettimeofday()
}
#include <LwIP.h>
#include <STM32Ethernet.h>
#else
#include <SPI.h>
#include <EthernetLarge.h>
#endif
#include <SSLClient.h>
#include "trust_anchors.h"

#if !defined(ARDUINO_NUCLEO_F767ZI)
// Enter a MAC address for your controller below.
// Newer Ethernet shields have a MAC address printed on a sticker on the shield
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
#endif

// if you don't want to use DNS (and reduce your sketch size)
// use the numeric IP instead of the name for the server:
//IPAddress server(54,85,55,79);  // numeric IP for Google (no DNS)
const char server[] = "www.howsmyssl.com";    // name address for Arduino (using DNS)
const char server_host[] = "www.howsmyssl.com"; // leave this alone, change only above two

// Set the static IP address to use if the DHCP fails to assign
IPAddress ip(192, 168, 0, 177);
IPAddress myDns(8, 8, 8, 8);

// Choose the analog pin to get semi-random data from for SSL
// Pick a pin that's not connected or attached to a randomish voltage source
const int rand_pin = A5;

// Initialize the SSL client library
// We input an EthernetClient, our trust anchors, and the analog pin
SSLClient<EthernetClient> client(EthernetClient(), TAs, (size_t)TAs_NUM, rand_pin, SSL_NONE);
// Variables to measure the speed
unsigned long beginMicros, endMicros;
unsigned long byteCount = 0;
bool printWebData = true;  // set to false for better speed measurement

void setup() {
#if !defined(ARDUINO_NUCLEO_F767ZI)
  // You can use Ethernet.init(pin) to configure the CS pin
  Ethernet.init(10);  // Most Arduino shields
  //Ethernet.init(5);   // MKR ETH shield
  //Ethernet.init(0);   // Teensy 2.0
  //Ethernet.init(20);  // Teensy++ 2.0
  //Ethernet.init(15);  // ESP8266 with Adafruit Featherwing Ethernet
  //Ethernet.init(33);  // ESP32 with Adafruit Featherwing Ethernet
#endif

  // Open serial communications and wait for port to open:
  Serial.begin(115200);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }

  // start the Ethernet connection:
  Serial.println("Initialize Ethernet with DHCP:");
#if defined(ARDUINO_NUCLEO_F767ZI)
  // STM32 built-in Ethernet has a factory installed MAC address.
  if (Ethernet.begin() == 0) {
    Serial.println("Failed to configure Ethernet using DHCP");
    while (1) delay(1);
  } else {
    Serial.print("  DHCP assigned IP ");
    Serial.println(Ethernet.localIP());
  }
#else
  if (Ethernet.begin(mac) == 0) {
    Serial.println("Failed to configure Ethernet using DHCP");
    // Check for Ethernet hardware present
    if (Ethernet.hardwareStatus() == EthernetNoHardware) {
      Serial.println("Ethernet shield was not found.  Sorry, can't run without hardware. :(");
      while (true) {
        delay(1); // do nothing, no point running without Ethernet hardware
      }
    }
    if (Ethernet.linkStatus() == LinkOFF) {
      Serial.println("Ethernet cable is not connected.");
    }
    // try to configure using IP address instead of DHCP:
    Ethernet.begin(mac, ip, myDns);
  } else {
    Serial.print("  DHCP assigned IP ");
    Serial.println(Ethernet.localIP());
  }
  // give the Ethernet shield a second to initialize:
  delay(2000);
#endif

  Serial.print("connecting to ");
  Serial.print(server);
  Serial.println("...");

  // if you get a connection, report back via serial:
  auto start = millis();
  // specify the server and port, 443 is the standard port for HTTPS
  if (client.connect(server, 443)) {
    auto time = millis() - start;
    Serial.print("connected to ");
    Serial.println(client.remoteIP());
    Serial.print("Took: ");
    Serial.println(time);
    // Make a HTTP request:
    client.println("GET /a/check HTTP/1.1");
    client.println("User-Agent: SSLClientOverEthernet");
    client.print("Host: ");
    client.println(server_host);
    client.println("Connection: close");
    client.println();
    client.flush();
  } else {
    // if you didn't get a connection to the server:
    Serial.println("connection failed");
  }
  beginMicros = micros();
}

void loop() {
  // if the server's disconnected, stop the client:
  if (client.connected()) {
    // if there are incoming bytes available
    // from the server, read them and print them:
    int len = client.available();
    if (len > 0) {
      byte buffer[80];
      if (len > 80) len = 80;
      client.read(buffer, len);
      if (printWebData) {
        Serial.write(buffer, len); // show in the serial monitor (slows some boards)
      }
      byteCount = byteCount + len;
    }
  }
  else {
    endMicros = micros();
    Serial.println();
    Serial.println("disconnecting.");
    client.stop();
    Serial.print("Received ");
    Serial.print(byteCount);
    Serial.print(" bytes in ");
    float seconds = (float)(endMicros - beginMicros) / 1000000.0;
    Serial.print(seconds, 4);
    float rate = (float)byteCount / seconds / 1000.0;
    Serial.print(", rate = ");
    Serial.print(rate);
    Serial.print(" kbytes/second");
    Serial.println();

    // do nothing forevermore:
    while (true) {
      delay(1);
    }
  }
}
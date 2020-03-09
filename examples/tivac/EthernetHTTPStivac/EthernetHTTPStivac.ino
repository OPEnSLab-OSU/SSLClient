/*
  Web client

 This sketch connects to a website (http://www.arduino.cc/asciilogo.txt)
 using an Arduino Wiznet Ethernet shield and TLS. This

 Circuit:
 * Ethernet shield attached to pins 10, 11, 12, 13

 created 18 Dec 2009
 by David A. Mellis
 modified 9 March 2020
 by Noah Koontz, based on work by Adrian McEwen and Tom Igoe
 */

#include <SPI.h>
#include <Ethernet.h>
#include <SSLClient.h>
#include "trust_anchors.h"

#define BUFFLEN 80

// Enter a MAC address for your controller below.
// Newer Ethernet shields have a MAC address printed on a sticker on the shield
// byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
// With Tiva C the mac address could be changed with LM Flash Programmer

// if you don't want to use DNS (and reduce your sketch size)
// use the numeric IP instead of the name for the server:
//IPAddress server(54,85,55,79);  // numeric IP for Google (no DNS)
const char server[] = "www.arduino.cc";    // name address for Arduino (using DNS)
const char server_host[] = "www.arduino.cc"; // leave this alone, change only above two

// Set the static IP address to use if the DHCP fails to assign
IPAddress ip(192,168,2,177);
IPAddress myDns(8, 8, 8, 8);
IPAddress gw = IPAddress(192,168,2,1);
IPAddress mask = IPAddress(255,255,255,0);

// Choose the analog pin to get semi-random data from for SSL
// Pick a pin that's not connected or attached to a randomish voltage source
const int rand_pin = A5;

// Initialize the SSL client library
// We input an EthernetClient, our trust anchors, and the analog pin
EthernetClient base_client;
SSLClient client(base_client, TAs, (size_t)TAs_NUM, rand_pin);
// Variables to measure the speed
unsigned long beginMicros, endMicros;
unsigned long byteCount = 0;
bool printWebData = true;  // set to false for better speed measurement

void setup() {
  // Open serial communications and wait for port to open:
  Serial.begin(115200);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }
  
  // start the Ethernet connection:
  Serial.println(F("Initialize Ethernet with DHCP:"));
  //if (Ethernet.begin(mac) == 0) {
  if (Ethernet.begin(0) == 0) {  
    Serial.println(F("Failed to configure Ethernet using DHCP"));
    Ethernet.begin(0, ip, myDns, gw, mask);
  } else {
    Serial.print(F("  DHCP assigned IP "));
    Serial.println(Ethernet.localIP());
  }
  // give the Ethernet shield a second to initialize:
  delay(2000);
  
  Serial.print(F("connecting to "));
  Serial.print(server);
  Serial.println(F("..."));

  // if you get a connection, report back via serial:
  auto start = millis();
  // specify the server and port, 443 is the standard port for HTTPS
  if (client.connect(server, 443)) {
    auto time = millis() - start;
    Serial.print(F("Took: "));
    Serial.println(time);
    // Make a HTTP request:
    client.println(F("GET /asciilogo.txt HTTP/1.1"));
    client.println(F("User-Agent: SSLClientOverEthernet"));
    client.print(F("Host: "));
    client.println(server_host);
    client.println(F("Connection: close"));
    client.println();
  } else {
    // if you didn't get a connection to the server:
    Serial.println(F("connection failed"));
  }
  beginMicros = micros();
}

void loop() {
  // if there are incoming bytes available
  // from the server, read them and print them:
  int len = client.available();
  while (len > 0) {
    byte buffer[BUFFLEN];
    if (len > BUFFLEN) len = BUFFLEN;
    client.read(buffer, len);
    if (printWebData) {
      Serial.write(buffer, len); // show in the serial monitor (slows some boards)
    }
    byteCount = byteCount + len;
    len = client.available();
  }

    // if the server's disconnected, stop the client:
  if (!client.connected()) {
    endMicros = micros();
    Serial.println();
    Serial.println(F("disconnecting."));
    client.stop();
    Serial.print(F("Received "));
    Serial.print(byteCount);
    Serial.print(F(" bytes in "));
    float seconds = (float)(endMicros - beginMicros) / 1000000.0;
    Serial.print(seconds, 4);
    float rate = (float)byteCount / seconds / 1000.0;
    Serial.print(F(", rate = "));
    Serial.print(rate);
    Serial.print(F(" kbytes/second"));
    Serial.println();

    // do nothing forevermore:
    while (true) {
      delay(1);
    }
  }
}

/*
  Connect to AWS IOT using SSLClient and Wiz850io Ethernet Mdoule
   AWS_Root_CA.h is the trust anchor created using the Root CA from:
   https://www.amazontrust.com/repository/AmazonRootCA1.pem
   You can re-create it again using the python file present 
   in SSLClient/tools/pycert_bearssl/pycert_bearssl.py
   python pycert_bearssl.py convert --no-search <certificate PEM file>
   refer: https://github.com/OPEnSLab-OSU/SSLClient/issues/17#issuecomment-700143405
   
  Circuit:
   Ethernet shield WIZ850io:
   CS        10
   MOSI      11
   MISO      12
   SCK       13
   
  created 10 October 2020
  by Ram Rohit Gannavarapu
*/

#include <SPI.h>
#include <EthernetLarge.h>
#include <SSLClient.h>
#include <PubSubClient.h>
#include "AWS_Root_CA.h" // This file is created using AmazonRootCA1.pem from https://www.amazontrust.com/repository/AmazonRootCA1.pem

#define THING_NAME "<Thing_Name>"
#define MQTT_PACKET_SIZE  1024

void MQTTPublish(const char *topic, char *payload);
void updateThing();

const char my_cert[] = \
"-----BEGIN CERTIFICATE-----\n" \
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" \
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" \
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" \
"-----END CERTIFICATE-----\n";

const char my_key[] = \
"-----BEGIN RSA PRIVATE KEY-----\n" \
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" \
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" \
"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" \
"-----END RSA PRIVATE KEY-----\n";

SSLClientParameters mTLS = SSLClientParameters::fromPEM(my_cert, sizeof my_cert, my_key, sizeof my_key);

const char* mqttServer = "xxxxxxxxxxxx-ats.iot.us-east-1.amazonaws.com";
const char publishShadowUpdate[] = "$aws/things/" THING_NAME "/shadow/update";
char publishPayload[MQTT_PACKET_SIZE];
char *subscribeTopic[5] =
{
  "$aws/things/" THING_NAME "/shadow/update/accepted",
  "$aws/things/" THING_NAME "/shadow/update/rejected",
  "$aws/things/" THING_NAME "/shadow/update/delta",
  "$aws/things/" THING_NAME "/shadow/get/accepted",
  "$aws/things/" THING_NAME "/shadow/get/rejected"
};

void callback(char* topic, byte* payload, unsigned int length) 
{
  Serial.print("Message arrived [");
  Serial.print(topic);
  Serial.print("] ");
  for (int i=0;i<length;i++) 
  {
    Serial.print((char)payload[i]);
  }
  Serial.println();
}


EthernetClient ethClient;
SSLClient ethClientSSL(ethClient, TAs, (size_t)TAs_NUM, A5);
PubSubClient mqtt(mqttServer, 8883, callback, ethClientSSL);

// Enter a MAC address for your controller below.
// Newer Ethernet shields have a MAC address printed on a sticker on the shield
byte mac[] = {
  0x00, 0xAA, 0xBB, 0xCC, 0xDE, 0x02
};

void reconnect() 
{
  while (!mqtt.connected()) 
  {
    Serial.print("Attempting MQTT connection...");
    if (mqtt.connect("arduinoClient")) 
    {
      Serial.println("connected");
      for (int i = 0; i < 5; i++) 
      {
//        Serial.println(subscribeTopic[i]);
        mqtt.subscribe(subscribeTopic[i]);
      }
        Serial.println("Started updateThing ");
        updateThing();
        Serial.println("Done updateThing ");

    } 
    else 
    {
      Serial.print("failed, rc=");
      Serial.print(mqtt.state());
      Serial.println(" try again in 5 seconds");
      delay(5000);
    }
  }
}

void setup() {
  // You can use Ethernet.init(pin) to configure the CS pin
  Ethernet.init(10);  // Most Arduino shields

  // Open serial communications and wait for port to open:
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }
 ethClientSSL.setMutualAuthParams(mTLS);
  mqtt.setBufferSize(MQTT_PACKET_SIZE);

  // start the Ethernet connection:
  Serial.println("Initialize Ethernet with DHCP:");
  if (Ethernet.begin(mac) == 0) {
    Serial.println("Failed to configure Ethernet using DHCP");
    if (Ethernet.hardwareStatus() == EthernetNoHardware) {
      Serial.println("Ethernet shield was not found.  Sorry, can't run without hardware. :(");
    } else if (Ethernet.linkStatus() == LinkOFF) {
      Serial.println("Ethernet cable is not connected.");
    }
    // no point in carrying on, so do nothing forevermore:
    while (true) {
      delay(1);
    }
  }
  // print your local IP address:
  Serial.print("My IP address: ");
  Serial.println(Ethernet.localIP());

}

void loop() {
  if (!mqtt.connected()) 
  {
    reconnect();
  }
  mqtt.loop();
}


void updateThing()
{
  strcpy(publishPayload, "{\"state\": {\"reported\": {\"powerState\":\"ON\"}}}");
  MQTTPublish(publishShadowUpdate, publishPayload);

}

void MQTTPublish(const char *topic, char *payload)
{
  mqtt.publish(topic, payload);
  Serial.print("Published [");
  Serial.print(topic);
  Serial.print("] ");
  Serial.println(payload);
}

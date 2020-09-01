# Trust Anchors
## Background

SSLClient uses BearSSL's [minimal x509 verification engine](https://bearssl.org/x509.html#the-minimal-engine) to verify the certificate of an SSL connection. This engine requires the developer create a trust anchor array using values stored in trusted root certificates. In short, these trust anchor arrays allow BearSSL to verify that the server being connected to is who they say they are, and not someone malicious. You can read more about certificates and why they are important [here](https://www.globalsign.com/en/ssl-information-center/what-is-an-ssl-certificate/).

SSLClient stores trust anchors in hardcoded constant variables, passed into `SSLClient::SSLClient` during setup. These constants are generally stored in their own header file as found in [the BearSSL docs](https://bearssl.org/api1.html#profiles). This header file will look something like:
```C++
#define TAs_NUM 1

static const unsigned char TA_DN0[] = {
    // lots of raw bytes here
    // ...
};

static const unsigned char TA_RSA_N0[] = {
    // lots of raw bytes here
    //...
};

static const unsigned char TA_RSA_E0[] = {
    // 1-3 bytes here
};

static const br_x509_trust_anchor TAs[] = {
    {
        { (unsigned char *)TA_DN0, sizeof TA_DN0 },
        BR_X509_TA_CA,
        {
            BR_KEYTYPE_RSA,
            { .rsa = {
                (unsigned char *)TA_RSA_N0, sizeof TA_RSA_N0,
                (unsigned char *)TA_RSA_E0, sizeof TA_RSA_E0,
            } }
        }
    },
};
```
A full example of a trust anchor header can be found in [this file](./readme/cert.h). Full documentation for the format of these variables can be found in the [BearSSL documentation for br_x509_trust_anchor](https://bearssl.org/apidoc/structbr__x509__trust__anchor.html). 



## Generating Trust Anchors

Typically a trust anchor header file is generated using [brssl](https://bearssl.org/gitweb/?p=BearSSL;a=tree;f=tools;h=0fa053e41d6bf88a28472f3b22dde41b21f14292;hb=dda1f8a0c46e15b4a235163470ff700b2f13dcc5), a command-line utility included in BearSSL. As it is a fairly involded process to get brssl working, SSLClient provides a number of alternative tools to make the generation process a bit easier.

**Note:** When working with certificates (particularly in complicated mTLS setups), it can easily become confusing which certificate does what. If you aren't sure what certificate to put into the Trust Anchor tool, remember that Trust Anchors *only care about the verifying the server*: in other words, the certificate that goes into a Trust Anchor generation tool should be the certificate used to generate the server's certificate (usually a CA). Trust Anchors will never contain any information about client certificates, which should be passed into [SSLClientParams](https://github.com/OPEnSLab-OSU/SSLClient#mtls) instead.

### HTTPS

For HTTPS, there a couple of tools you can use. Ordered from easiest to hardest:
* This website, written to simplify the creation of trust anchor headers: https://openslab-osu.github.io/bearssl-certificate-utility/. Simply plug and play.
* [pycert_bearssl](./tools/pycert_bearssl/pycert_bearssl.py), a command line utility based on a [pycert](https://learn.adafruit.com/introducing-the-adafruit-wiced-feather-wifi/pycert-dot-py). You will need to install Python 3, and follow the instructions in the [pycert_bearssl.py file](./tools/pycert_bearssl/pycert_bearssl.py). You'll want to use the `pycert_bearssl.py download` command once the utility is set up.
* The `brssl` command line utility, included in the [BearSSL source](https://bearssl.org/gitweb/?p=BearSSL;a=blob_plain;f=tools/brssl.h;hb=HEAD). You will need to compile this file yourself.

### Other Connections

For other kinds of SSL connections, you will need to find the root certificate being used by your host. You can check out [this StackExchange post](https://superuser.com/questions/97201/how-to-save-a-remote-server-ssl-certificate-locally-as-a-file) for numerous methods of acquiring this certificate from a server. If these methods are not sufficient, you may need to request this certificate from your network administrator. Once you have the certificate, convert it to PEM format if needed (I use [this website](https://www.sslshopper.com/ssl-converter.html)), and use the `pycert_bearssl.py convert --no-search` command to convert the certificate into a trust anchor header.

## Using Trust Anchors

Once you've generated a trust anchor array, add it to your Arduino sketch using the `Sketch->Add File` button in the Arduino IDE, and link it to your SSLClient like so:
```C++
#include "yourtrustanchorfile.h"
// ...
SSLClient client(SomeClient, TAs, (size_t)TAs_NUM, SomePin);
// ...
```
Where `yourtrustanchorfile.h` contains a generated trust anchor array names `TAs`, with length `TAs_NUM`. BearSSL will now automatically use these trust anchors when `SSLClient::connect` is called.

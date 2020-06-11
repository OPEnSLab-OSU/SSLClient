# Contributing

Thank you for contributing to SSLClient! This library is a single-person effort, so help is always appreciated. 

There is no formal style guide, however this project does attempt to provide detailed documentation through the README and [Doxygen block comments](https://www.doxygen.nl/manual/docblocks.html) which are highly encouraged. If you get stuck or have a question, please feel free to [submit an issue](https://github.com/OPEnSLab-OSU/SSLClient/issues/new?assignees=&labels=question&template=question.md&title=). Below are some resources to get you started:
 * **TLS**
   * [How does SSL work? (StackOverflow)](https://security.stackexchange.com/questions/20803/how-does-ssl-tls-work)
   * [What happens in a TLS handshake? (Cloudflare)](https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake/)
   * [What is mTLS? (wott.io)](https://wott.io/blog/tutorials/2019/09/09/what-is-mtls)
 * **BearSSL**
   * [BearSSL Homepage](https://bearssl.org/)
   * [BearSSL TLS API Overview](https://bearssl.org/api1.html) (SSLClient uses the Generic I/O version ot the API).
   * [BearSSL Certificate API Overview](https://bearssl.org/x509.html) (SSLClient uses the Minimal Engine)
   * [BearSSL Doxygen](https://bearssl.org/apidoc/index.html)
 * **SSLClient**
   * [README](./README.md)
   * [Trust Anchors Overview](./TrustAnchors.md)
   * [Known ESP32 Issue with PubSubClient](https://github.com/OPEnSLab-OSU/SSLClient/issues/9)
   * [Known ESP8266 Issue with any TLS Connection](https://github.com/OPEnSLab-OSU/SSLClient/issues/5)
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
 * which is also use in the Arduino ESP8266 core. SSLClient will serve to implement the
 * BearSSL functionality inbetween EthernetCLient and the User, such that the user will
 * simply need to start with:
 * SSLCLient client(ethCLient);
 * And then call the functions they normally would with EthernetClient using SSLCLient.
 */

#include "bearssl.h"

#ifdef SSLClient_H_
#define SSLClient_H_




#endif /** SSLClient_H_ */
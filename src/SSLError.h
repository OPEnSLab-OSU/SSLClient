#ifndef SSLError_H_
#define SSLError_H_

#include <stdint.h>

/**
 * @brief Static constants defining the possible errors encountered.
 * 
 * If SSLClient encounters an error, it will generally output
 * logs into the serial monitor. If you need a way of programmatically
 * checking the errors, you can do so with SSLClient::getWriteError(),
 * which will return one of these values.
 */
enum class SSLError : const uint8_t {
    SSL_OK = 0,
    /** The underlying client failed to connect, probably not an issue with SSL */
    SSL_CLIENT_CONNECT_FAIL = 2,
    /** BearSSL failed to complete the SSL handshake, check logs for bear ssl error output */
    SSL_BR_CONNECT_FAIL = 3,
    /** The underlying client failed to write a payload, probably not an issue with SSL */
    SSL_CLIENT_WRTIE_ERROR = 4,
    /** An internal error occurred with BearSSL, check logs for diagnosis. */
    SSL_BR_WRITE_ERROR = 5,
    /** An internal error occurred with SSLClient, and you probably need to submit an issue on Github. */
    SSL_INTERNAL_ERROR = 6,
    /** SSLClient detected that there was not enough memory (>8000 bytes) to continue. */
    SSL_OUT_OF_MEMORY = 7
};

#endif /** SSLError_H_ */

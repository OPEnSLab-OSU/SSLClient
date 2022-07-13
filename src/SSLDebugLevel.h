#ifndef SSLDebugLevel_H_
#define SSLDebugLevel_H_

#include <stdint.h>

/**
 * @brief Level of verbosity used in logging for SSLClient.
 * 
 * Use these values when initializing SSLClient to set how many logs you
 * would like to see in the Serial monitor.
 */
enum class SSLDebugLevel : const uint8_t {
    /** No logging output */
    SSL_NONE = 0,
    /** Only output errors that result in connection failure */
    SSL_ERROR = 1,
    /** Output errors and warnings (useful when just starting to develop) */
    SSL_WARN = 2,
    /** Output errors, warnings, and internal information (very verbose) */
    SSL_INFO = 3,
    /** In addition to the above logs, dumps every byte in SSLClient::write to the Serial monitor */
    SSL_DUMP = 4
};

#endif /** SSLDebugLevel_H_ */

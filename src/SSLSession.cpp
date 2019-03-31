#include "SSLSession.h"

/* See SSLSession.h */
void SSLSession::set_parameters(const IPAddress& ip, const char* hostname) {
    // copy the hostname
    if (hostname != NULL) m_hostname = hostname;
    // or if there's no hostname, clear the string
    else m_hostname = "";
    // and the IP address
    m_ip = ip;
    // check if both values are valid, and if so set valid to true
    if (m_ip != INADDR_NONE && session_id_len > 0
        && (hostname == NULL || m_hostname)) m_valid_session = true;
    // else clear
    else clear_parameters();
}

/* see SSLSession.h */
void SSLSession::clear_parameters() {
    // clear the hostname , ip, and valid session flags
    m_hostname = "";
    m_ip = INADDR_NONE;
    m_valid_session = false;
}
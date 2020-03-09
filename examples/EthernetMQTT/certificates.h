#ifndef _CERTIFICATES_H_
#define _CERTIFICATES_H_

#ifdef __cplusplus
extern "C"
{
#endif

/* You will need to generate the information in this file manually
 * using pycert_bearssl. For more information, please see
 * https://github.com/OPEnSLab-OSU/SSLClient/blob/master/TrustAnchors.md
 */

#define TAs_NUM 1

static const unsigned char TA_DN0[] = {
    // FIXME
};

static const unsigned char TA_RSA_N0[] = {
    // FIXME
};

static const unsigned char TA_RSA_E0[] = {
    // FIXME
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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ifndef _CERTIFICATES_H_ */
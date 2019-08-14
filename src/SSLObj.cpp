#include "SSLObj.h"

// fix for non-exception arduino platforms
#ifdef ADAFRUIT_FEATHER_M0
namespace std {
    void __throw_length_error(char const*) {}
}
#endif

struct ssl_pem_decode_state {
    std::vector<unsigned char>* vect;
    size_t index = 0;
};

static void ssl_pem_decode_callback(void *dest_ctx, const void *src, size_t len) {
    ssl_pem_decode_state* ctx = static_cast<ssl_pem_decode_state*>(dest_ctx);
    for (size_t i = 0; i < len; i++) ctx->vect->emplace_back(static_cast<const unsigned char*>(src)[i]);
    // update index
    ctx->index += len;
}

const std::vector<unsigned char> SSLObj::make_vector_pem(const char* data, const size_t len) {
    if (data == nullptr || len < 80) return {};
    // initialize the bearssl PEM context
    br_pem_decoder_context pctx;
    br_pem_decoder_init(&pctx);
    // create a temporary vector
    std::vector<unsigned char> temp;
    // initialize the DER storage context
    ssl_pem_decode_state state;
    state.vect = &temp;
    state.index = 0;
    // set the byte reciever
    br_pem_decoder_setdest(&pctx, &ssl_pem_decode_callback, &state);
    // start decoding!
    int br_state = 0;
    size_t index = 0;
    do {
        index += br_pem_decoder_push(&pctx, static_cast<const void*>(&data[index]), len - index);
        br_state = br_pem_decoder_event(&pctx);
        // if we found the begining object, reserve the vector based on the remaining relavent bytes
        if (br_state == BR_PEM_BEGIN_OBJ) {
            // 22 = five dashes for header and footer + four newlines - character difference between `BEGIN` and `END`
            const size_t relavant_bytes_base64 = len - (2*strlen(br_pem_decoder_name(&pctx)) + 22);
            temp.reserve(relavant_bytes_base64 * 3 / 4);
        }
    } while (br_state != BR_PEM_ERROR && br_state != BR_PEM_END_OBJ && len != index);
    // error check
    if (br_state == BR_PEM_ERROR) {
        // set data to error
        temp.clear();
    }
    // else we're good!
    return temp;
}
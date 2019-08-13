#include "SSLObj.h"

struct ssl_pem_decode_state {
    std::vector<unsigned char>* vect;
    size_t index = 0;
};

static void ssl_pem_decode(void *dest_ctx, const void *src, size_t len) {
    ssl_pem_decode_state* ctx = static_cast<ssl_pem_decode_state*>(dest_ctx);
    // copy the recieved bytes into the vector, resizing if needed
    if (ctx->vect->size() < len + ctx->index) {
        Serial.println("Overflow!");
        return;
    }
    for (size_t i = 0; i < len; i++) (*(ctx->vect))[i + ctx->index] = static_cast<const unsigned char*>(src)[i];
    // update index
    ctx->index += len;
}

const std::vector<unsigned char> SSLObj::make_vector_pem(const char* data, const size_t len) {
    if (data == nullptr || len == 0) return { 0 };
    // initialize the bearssl PEM context
    br_pem_decoder_context pctx;
    br_pem_decoder_init(&pctx);
    // create a temporary vector
    std::vector<unsigned char> temp(len * 3 / 4 + 5);
    // initialize the DER storage context
    ssl_pem_decode_state state;
    state.vect = &temp;
    state.index = 0;
    // set the byte reciever
    br_pem_decoder_setdest(&pctx, &ssl_pem_decode, &state);
    // start decoding!
    int br_state = 0;
    size_t index = 0;
    do {
        index += br_pem_decoder_push(&pctx, static_cast<const void*>(&data[index]), len - index);
        br_state = br_pem_decoder_event(&pctx);
    } while (br_state != BR_PEM_ERROR && br_state != BR_PEM_END_OBJ);
    // error check
    if (br_state == BR_PEM_ERROR) {
        // set data to error
        temp.clear();
    }
    // else we're good!
    return { temp };
}

const std::vector<unsigned char> SSLObj::make_vector_der(const char* data, const size_t len) {
    if (data == nullptr || len == 0) return { 0 };
    // create a temporary vector
    std::vector<unsigned char> temp(len);
    // copy the elements over
    for (size_t i = 0; i < len; i++) temp[i] = data[i];
    // return the new SSLObj
    return { temp };
}
// Development-only wrapper for KDE's unmodified BlowFish (v6.18.0).
// Compile with blowfish.cc/blockcipher.cc and their headers; no evidence inputs.
#include "blowfish.h"
#include <cstring>
extern "C" int encrypt_native(void *data, int length, void *key, int key_length, int cbc) {
    BlowFish cipher;
    if (length < 0 || length % 8 || !cipher.setKey(key, key_length * 8)) return -1;
    unsigned char previous[8] = {};
    auto *bytes = static_cast<unsigned char *>(data);
    for (int offset = 0; offset < length; offset += 8) {
        if (cbc) for (int i = 0; i < 8; i++) bytes[offset + i] ^= previous[i];
        if (cipher.encrypt(bytes + offset, 8) != 8) return -1;
        std::memcpy(previous, bytes + offset, 8);
    }
    return length;
}

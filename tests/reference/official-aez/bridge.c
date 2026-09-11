/* Test-only bridge: include the unmodified official ref/encrypt.c so its
 * internal helpers can be checked too. Do not use with real wallet secrets. */
#include "encrypt.c"

void ref_extract(byte *key, byte *out) { Extract(key, 32, out); }
void ref_raw_decrypt(byte *key, byte *encoded, byte *out) {
    byte nonce[1] = {0}, ad[6], delta[16];
    byte *ads[] = {ad}; unsigned lengths[] = {6};
    ad[0] = encoded[0]; memcpy(ad + 1, encoded + 24, 5);
    AEZhash(key, 32, nonce, 0, ads, lengths, 1, 32, delta);
    Decipher(key, 32, delta, encoded + 1, 23, out);
}
void ref_encrypt(byte *key, byte *salt, byte *plain, byte *out) {
    byte nonce[1] = {0}, ad[6] = {0};
    byte *ads[] = {ad}; unsigned lengths[] = {6};
    memcpy(ad + 1, salt, 5);
    Encrypt(key, 32, nonce, 0, ads, lengths, 1, 4, plain, 19, out);
}
int ref_decrypt(byte *key, byte *encoded, byte *out) {
    byte nonce[1] = {0}, ad[6];
    byte *ads[] = {ad}; unsigned lengths[] = {6};
    ad[0] = encoded[0]; memcpy(ad + 1, encoded + 24, 5);
    return Decrypt(key, 32, nonce, 0, ads, lengths, 1, 4, encoded + 1, 23, out);
}

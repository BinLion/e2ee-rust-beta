#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct SharedKey {
  unsigned char data[32];
};

struct Signature {
  unsigned char data[64];
};

struct Address {
  char *name;
  unsigned int name_len;
  int device_id;
  int device_type;
};

struct DataWrap {
  const char *data;
  unsigned int length;
};

struct MessageBuf {
  const char *data;
  unsigned int length;
  unsigned int message_type;
};

struct EcKeyPair {
  unsigned char public_key[32];
  unsigned char private_key[32];
};

typedef struct EcKeyPair IdentityKeyPair;

struct PreKey {
  unsigned char public_key[32];
  unsigned char private_key[32];
  unsigned int key_id;
  unsigned long long timestamp;
};

struct PreKeyNode {
  struct PreKey *element;
  struct PreKeyNode *next;
};

struct SignedPreKey {
  unsigned char public_key[32];
  unsigned char private_key[32];
  unsigned char signature[64];
  unsigned int key_id;
  unsigned long long timestamp;
};

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

int curve_calculate_agreement(struct SharedKey **shared_key_data,
                              const unsigned char (*public_key)[32],
                              const unsigned char (*private_key)[32]);

int curve_calculate_signature(struct Signature **signature,
                              const unsigned char *message,
                              unsigned int mlen,
                              const unsigned char (*identity_private_key)[32]);

int curve_verify_signature(const unsigned char (*public_key)[32],
                           const unsigned char *message,
                           unsigned int mlen,
                           const unsigned char (*signature)[64]);

void free_address(const struct Address *address);

int generate_address(struct Address **address,
                     char *name,
                     unsigned int name_len,
                     int id,
                     int device_type);

int generate_buf(struct DataWrap **buf, const char *data, unsigned int length);

int generate_message_buf(struct MessageBuf **buf,
                         const char *data,
                         unsigned int length,
                         unsigned int message_type);

int group_cipher_decode(struct MessageBuf **decrypted_message,
                        char *group_id,
                        unsigned int group_len,
                        const struct Address *address,
                        const char *cipher_text,
                        unsigned int text_len);

int group_cipher_encode(struct MessageBuf **encrypted_message,
                        const char *group_id,
                        unsigned int group_len,
                        const struct Address *address,
                        const char *plain_text,
                        unsigned int text_len);

int group_create_distribution_message(struct MessageBuf **distribution_message,
                                      const char *group_id,
                                      unsigned int group_len,
                                      const struct Address *address);

int group_get_distribution_message(struct MessageBuf **distribution_message,
                                   const char *group_id,
                                   unsigned int group_len,
                                   const struct Address *address);

int group_process_distribution_message(const struct MessageBuf *distribution_message,
                                       const char *group_id,
                                       unsigned int group_len,
                                       const struct Address *address);

bool has_sender_chain(const struct Address *address);

int initE2eeSdkLogger(const char *level);

int initE2eeSdkLoggerV2(const char *level, const char *file);

int key_helper_generate_ec_key_pair(struct EcKeyPair **key_pair);

int key_helper_generate_identity_key_pair(IdentityKeyPair **key_pair);

int key_helper_generate_pre_keys(struct PreKeyNode **head,
                                 unsigned int start,
                                 unsigned int count,
                                 unsigned long long timestamp);

int key_helper_generate_signed_pre_key(struct SignedPreKey **key_pair,
                                       const IdentityKeyPair *identity_key_pair,
                                       unsigned int key_id);

int process_with_key_bundle(const struct Address *address,
                            unsigned int registration_id,
                            unsigned int device_id,
                            const unsigned char (*pre_key)[32],
                            unsigned int pre_key_id,
                            const unsigned char (*signed_pre_key)[32],
                            unsigned int signed_pre_key_id,
                            const unsigned char (*signature)[64],
                            const unsigned char (*identity_key)[32],
                            const char *signed_data,
                            unsigned int signed_data_len);

int session_cipher_decrypt(struct DataWrap **out,
                           const struct MessageBuf *encrypted_message,
                           const struct Address *address);

int session_cipher_encrypt(struct MessageBuf **encrypted_message,
                           const struct Address *address,
                           const char *plain_text,
                           unsigned int text_len);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

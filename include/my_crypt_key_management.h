
#ifndef INCLUDE_MY_CRYPT_KEY_MANAGMENT_INCLUDED
#define INCLUDE_MY_CRYPT_KEY_MANAGMENT_INCLUDED

#include "my_global.h"
#include "my_pthread.h"
#include "mysql/psi/psi.h"

#ifndef DBUG_OFF
extern my_bool debug_use_static_crypto_keys;

#ifdef HAVE_PSI_INTERFACE
extern PSI_rwlock_key key_LOCK_dbug_crypto_key_version;
#endif

extern mysql_rwlock_t LOCK_dbug_crypto_key_version;
extern uint opt_debug_crypto_key_version;
#endif /* DBUG_OFF */

C_MODE_START

/**
 * Functions to interact with key management
 */

int GetLatestCryptoKeyVersion();
unsigned int HasCryptoKey(unsigned int version);
int GetCryptoKeySize(unsigned int version);
int GetCryptoKey(unsigned int version, unsigned char* key_buffer,
                 unsigned int size);
int GetCryptoIV(unsigned int version, unsigned char* key_buffer,
                unsigned int size);

C_MODE_END

#endif // INCLUDE_MY_CRYPT_KEY_MANAGMENT_INCLUDED

#include <my_global.h>
#include <mysql/plugin_cryptokey_management.h>
#include "cryptokey.h"
#include "log.h"
#include "sql_plugin.h"

#ifndef DBUG_OFF
#include <arpa/inet.h>
my_bool debug_use_static_crypto_keys = 0;
uint opt_debug_crypto_key_version = 0;
#endif

/* there can be only one cryptokey management plugin enabled */
static plugin_ref cryptokey_manager= 0;
static struct st_mariadb_cryptokey_management *handle;

uint get_latest_crypto_key_version()
{
#ifndef DBUG_OFF
  if (debug_use_static_crypto_keys)
  {
    //mysql_mutex_lock(&LOCK_global_system_variables);
    uint res = opt_debug_crypto_key_version;
    //mysql_mutex_unlock(&LOCK_global_system_variables);
    return res;
  }
#endif

  if (cryptokey_manager)
    return handle->get_latest_key_version();

  return BAD_CRYPTOKEY_VERSION;
}

uint has_crypto_key(uint version)
{
  if (cryptokey_manager)
    return handle->has_key_version(version);

  return 0;
}

uint get_crypto_key_size(uint version)
{
  if (cryptokey_manager)
    return handle->get_key_size(version);

  return 0;
}

int get_crypto_key(uint version, uchar* key, uint size)
{
#ifndef DBUG_OFF
  if (debug_use_static_crypto_keys)
  {
    memset(key, 0, size);
    // Just don't support tiny keys, no point anyway.
    if (size < sizeof(version))
      return 1;

    version = htonl(version);
    memcpy(key, &version, sizeof(version));
    return 0;
  }
#endif

  if (cryptokey_manager)
    return handle->get_key(version, key, size);

  return 1;
}

int get_crypto_iv(uint version, uchar* iv, uint size)
{
  if (cryptokey_manager)
    return handle->get_iv(version, iv, size);

  return 1;
}

int initialize_cryptokey_management_plugin(st_plugin_int *plugin)
{
  if (cryptokey_manager)
    return 1;

  if (plugin->plugin->init && plugin->plugin->init(plugin))
  {
    sql_print_error("Plugin '%s' init function returned error.",
                    plugin->name.str);
    return 1;
  }

  cryptokey_manager= plugin_lock(NULL, plugin_int_to_ref(plugin));
  handle= (struct st_mariadb_cryptokey_management*)
            plugin->plugin->info;
  return 0;
}

int finalize_cryptokey_management_plugin(st_plugin_int *plugin)
{
  DBUG_ASSERT(cryptokey_manager);

  if (plugin->plugin->deinit && plugin->plugin->deinit(NULL))
  {
    DBUG_PRINT("warning", ("Plugin '%s' deinit function returned error.",
                           plugin->name.str));
  }
  plugin_unlock(NULL, cryptokey_manager);
  cryptokey_manager= 0;
  return 0;
}


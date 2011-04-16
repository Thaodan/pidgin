/**
 * @file privatekey.h Private-Key API
 * @ingroup core
 * @see @ref privatekey-signals
 * @since 2.2.0
 */

/*
 *
 * purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *a
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#ifndef _PURPLE_PRIVATEKEY_H
#define _PURPLE_PRIVATEKEY_H

#include <time.h>

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _PurplePrivateKey PurplePrivateKey;
typedef struct _PurplePrivateKeyPool PurplePrivateKeyPool;
typedef struct _PurplePrivateKeyScheme PurplePrivateKeyScheme;

/** A private key instance
 *
 *  An opaque data structure representing a single private key under some
 *  PrivateKeyScheme
 */
struct _PurplePrivateKey
{
	/** Scheme this private key is under */
	PurplePrivateKeyScheme * scheme;
	/** Opaque pointer to internal data */
	gpointer data;
};

/**
 * Database for retrieval or storage of PrivateKeys
 *
 * More or less a hash table; all lookups and writes are controlled by a string
 * key.
 */
struct _PurplePrivateKeyPool
{
	/** Scheme this Pool operates for */
	gchar *scheme_name;
	/** Internal name to refer to the pool by */
	gchar *name;

	/** User-friendly name for this type
	 *  ex: N_("SSL Servers")
	 *  When this is displayed anywhere, it should be i18ned
	 *  ex: _(pool->fullname)
	 */
	gchar *fullname;

	/** Internal pool data */
	gpointer data;

	/**
	 * Set up the Pool's internal state
	 *
	 * Upon calling purple_privatekey_register_pool() , this function will
	 * be called. May be NULL.
	 * @return TRUE if the initialization succeeded, otherwise FALSE
	 */
	gboolean (* init)(void);

	/**
	 * Uninit the Pool's internal state
	 *
	 * Will be called by purple_privatekey_unregister_pool() . May be NULL
	 */
	void (* uninit)(void);
	
	/**
	 * Use password to protect the keys on disk on the pool using the password.
	 *
	 * @param password 
	 */
	//void (* set_password)(const gchar* password);

	/** Check for presence of a private key in the pool using unique ID */
	gboolean (* key_in_pool)(const gchar *id);

	/** Retrieve a PurplePrivateKey from the pool */
	PurplePrivateKey * (* get_key)(const gchar *id, const gchar* password);

	/** Add a private key to the pool. Must overwrite any other
	 *  keys sharing the same ID in the pool.
	 *  @return TRUE if the operation succeeded, otherwise FALSE
	 */
	gboolean (* put_key)(const gchar *id, PurplePrivateKey *crt, const gchar* password);

	/** Delete a key from the pool */
	gboolean (* delete_key)(const gchar *id);

	/** Returns a list of IDs stored in the pool */
	GList * (* get_idlist)(void);

	void (*_purple_reserved1)(void);
	void (*_purple_reserved2)(void);
	void (*_purple_reserved3)(void);
	void (*_purple_reserved4)(void);
};

/** A private key type
 *
 *  A PrivateKeyScheme must implement all of the fields in the structure,
 *  and register it using purple_privatekey_register_scheme()
 *
 *  There may be only ONE PrivateKeyScheme provided for each certificate
 *  type, as specified by the "name" field.
 */
struct _PurplePrivateKeyScheme
{
	/** Name of the private key type
	 *  ex: "x509", "pgp", etc.
	 *  This must be globally unique - you may not register more than one
	 *  PrivateKeyScheme of the same name at a time.
	 */
	gchar * name;

	/** User-friendly name for this type
	 *  ex: N_("X.509 PrivateKeys")
	 *  When this is displayed anywhere, it should be i18ned
	 *  ex: _(scheme->fullname)
	 */
	gchar * fullname;

	/** Imports a private key from a file
	 *
	 *  @param filename   File to import the private key from
	 *  @param password   Password to decrypt the key file.
	 *  @return           Pointer to the newly allocated PrivateKey struct
	 *                    or NULL on failure.
	 */
	PurplePrivateKey * (* import_key)(const gchar * filename, const gchar * password);

	/**
	 * Exports a private key to a file
	 *
	 * @param filename    File to export the private key to
	 * @param key         PrivateKey to export
	 * @param password    Password t encrypt the key file
	 * @return TRUE if the export succeeded, otherwise FALSE
	 * @see purple_privatekey_export()
	 */
	gboolean (* export_key)(const gchar *filename, PurplePrivateKey *key, const gchar* password);

	/**
	 * Duplicates a private key
	 *
	 * Keys are generally assumed to be read-only, so feel free to
	 * do any sort of reference-counting magic you want here. If this ever
	 * changes, please remember to change the magic accordingly.
	 * @return Reference to the new copy
	 */
	PurplePrivateKey * (* copy_key)(PurplePrivateKey *key);

	/** Destroys and frees a PrviateKey structure
	 *
	 *  Destroys a PrivateKey's internal data structures and calls
	 *  free(key)
	 *
	 *  @param key  PrviateKey instance to be destroyed. It WILL NOT be
	 *              destroyed if it is not of the correct
	 *              PrivateKeyScheme. Can be NULL
	 */
	void (* destroy_key)(PurplePrivateKey * key);

	/**
	 * Retrieves a unique key identifier
	 *
	 * @param key PrivateKey instance
	 * @return Newly allocated string that can be used to uniquely
	 *         identify the key.
	 */
	gchar* (* get_unique_id)(PurplePrivateKey *key);

	void (*_purple_reserved1)(void);
	void (*_purple_reserved2)(void);
	void (*_purple_reserved3)(void);
};

/*@}*/

/*****************************************************************************/
/** @name Private Key Functions                                              */
/*****************************************************************************/
/*@{*/

/**
 * Makes a duplicate of a private key
 *
 * @param key        Instance to duplicate
 * @return Pointer to new instance
 */
PurplePrivateKey *
purple_privatekey_copy(PurplePrivateKey *key);

/**
 * Destroys and free()'s a PrivateKey
 *
 * @param key        Instance to destroy. May be NULL.
 */
void
purple_privatekey_destroy (PurplePrivateKey *key);

/**
 * Imports a PurplePrivateKey from a file
 *
 * @param scheme      Scheme to import under
 * @param filename    File path to import from
 * @param password    Password to protecting the key on disk
 * @return Pointer to a new PurplePrivateKey, or NULL on failure
 */
PurplePrivateKey *
purple_privatekey_import(PurplePrivateKeyScheme *scheme, const gchar *filename, const gchar *password);

/**
 * Exports a PurplePrivateKey to a file
 *
 * @param filename    File to export the key to
 * @param key         Key to export
 * @param password    Password to protect the key on disk
 * @return TRUE if the export succeeded, otherwise FALSE
 */
gboolean
purple_privatekey_export(const gchar *filename, PurplePrivateKey *key, const gchar *password);

/**
 * Get a unique identifier for the private key
 *
 * @param key        PrivateKey instance
 * @return String representing the key uniquely. Must be g_free()'ed
 */
gchar *
purple_privatekey_get_unique_id(PurplePrivateKey *key);

/*@}*/

/*****************************************************************************/
/** @name Private Key Pool Functions                                         */
/*****************************************************************************/
/*@{*/
/**
 * Helper function for generating file paths in ~/.purple/certificates for
 * PrivateKeyPools that use them.
 *
 * All components will be escaped for filesystem friendliness.
 *
 * @param pool   PrivateKeyPool to build a path for
 * @param id     Key to look up a PrivateKey by. May be NULL.
 * @return A newly allocated path of the form
 *         ~/.purple/certificates/scheme_name/pool_name/unique_id
 */
gchar *
purple_privatekey_pool_mkpath(PurplePrivateKeyPool *pool, const gchar *id);

/**
 * Determines whether a pool can be used.
 *
 * Checks whether the associated PrivateKeyScheme is loaded.
 *
 * @param pool   Pool to check
 *
 * @return TRUE if the pool can be used, otherwise FALSE
 */
gboolean
purple_privatekey_pool_usable(PurplePrivateKeyPool *pool);

gboolean
purple_privatekey_pool_set_password(PurplePrivateKeyPool *pool, const gchar* password);

const gchar* purple_privatekey_pool_get_password(PurplePrivateKeyPool *pool);

/**
 * Looks up the scheme the pool operates under
 *
 * @param pool   Pool to get the scheme of
 *
 * @return Pointer to the pool's scheme, or NULL if it isn't loaded.
 * @see purple_privatekey_pool_usable()
 */
PurplePrivateKeyScheme *
purple_privatekey_pool_get_scheme(PurplePrivateKeyPool *pool);

/**
 * Check for presence of an ID in a pool.
 * @param pool   Pool to look in
 * @param id     ID to look for
 * @return TRUE if the ID is in the pool, else FALSE
 */
gboolean
purple_privatekey_pool_contains(PurplePrivateKeyPool *pool, const gchar *id);


typedef void (*PurplePrivateKeyPoolCancelCb)(void* data);
typedef void (*PurplePrivateKeyPoolRetrieveRequestOkCb)(PurplePrivateKey *key, void* data);
typedef void (*PurplePrivateKeyPoolStoreRequestOkCb)(gboolean result, void* data);

/**
 * Retrieve a key from a pool and prompt user for the password protecting the key.
 *
 * @param pool      Pool to get key from
 * @param id        ID of key to retrieve
 * @param ok_cb     Called if the user clicks ok in the password prompt.
 *                  The key parameter to the callback is non-null if the key was successfully
 *                  retrieved from the pool and null otherwise.
 * @param cancel_cb Called if the user cancels the password dialog.
 * @param user_data Pointer to caller defined data structure to be passed to callbacks.
 */
void 
purple_privatekey_pool_retrieve_request(
	PurplePrivateKeyPool *pool, const gchar *id,
	GCallback ok_cb,
	GCallback cancel_cb,
	void* user_data);

/**
 * Store a key in the given pool and prompt user for a password to protect the key.
 *
 * @param pool      Pool to store key in
 * @param id        ID of key to store
 * @param key       Key to store.
 * @param ok_cb     Called if the user clicks ok in the password prompt.
 *                  The result parameter to the callback is true if the key was successfully
 *                  stored in the pool and false otherwise.
 * @param cancel_cb Called if the user cancels the password dialog.
 * @param user_data Pointer to caller defined data structure to be passed to callbacks.
 */
void 
purple_privatekey_pool_store_request(
	PurplePrivateKeyPool *pool, const gchar *id, PurplePrivateKey *key,
	GCallback ok_cb,
	GCallback cancel_cb,
	void* user_data);

/**
 * Retrieve a key from a pool.
 * @param pool     Pool to fish in
 * @param id       ID to look up
 * @param password Password used to encrypt key
 * @return Retrieved key, or NULL if it wasn't there
 */
PurplePrivateKey *
purple_privatekey_pool_retrieve(PurplePrivateKeyPool *pool, const gchar *id, const gchar *password);

/**
 * Add a key to a pool
 *
 * Any pre-existing key of the same ID will be overwritten.
 *
 * @param pool     Pool to add to
 * @param id       ID to store the key with
 * @param key      Key to store
 * @param password Password to decrypt key
 * @return TRUE if the operation succeeded, otherwise FALSE
 */
gboolean
purple_privatekey_pool_store(PurplePrivateKeyPool *pool, const gchar *id, PurplePrivateKey *key, const gchar *password);

/**
 * Remove a key from a pool
 *
 * @param pool   Pool to remove from
 * @param id     ID to remove
 * @return TRUE if the operation succeeded, otherwise FALSE
 */
gboolean
purple_privatekey_pool_delete(PurplePrivateKeyPool *pool, const gchar *id);

/**
 * Get the list of IDs currently in the pool.
 *
 * @param pool   Pool to enumerate
 * @return GList pointing to newly-allocated id strings. Free using
 *         purple_privatekey_pool_destroy_idlist()
 */
GList *
purple_privatekey_pool_get_idlist(PurplePrivateKeyPool *pool);

/**
 * Destroys the result given by purple_privatekey_pool_get_idlist()
 *
 * @param idlist ID List to destroy
 */
void
purple_privatekey_pool_destroy_idlist(GList *idlist);

/*@}*/

/*****************************************************************************/
/** @name PrivateKey Subsystem API                                           */
/*****************************************************************************/
/*@{*/

/**
 * Initialize the private key system
 */
void
purple_privatekey_init(void);

/**
 * Un-initialize the private key system
 */
void
purple_privatekey_uninit(void);

/**
 * Get the PrivateKey subsystem handle for signalling purposes
 */
gpointer
purple_privatekey_get_handle(void);

/** Look up a registered PrivateKeyScheme by name
 * @param name   The scheme name. Case insensitive.
 * @return Pointer to the located Scheme, or NULL if it isn't found.
 */
PurplePrivateKeyScheme *
purple_privatekey_find_scheme(const gchar *name);

/**
 * Get all registered PrivateKeySchemes
 *
 * @return GList pointing to all registered PrivateKeySchemes . This value
 *         is owned by libpurple
 */
GList *
purple_privatekey_get_schemes(void);

/** Register a PrivateKeyScheme with libpurple
 *
 * No two schemes can be registered with the same name; this function enforces
 * that.
 *
 * @param scheme  Pointer to the scheme to register.
 * @return TRUE if the scheme was successfully added, otherwise FALSE
 */
gboolean
purple_privatekey_register_scheme(PurplePrivateKeyScheme *scheme);

/** Unregister a PrivateKeyScheme from libpurple
 *
 * @param scheme    Scheme to unregister.
 *                  If the scheme is not registered, this is a no-op.
 *
 * @return TRUE if the unregister completed successfully
 */
gboolean
purple_privatekey_unregister_scheme(PurplePrivateKeyScheme *scheme);

/** Look up a registered PurplePrivateKeyPool by scheme and name
 * @param scheme_name  Scheme name. Case insensitive.
 * @param pool_name    Pool name. Case insensitive.
 * @return Pointer to the located Pool, or NULL if it isn't found.
 */
PurplePrivateKeyPool *
purple_privatekey_find_pool(const gchar *scheme_name, const gchar *pool_name);

/**
 * Get the list of registered Pools
 *
 * @return GList of all registered PurplePrivateKeyPools. This value
 *         is owned by libpurple
 */
GList *
purple_privatekey_get_pools(void);

/**
 * Register a PrivateKeyPool with libpurple and call its init function
 *
 * @param pool   Pool to register.
 * @return TRUE if the register succeeded, otherwise FALSE
 */
gboolean
purple_privatekey_register_pool(PurplePrivateKeyPool *pool);

/**
 * Unregister a PrivateKeyPool with libpurple and call its uninit function
 *
 * @param pool   Pool to unregister.
 * @return TRUE if the unregister succeeded, otherwise FALSE
 */
gboolean
purple_privatekey_unregister_pool(PurplePrivateKeyPool *pool);

/*@}*/

/**
 * Add a search path for keys.
 *
 * @param path   Path to search for keys.
 */
void purple_privatekey_add_key_search_path(const char *path);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _PURPLE_PRIVATEKEY_H */

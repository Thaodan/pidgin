/**
 * @file privatekey.c Private-Key API
 * @ingroup core
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
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "internal.h"
#include "privatekey.h"
#include "dbus-maybe.h"
#include "debug.h"
#include "request.h"
#include "signals.h"
#include "util.h"

/** List holding pointers to all registered private key schemes */
static GList *key_schemes = NULL;
/** List of registered Pools */
static GList *key_pools = NULL;


/*****************************************************************************
 *  Purple Private Key API                                                   *
 *****************************************************************************/

PurplePrivateKey *
purple_privatekey_copy(PurplePrivateKey *key)
{
	g_return_val_if_fail(key, NULL);
	g_return_val_if_fail(key->scheme, NULL);
	g_return_val_if_fail(key->scheme->copy_key, NULL);

	return (key->scheme->copy_key)(key);
}

void
purple_privatekey_destroy (PurplePrivateKey *key)
{
	PurplePrivateKeyScheme *scheme;

	if (NULL == key) return;

	scheme = key->scheme;

	(scheme->destroy_key)(key);
}

PurplePrivateKey *
purple_privatekey_import(PurplePrivateKeyScheme *scheme, const gchar *filename,
						 const gchar *password)
{
	g_return_val_if_fail(scheme, NULL);
	g_return_val_if_fail(scheme->import_key, NULL);
	g_return_val_if_fail(filename, NULL);

	return (scheme->import_key)(filename, password);
}

gboolean
purple_privatekey_export(const gchar *filename, PurplePrivateKey *key,
						 const gchar *password)
{
	PurplePrivateKeyScheme *scheme;

	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(key->scheme, FALSE);

	scheme = key->scheme;
	g_return_val_if_fail(scheme->export_key, FALSE);

	return (scheme->export_key)(filename, key, password);
}

gchar *
purple_privatekey_get_unique_id(PurplePrivateKey *key)
{
	g_return_val_if_fail(key, NULL);
	g_return_val_if_fail(key->scheme, NULL);
	g_return_val_if_fail(key->scheme->get_unique_id, NULL);

	return (key->scheme->get_unique_id)(key);
}




/*****************************************************************************
 * Purple Private Key Pool API                                               *
 *****************************************************************************/

gchar *
purple_privatekey_pool_mkpath(PurplePrivateKeyPool *pool, const gchar *id)
{
	gchar *path;
	gchar *esc_scheme_name, *esc_name, *esc_id;

	g_return_val_if_fail(pool, NULL);
	g_return_val_if_fail(pool->scheme_name, NULL);
	g_return_val_if_fail(pool->name, NULL);

	/* Escape all the elements for filesystem-friendliness */
	esc_scheme_name = pool ? g_strdup(purple_escape_filename(pool->scheme_name)) : NULL;
	esc_name = pool ? g_strdup(purple_escape_filename(pool->name)) : NULL;
	esc_id = id ? g_strdup(purple_escape_filename(id)) : NULL;

	path = g_build_filename(purple_user_dir(),
				"privatekeys", /* TODO: constantize this? */
				esc_scheme_name,
				esc_name,
				esc_id,
				NULL);

	g_free(esc_scheme_name);
	g_free(esc_name);
	g_free(esc_id);
	return path;
}

#if 0
gboolean
purple_privatekey_pool_set_password(PurplePrivateKeyPool *pool, const gchar* password)
{
	g_return_val_if_fail(pool, FALSE);
	g_return_val_if_fail(password, FALSE);

	(pool->set_password)(password);

	return TRUE;
}

const gchar*
purple_privatekey_pool_get_password(PurplePrivateKeyPool *pool)
{
	g_returen_val_if_fail(pool, FALSE);

	return (pool->get_password)();
}
#endif

gboolean
purple_privatekey_pool_usable(PurplePrivateKeyPool *pool)
{
	g_return_val_if_fail(pool, FALSE);
	g_return_val_if_fail(pool->scheme_name, FALSE);

	/* Check that the pool's scheme is loaded */
	if (purple_privatekey_find_scheme(pool->scheme_name) == NULL) {
		return FALSE;
	}

	return TRUE;
}

PurplePrivateKeyScheme *
purple_privatekey_pool_get_scheme(PurplePrivateKeyPool *pool)
{
	g_return_val_if_fail(pool, NULL);
	g_return_val_if_fail(pool->scheme_name, NULL);

	return purple_privatekey_find_scheme(pool->scheme_name);
}

gboolean
purple_privatekey_pool_contains(PurplePrivateKeyPool *pool, const gchar *id)
{
	g_return_val_if_fail(pool, FALSE);
	g_return_val_if_fail(id, FALSE);
	g_return_val_if_fail(pool->key_in_pool, FALSE);

	return (pool->key_in_pool)(id);
}

/******************************************************************************
 * Purple Private Key retrieve and store that prompt user for password
 */

typedef struct {
	PurplePrivateKeyPool *pool;
	PurplePrivateKey *key;
	const gchar* id;
	GCallback ok_cb;
	GCallback cancel_cb;
	void *user_data;
} privatekey_pool_req_data;

static void
purple_privatekey_pool_request_password(
		const gchar* msg,
		PurplePrivateKeyPool *pool,
		const gchar* id,
		GCallback  ok_cb,
		GCallback cancel_cb,
		void *user_data)
{
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;
	PurpleRequestFields *fields;

	/* Close any previous password request windows */
	purple_request_close_with_handle(pool);

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	field = purple_request_field_string_new("password", _("Enter Password"), NULL, FALSE);
	purple_request_field_string_set_masked(field, TRUE);
	purple_request_field_set_required(field, TRUE);
	purple_request_field_group_add_field(group, field);
/*
	field = purple_request_field_bool_new("remember", _("Save password"), FALSE);
	purple_request_field_group_add_field(group, field);
*/
	purple_request_fields((void*)id,
                        NULL,
                        msg,
                        NULL,
                        fields,
                        _("OK"), ok_cb,
                        _("Cancel"), cancel_cb,
			NULL, NULL, NULL,
                        user_data);
}


static void
privatekey_pool_req_cancel_cb(privatekey_pool_req_data *data, PurpleRequestFields *fields)
{
	((PurplePrivateKeyPoolCancelCb)(data->cancel_cb))(data->user_data);
	g_free(data);
}

static void
privatekey_pool_req_retrieve_ok_cb(privatekey_pool_req_data *data, PurpleRequestFields *fields)
{
	const char *entry;
	gboolean remember;
	PurplePrivateKey *key;

	entry = purple_request_fields_get_string(fields, "password");
/*	remember = purple_request_fields_get_bool(fields, "remember");*/

	if (!entry || !*entry)
	{
		/* TODO: can we use any pointer for the handle here? */
		purple_notify_error((void*)data->id, NULL, _("Password is required to access your private keys."), NULL);
		return;
	}
/*
	if(remember)
		purple_account_set_remember_password(account, TRUE);
*/

	key = (data->pool->get_key)(data->id, entry);

	((PurplePrivateKeyPoolRetrieveRequestOkCb)data->ok_cb)(key, data->user_data);
	g_free(data);
}

void purple_privatekey_pool_retrieve_request(
	PurplePrivateKeyPool *pool, const gchar *id,
//	PurplePrivateKeyPoolRetrieveRequestOkCb ok_cb,
//	PurplePrivateKeyPoolCancelCb cancel_cb,
	GCallback ok_cb,
	GCallback cancel_cb,
	void* user_data)
{
	gchar* msg;

	privatekey_pool_req_data *data;

	g_return_if_fail(pool);
	g_return_if_fail(id);
	g_return_if_fail(ok_cb);
	g_return_if_fail(cancel_cb);
	

	data = g_new0(privatekey_pool_req_data, 1);
	g_return_if_fail(data);

	data->key = NULL;
	data->pool = pool;
	data->id = id;
	data->ok_cb = G_CALLBACK(ok_cb);
	data->cancel_cb = G_CALLBACK(cancel_cb);
	data->user_data = user_data;

	msg = g_strdup_printf(_("Enter the password protecting the key named \"%s\""), id);
	purple_privatekey_pool_request_password(
		msg,
		pool,
		id,
		G_CALLBACK(privatekey_pool_req_retrieve_ok_cb),
		G_CALLBACK(privatekey_pool_req_cancel_cb),
		data);
	g_free(msg); /* TODO: not sure this is safe */
}

static void
privatekey_pool_req_store_ok_cb(privatekey_pool_req_data *data, PurpleRequestFields *fields)
{
	const char *entry;
	gboolean remember;
	gboolean result;

	entry = purple_request_fields_get_string(fields, "password");
/*	remember = purple_request_fields_get_bool(fields, "remember");*/

	if (!entry || !*entry)
	{
		/* TODO: can we use any pointer for the handle here? */
		purple_notify_error((void*)data->id, NULL, _("Password is required to protect your private keys."), NULL);
		return;
	}
/*
	if(remember)
		purple_account_set_remember_password(account, TRUE);
*/

	result = (data->pool->put_key)(data->id, data->key, entry);

	((PurplePrivateKeyPoolStoreRequestOkCb)data->ok_cb)(result, data->user_data);
	g_free(data);
}

void 
purple_privatekey_pool_store_request(
	PurplePrivateKeyPool *pool, const gchar *id, PurplePrivateKey *key,
//	PurplePrivateKeyPoolStoreRequestOkCb ok_cb,
//	PurplePrivateKeyPoolCancelCb cancel_cb,
	GCallback ok_cb,
	GCallback cancel_cb,
	void* user_data)
{
	gchar* msg;
	privatekey_pool_req_data *data;

	g_return_if_fail(pool);
	g_return_if_fail(id);
	g_return_if_fail(ok_cb);
	g_return_if_fail(cancel_cb);
	

	data = g_new0(privatekey_pool_req_data, 1);
	g_return_if_fail(data);

	data->key = key;
	data->pool = pool;
	data->id = id;
	data->ok_cb = G_CALLBACK(ok_cb);
	data->cancel_cb = G_CALLBACK(cancel_cb);
	data->user_data = user_data;

	msg = g_strdup_printf(_("Enter a password to protect the key named \"%s\""), id);
	purple_privatekey_pool_request_password(
		msg,
		pool,
		id,
		G_CALLBACK(privatekey_pool_req_store_ok_cb),
		G_CALLBACK(privatekey_pool_req_cancel_cb),
		data);
	g_free(msg); /* TODO: not sure this is safe */
}

/******************************************************************************
 * Purple Private Key Pool direct retrieve and store 
 */

PurplePrivateKey *
purple_privatekey_pool_retrieve(PurplePrivateKeyPool *pool, const gchar *id, const gchar *password)
{
	g_return_val_if_fail(pool, NULL);
	g_return_val_if_fail(id, NULL);
	g_return_val_if_fail(pool->get_key, NULL);

	return (pool->get_key)(id, password);
}

gboolean
purple_privatekey_pool_store(PurplePrivateKeyPool *pool, const gchar *id, PurplePrivateKey *key, const gchar* password)
{
	gboolean ret = FALSE;

	g_return_val_if_fail(pool, FALSE);
	g_return_val_if_fail(id, FALSE);
	g_return_val_if_fail(pool->put_key, FALSE);

	/* Whether key->scheme matches find_scheme(pool->scheme_name) is not
	   relevant... I think... */
	g_return_val_if_fail(
		g_ascii_strcasecmp(pool->scheme_name, key->scheme->name) == 0,
		FALSE);

	ret = (pool->put_key)(id, key, password);

	/* Signal that the certificate was stored if success*/
	if (ret) {
		purple_signal_emit(pool, "privatekey-stored",
				   pool, id);
	}

	return ret;
}

gboolean
purple_privatekey_pool_delete(PurplePrivateKeyPool *pool, const gchar *id)
{
	gboolean ret = FALSE;

	g_return_val_if_fail(pool, FALSE);
	g_return_val_if_fail(id, FALSE);
	g_return_val_if_fail(pool->delete_key, FALSE);

	ret = (pool->delete_key)(id);

	/* Signal that the key was deleted if success */
	if (ret) {
		purple_signal_emit(pool, "key-deleted",
				   pool, id);
	}

	return ret;
}

GList *
purple_privatekey_pool_get_idlist(PurplePrivateKeyPool *pool)
{
	g_return_val_if_fail(pool, NULL);
	g_return_val_if_fail(pool->get_idlist, NULL);

	return (pool->get_idlist)();
}

void
purple_privatekey_pool_destroy_idlist(GList *idlist)
{
	GList *l;

	/* Iterate through and free them strings */
	for ( l = idlist; l; l = l->next ) {
		g_free(l->data);
	}

	g_list_free(idlist);
}


/****************************************************************************/
/* Builtin Pools                                                            */
/****************************************************************************/

/***** Cache of user's keys *****/
static PurplePrivateKeyPool x509_user_keys;

typedef struct x509_user_data {
	gchar *password;
} x509_user_data_t;

static GList* x509_user_key_paths = NULL;

static gboolean
x509_user_init(void)
{
	gchar *poolpath;
	int ret;

	x509_user_keys.data = g_new0(x509_user_data_t, 1);

	/* Set up key cache here if it isn't already done */
	poolpath = purple_privatekey_pool_mkpath(&x509_user_keys, NULL);
	ret = purple_build_dir(poolpath, 0700); /* Make it this user only */

	if (ret != 0)
		purple_debug_info("x509_user/keys",
				"Could not create %s.  Keys will not be saved.\n",
				poolpath);

	g_free(poolpath);

	return TRUE;
}

static void
x509_user_uninit(void)
{
	if (x509_user_keys.data != NULL)
		g_free(x509_user_keys.data);
}
/*
static void 
x509_user_set_password(const gchar *password)
{
	x509_user_data_t *user_data = (x509_user_data_t*)x509_user_keys.data;

	user_data->password = g_strdup(password);
	purple_debug_info("x509_user/keys", "Setting password\n");
}
*/
static gboolean
x509_user_key_in_pool(const gchar *id)
{
	gchar *keypath;
	gboolean ret = FALSE;

	g_return_val_if_fail(id, FALSE);

	keypath = purple_privatekey_pool_mkpath(&x509_user_keys, id);

	ret = g_file_test(keypath, G_FILE_TEST_IS_REGULAR);

	g_free(keypath);
	return ret;
}

static PurplePrivateKey *
x509_user_get_key(const gchar *id, const gchar* password)
{
	PurplePrivateKeyScheme *x509;
	PurplePrivateKey *key;
	gchar *keypath;

	g_return_val_if_fail(id, NULL);

	/* Is it in the pool? */
	if ( !x509_user_key_in_pool(id) ) {
		return NULL;
	}

	/* Look up the X.509 scheme */
	x509 = purple_privatekey_find_scheme("x509");
	g_return_val_if_fail(x509, NULL);

	/* Okay, now find and load that key */
	keypath = purple_privatekey_pool_mkpath(&x509_user_keys, id);
	key = purple_privatekey_import(x509, keypath, password);

	g_free(keypath);

	return key;
}

static gboolean
x509_user_put_key(const gchar *id, PurplePrivateKey *key, const gchar* password)
{
	gboolean ret = FALSE;
	gchar *keypath;

	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(key->scheme, FALSE);
	/* Make sure that this is some kind of X.509 certificate */
	/* TODO: Perhaps just check key->scheme->name instead? */
	g_return_val_if_fail(key->scheme == purple_privatekey_find_scheme(x509_user_keys.scheme_name), FALSE);

	/* Work out the filename and export */
	keypath = purple_privatekey_pool_mkpath(&x509_user_keys, id);
	ret = purple_privatekey_export(keypath, key, password);

	g_free(keypath);
	return ret;
}

static gboolean
x509_user_delete_key(const gchar *id)
{
	gboolean ret = FALSE;
	gchar *keypath;

	g_return_val_if_fail(id, FALSE);

	/* Is the id even in the pool? */
	if (!x509_user_key_in_pool(id)) {
		purple_debug_warning("x509_user/keys",
				     "Id %s wasn't in the key pool\n",
				     id);
		return FALSE;
	}

	/* OK, so work out the keypath and delete the thing */
	keypath = purple_privatekey_pool_mkpath(&x509_user_keys, id);
	if ( unlink(keypath) != 0 ) {
		purple_debug_error("x509_user/keys",
				   "Unlink of %s failed!\n",
				   keypath);
		ret = FALSE;
	} else {
		ret = TRUE;
	}

	g_free(keypath);
	return ret;
}

static GList *
x509_user_get_idlist(void)
{
	GList *idlist = NULL;
	GDir *dir;
	const gchar *entry;
	gchar *poolpath;

	/* Get a handle on the pool directory */
	poolpath = purple_privatekey_pool_mkpath(&x509_user_keys, NULL);
	dir = g_dir_open(poolpath,
			 0,     /* No flags */
			 NULL); /* Not interested in what the error is */
	g_free(poolpath);

	g_return_val_if_fail(dir, NULL);

	/* Traverse the directory listing and create an idlist */
	while ( (entry = g_dir_read_name(dir)) != NULL ) {
		/* Unescape the filename */
		const char *unescaped = purple_unescape_filename(entry);

		/* Copy the entry name into our list (GLib owns the original
		   string) */
		idlist = g_list_prepend(idlist, g_strdup(unescaped));
	}

	/* Release the directory */
	g_dir_close(dir);

	return idlist;
}

static PurplePrivateKeyPool x509_user_keys = {
	"x509",                       /* Scheme name */
	"user",                       /* Pool name */
	N_("My Private Keys"),        /* User-friendly name */
	NULL,                         /* Internal data */
	x509_user_init,               /* init */
	x509_user_uninit,             /* uninit */
	x509_user_key_in_pool,  /* Certificate exists? */
	x509_user_get_key,      /* Cert retriever */
	x509_user_put_key,      /* Cert writer */
	x509_user_delete_key,   /* Cert remover */
	x509_user_get_idlist,   /* idlist retriever */

	NULL,
	NULL,
	NULL,
	NULL
};

/****************************************************************************/
/* Subsystem                                                                */
/****************************************************************************/
void
purple_privatekey_init(void)
{
	/* Register builtins */
	purple_privatekey_register_pool(&x509_user_keys);
}

void
purple_privatekey_uninit(void)
{
	/* Unregister all Pools */
	g_list_foreach(key_pools, (GFunc)purple_privatekey_unregister_pool, NULL);
}

gpointer
purple_privatekey_get_handle(void)
{
	static gint handle;
	return &handle;
}

PurplePrivateKeyScheme *
purple_privatekey_find_scheme(const gchar *name)
{
	PurplePrivateKeyScheme *scheme = NULL;
	GList *l;

	g_return_val_if_fail(name, NULL);

	/* Traverse the list of registered schemes and locate the
	   one whose name matches */
	for(l = key_schemes; l; l = l->next) {
		scheme = (PurplePrivateKeyScheme *)(l->data);

		/* Name matches? that's our man */
		if(!g_ascii_strcasecmp(scheme->name, name))
			return scheme;
	}

	purple_debug_warning("privatekey",
			     "PrivateKeyScheme %s requested but not found.\n",
			     name);

	/* TODO: Signalling and such? */

	return NULL;
}

GList *
purple_privatekey_get_schemes(void)
{
	return key_schemes;
}

gboolean
purple_privatekey_register_scheme(PurplePrivateKeyScheme *scheme)
{
	g_return_val_if_fail(scheme != NULL, FALSE);

	/* Make sure no scheme is registered with the same name */
	if (purple_privatekey_find_scheme(scheme->name) != NULL) {
		return FALSE;
	}

	/* Okay, we're golden. Register it. */
	key_schemes = g_list_prepend(key_schemes, scheme);

	/* TODO: Signalling and such? */

	purple_debug_info("privatekey",
			  "PrivateKeyScheme %s registered\n",
			  scheme->name);

	return TRUE;
}

gboolean
purple_privatekey_unregister_scheme(PurplePrivateKeyScheme *scheme)
{
	if (NULL == scheme) {
		purple_debug_warning("privatekey",
				     "Attempting to unregister NULL scheme\n");
		return FALSE;
	}

	/* TODO: signalling? */

	/* TODO: unregister all PrivateKeyPools for this scheme? */
	/* Neither of the above should be necessary, though */
	key_schemes = g_list_remove(key_schemes, scheme);

	purple_debug_info("privatekey",
			  "PrivateKeyScheme %s unregistered\n",
			  scheme->name);


	return TRUE;
}

PurplePrivateKeyPool *
purple_privatekey_find_pool(const gchar *scheme_name, const gchar *pool_name)
{
	PurplePrivateKeyPool *pool = NULL;
	GList *l;

	g_return_val_if_fail(scheme_name, NULL);
	g_return_val_if_fail(pool_name, NULL);

	/* Traverse the list of registered pools and locate the
	   one whose name matches */
	for(l = key_pools; l; l = l->next) {
		pool = (PurplePrivateKeyPool *)(l->data);

		/* Scheme and name match? */
		if(!g_ascii_strcasecmp(pool->scheme_name, scheme_name) &&
		   !g_ascii_strcasecmp(pool->name, pool_name))
			return pool;
	}

	purple_debug_warning("privatekey",
			     "PrivateKeyPool %s, %s requested but not found.\n",
			     scheme_name, pool_name);

	/* TODO: Signalling and such? */

	return NULL;

}

GList *
purple_privatekey_get_pools(void)
{
	return key_pools;
}

gboolean
purple_privatekey_register_pool(PurplePrivateKeyPool *pool)
{
	g_return_val_if_fail(pool, FALSE);
	g_return_val_if_fail(pool->scheme_name, FALSE);
	g_return_val_if_fail(pool->name, FALSE);
	g_return_val_if_fail(pool->fullname, FALSE);

	/* Make sure no pools are registered under this name */
	if (purple_privatekey_find_pool(pool->scheme_name, pool->name)) {
		return FALSE;
	}

	/* Initialize the pool if needed */
	if (pool->init) {
		gboolean success;

		success = pool->init();
		if (!success)
			return FALSE;
	}

	/* Register the Pool */
	key_pools = g_list_prepend(key_pools, pool);

	/* TODO: Emit a signal that the pool got registered */

	PURPLE_DBUS_REGISTER_POINTER(pool, PurplePrivateKeyPool);
	purple_signal_register(pool, /* Signals emitted from pool */
			       "privatekey-stored",
			       purple_marshal_VOID__POINTER_POINTER,
			       NULL, /* No callback return value */
			       2,    /* Two non-data arguments */
			       purple_value_new(PURPLE_TYPE_SUBTYPE,
						PURPLE_SUBTYPE_PRIVATEKEYPOOL),
			       purple_value_new(PURPLE_TYPE_STRING));

	purple_signal_register(pool, /* Signals emitted from pool */
			       "privatekey-deleted",
			       purple_marshal_VOID__POINTER_POINTER,
			       NULL, /* No callback return value */
			       2,    /* Two non-data arguments */
			       purple_value_new(PURPLE_TYPE_SUBTYPE,
						PURPLE_SUBTYPE_PRIVATEKEYPOOL),
			       purple_value_new(PURPLE_TYPE_STRING));

	purple_debug_info("privatekey",
		  "PrivateKeyPool %s registered\n",
		  pool->name);

	return TRUE;
}

gboolean
purple_privatekey_unregister_pool(PurplePrivateKeyPool *pool)
{
	if (NULL == pool) {
		purple_debug_warning("privatekey",
				     "Attempting to unregister NULL pool\n");
		return FALSE;
	}

	/* Check that the pool is registered */
	if (!g_list_find(key_pools, pool)) {
		purple_debug_warning("privatekey",
				     "Pool to unregister isn't registered!\n");

		return FALSE;
	}

	/* Uninit the pool if needed */
	PURPLE_DBUS_UNREGISTER_POINTER(pool);
	if (pool->uninit) {
		pool->uninit();
	}

	key_pools = g_list_remove(key_pools, pool);

	/* TODO: Signalling? */
	purple_signal_unregister(pool, "privatekey-stored");
	purple_signal_unregister(pool, "privatekey-deleted");

	purple_debug_info("privatekey",
			  "PrivateKeyPool %s unregistered\n",
			  pool->name);
	return TRUE;
}

/****************************************************************************/
/* Scheme-specific functions                                                */
/****************************************************************************/

#if 0
static void
purple_privatekey_display_x509(PurplePrivateKey *key)
{
}
#endif

void purple_privatekey_add_key_search_path(const char *path)
{
	if (g_list_find_custom(x509_user_key_paths, path, (GCompareFunc)strcmp))
		return;
	x509_user_key_paths = g_list_append(x509_user_key_paths, g_strdup(path));
}

/**
 * @file pkcs12.c PKCS12 API
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
#include "pkcs12.h"
#include "dbus-maybe.h"
#include "debug.h"
#include "request.h"
#include "signals.h"
#include "util.h"
#include "credential.h"

/** List holding pointers to all registered private key schemes */
static GList *pkcs12_schemes = NULL;

gboolean
purple_pkcs12_import(PurplePkcs12Scheme *scheme,
		     const gchar *filename, const gchar *password,
		     GList **credentials)
{
	g_return_val_if_fail(scheme, FALSE);
	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(password, FALSE);
	g_return_val_if_fail(credentials, FALSE);

	return (scheme->import_pkcs12)(filename, password, credentials);
}

gboolean
purple_pkcs12_export(PurplePkcs12Scheme *scheme,
		     const gchar *filename, const gchar *password,
		     GList *crts, PurplePrivateKey *key)
{
	g_return_val_if_fail(scheme, FALSE);
	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(password, FALSE);

	return (scheme->export_pkcs12)(filename, password, crts, key);
}

gboolean
purple_pkcs12_import_to_pool(PurplePkcs12Scheme *scheme, const gchar *filename, const gchar *password,
							 PurpleCertificatePool *crtpool, PurplePrivateKeyPool *keypool)
{
	GList *creds;
	PurplePrivateKey *key;
	GList *i;
	gchar *id;
	gboolean result = FALSE;
	GList *creditem;

	g_return_val_if_fail(scheme, FALSE);
	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(password, FALSE);
	g_return_val_if_fail(crtpool, FALSE);
	g_return_val_if_fail(keypool, FALSE);


	if (!purple_pkcs12_import(scheme, filename, password, &creds))
		return FALSE;

	for (creditem = g_list_first(creds);
			NULL != creditem; creditem = g_list_next(creditem)) {
		PurpleCredential *cred = (PurpleCredential*)creditem->data;

		for (i = g_list_first(cred->crts); NULL != i; i = g_list_next(i)) {
			PurpleCertificate *crt = (PurpleCertificate*)i->data;

			id = purple_certificate_get_unique_id(crt);
			if (NULL == id)
				goto done;

			if (!purple_certificate_pool_store(crtpool, id, crt))
				goto done;
		}

		id = purple_privatekey_get_unique_id(cred->key);
		if (NULL == id)
			goto done;

		if (!purple_privatekey_pool_store(keypool, id, key, password))
			goto done;
	}

	result = TRUE;

done:
	purple_credential_destroy_list(creds);
	return result;
}

void
purple_pkcs12_request_password(void* handle, const char* filename, GCallback ok_cb,
				GCallback cancel_cb, void *user_data)
{
	gchar *primary;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;
	PurpleRequestFields *fields;

	/* Close any previous password request windows */
	purple_request_close_with_handle((void*)filename);

	/* TODO: Should display only filename and not whole path */
	primary = g_strdup_printf(_("Enter password for %s"), filename);

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
	purple_request_fields(handle,              /* handle    */
                        _("Enter Password"),       /* title     */
                        primary,                   /* primary   */
                        NULL,                      /* secondary */
                        fields,                    /* fields    */
                        _("OK"), ok_cb,            /* ok text and callback */
                        _("Cancel"), cancel_cb,    /* cancel text and callback */
			NULL, NULL, NULL,          /* account, who, conv */
                        user_data);                /* callback data */
	g_free(primary); /* TODO: not right ?? */
}

/****************************************************************************/
/* Subsystem                                                                */
/****************************************************************************/
void
purple_pkcs12_init(void)
{
}

void
purple_pkcs12_uninit(void)
{
}

gpointer
purple_pkcs12_get_handle(void)
{
	static gint handle;
	return &handle;
}

PurplePkcs12Scheme *
purple_pkcs12_find_scheme(const gchar *name)
{
	PurplePkcs12Scheme *scheme = NULL;
	GList *l;

	g_return_val_if_fail(name, NULL);

	/* Traverse the list of registered schemes and locate the
	   one whose name matches */
	for(l = pkcs12_schemes; l; l = l->next) {
		scheme = (PurplePkcs12Scheme *)(l->data);

		/* Name matches? that's our man */
		if(!g_ascii_strcasecmp(scheme->name, name))
			return scheme;
	}

	purple_debug_warning("pkcs12",
			     "Pkcs12Scheme %s requested but not found.\n",
			     name);

	/* TODO: Signalling and such? */

	return NULL;
}

GList *
purple_pkcs12_get_schemes(void)
{
	return pkcs12_schemes;
}

gboolean
purple_pkcs12_register_scheme(PurplePkcs12Scheme *scheme)
{
	g_return_val_if_fail(scheme != NULL, FALSE);

	/* Make sure no scheme is registered with the same name */
	if (purple_pkcs12_find_scheme(scheme->name) != NULL) {
		return FALSE;
	}

	/* Okay, we're golden. Register it. */
	pkcs12_schemes = g_list_prepend(pkcs12_schemes, scheme);

	/* TODO: Signalling and such? */

	purple_debug_info("pkcs12",
			  "Pkcs12Scheme %s registered\n",
			  scheme->name);

	return TRUE;
}

gboolean
purple_pkcs12_unregister_scheme(PurplePkcs12Scheme *scheme)
{
	if (NULL == scheme) {
		purple_debug_warning("pkcs12",
				     "Attempting to unregister NULL scheme\n");
		return FALSE;
	}

	pkcs12_schemes = g_list_remove(pkcs12_schemes, scheme);

	purple_debug_info("pkcs12",
			  "Pkcs12Scheme %s unregistered\n",
			  scheme->name);

	return TRUE;
}

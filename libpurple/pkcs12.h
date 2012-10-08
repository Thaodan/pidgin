/**
 * @file pkcs12.h PKCS12 API
 * @ingroup core
 * @see 
 * @since 3.0.0
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

#ifndef _PURPLE_PKCS12_H
#define _PURPLE_PKCS12_H

#include <time.h>

#include <glib.h>

#include <pkcs12.h>
#include <certificate.h>
#include <privatekey.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _PurplePkcs12Scheme PurplePkcs12Scheme;

/** PKCS12 import/export
 *
 *  A Pkcs12Scheme must implement all of the fields in the structure,
 *  and register it using purple_pkcs12_register_scheme()
 */
struct _PurplePkcs12Scheme
{
	/** Name of the pkcs12 scheme
	 *  ex: "pkcs12"
	 *  This must be globally unique - you may not register more than one
	 *  Pkcs12Scheme of the same name at a time.
	 */
	gchar * name;

	/** User-friendly name for this type
	 *  ex: N_("X.509 PKCS12")
	 *  When this is displayed anywhere, it should be i18ned
	 *  ex: _(scheme->fullname)
	 */
	gchar * fullname;

	/**
	 * Imports PurpleCertificates and PurplePrivateKeys from a PKCS12 file
	 *
	 * @param filename    File path to import from
	 * @param password    Password protecting the PKCS12 file
	 * @param credentials List of PurpleCredentials from the PKCS12 file.
	 *                    Must be free'd by caller.
	 * @return TRUE if at least one certificate and key were imported, and FALSE on failure
	 */
	gboolean (*import_pkcs12)(const gchar *filename, const gchar *password,
				  GList **credentials);

	/**
	 * Exports PurpleCertificates and PurplePrivateKey to a file
	 *
	 * @param filename    File to export the key to
	 * @param password    Password to protect the PKCS12 file
	 * @param crts        List of ptrs to PurpleCertificates to export
	 * @param key         PurplePrivateKey to export
	 * @return TRUE if the export succeeded, otherwise FALSE
	 */
	gboolean (*export_pkcs12)(const gchar *filename, const gchar *password,
				  GList *crts, PurplePrivateKey *key);

	void (*_purple_reserved1)(void);
	void (*_purple_reserved2)(void);
	void (*_purple_reserved3)(void);
};

/*@}*/

/*****************************************************************************/
/** @name PKCS12 Functions                                              */
/*****************************************************************************/
/*@{*/

/**
 * Imports PurpleCertificates and PurplePrivateKeys from a PKCS12 file
 *
 * @param scheme      Scheme to import under
 * @param filename    File path to import from
 * @param password    Password protecting the PKCS12 file
 * @param credentials List of PurpleCredentials. Each credentials contains:
 *                    Certificate chain from the PKCS12 file in the form of a list
 *                    of ptrs to PurpleCertificates. The chain must be in order.
 *                    The first certificate must be the certificate corresponding to
 *                    key. Each certificate should be followed by the issuer's
 *                    certificate and end at the root CA certificate. The whole chain
 *                    need not be present.
 *                    The PurplePrivateKey from the PKCS12 file for the certificate chain.
 *                    Must be free'd by caller.
 * @return TRUE if at least one certificate and key were imported, and FALSE on failure
 */
gboolean
purple_pkcs12_import(PurplePkcs12Scheme *scheme, const gchar *filename, const gchar *password,
		     GList **credentials);

/**
 * Exports PurpleCertificates and PurplePrivateKey to a file
 *
 * @param filename    File to export the key to
 * @param password    Password to protect the PKCS12 file
 * @param crts        List of ptrs to PurpleCertificates to export
 * @param key         PurplePrivateKey to export
 * @return TRUE if the export succeeded, otherwise FALSE
 */
gboolean
purple_pkcs12_export(PurplePkcs12Scheme *scheme, const gchar *filename, const gchar *password,
		     GList *crts, PurplePrivateKey *key);

/**
 * Imports certificates and key into given certificate and private key pools.
 * 
 * @param scheme      Scheme to import under
 * @param filename    File path to import from
 * @param password    Password protecting the PKCS12 file
 * @param certpool    CertificatePool to import certificates into
 * @param keypool     PrivateKeyPool to import keys into
 * @return TRUE if as least one certificate and key were imported, and FALSE on failure
 */
gboolean
purple_pkcs12_import_to_pool(PurplePkcs12Scheme *scheme, const gchar *filename, const gchar *password,
							 PurpleCertificatePool *crtpool, PurplePrivateKeyPool *keypool);

/**
 * Request the password used to encrypt the pkcs12 file.
 *
 * @param filename File name of the pkcs12 file.
 * @param ok_cb  Called when the user acknowledges the request.
 * @param cancel_cb Called when the user cancels the request.
 * @param user_data Opaque data pointer.
 */
void
purple_pkcs12_request_password(void* handle, const char* filename, GCallback ok_cb,
				GCallback cancel_cb, void *user_data);
/*@}*/

/*****************************************************************************/
/** @name PKCS12 Subsystem API                                               */
/*****************************************************************************/
/*@{*/

/**
 * Initialize the PKCS12 system
 */
void
purple_pkcs12_init(void);

/**
 * Un-initialize the pkcs12 system
 */
void
purple_pkcs12_uninit(void);

/**
 * Get the pkcs12 subsystem handle for signalling purposes
 */
gpointer
purple_pkcs12_get_handle(void);

/** Look up a registered PKCS12 by name
 * @param name   The scheme name. Case insensitive.
 * @return Pointer to the located Scheme, or NULL if it isn't found.
 */
PurplePkcs12Scheme *
purple_pkcs12_find_scheme(const gchar *name);

/**
 * Get all registered Pkcs12Schemes
 *
 * @return GList pointing to all registered Pkcs12Schemes . This value
 *         is owned by libpurple
 */
GList *
purple_pkcs12_get_schemes(void);

/** Register a Pkcs12Scheme with libpurple
 *
 * No two schemes can be registered with the same name; this function enforces
 * that.
 *
 * @param scheme  Pointer to the scheme to register.
 * @return TRUE if the scheme was successfully added, otherwise FALSE
 */
gboolean
purple_pkcs12_register_scheme(PurplePkcs12Scheme *scheme);

/** Unregister a Pkcs12Scheme from libpurple
 *
 * @param scheme    Scheme to unregister.
 *                  If the scheme is not registered, this is a no-op.
 *
 * @return TRUE if the unregister completed successfully
 */
gboolean
purple_pkcs12_unregister_scheme(PurplePkcs12Scheme *scheme);

/*@}*/


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _PURPLE_PKCS12_H */

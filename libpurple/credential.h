/**
 * @file credential.h CREDENTIAL API
 * @ingroup core
 * @see 
 * @since 3.0.0
 *
 * Purple credentials are basically a convienent means to carry around a 
 * key and its associated certificates in one object.
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

#ifndef _PURPLE_CREDENTIAL_H
#define _PURPLE_CREDENTIAL_H

#include <glib.h>
#include "privatekey.h"
#include "certificate.h"

typedef struct _PurpleCredential PurpleCredential;

struct _PurpleCredential
{
	GList *crts;            /* certificate chain starting with end point cert */
	PurplePrivateKey *key;	/* private key for end point cert */
};

/**
 * Destroy a credential and all certificates and keys referenced by it.
 *
 * @param cred PurpleCredential to destroy.
 */
void purple_credential_destroy(PurpleCredential *cred);

/**
 * Destroy a list of credentials.
 *
 * @param List of credentials.
 */
void purple_credential_destroy_list(GList *creds);

#endif  /* _PURPLE_CREDENTIAL_H*/

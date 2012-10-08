/**
 * @file credential.c CREDENTIAL API
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

#include "credential.h"

void purple_credential_destroy(PurpleCredential *cred)
{
	g_return_if_fail(NULL == cred);
	purple_certificate_destroy_list(cred->crts);
	purple_privatekey_destroy(cred->key);
}

void purple_credential_destroy_list(GList *creds)
{
	g_return_if_fail(NULL == creds);
	g_list_foreach(creds, (GFunc)purple_credential_destroy, NULL);
	g_list_free(creds);
}

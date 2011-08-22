/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02111-1301, USA.
 */

#ifndef _BONJOUR_MDNS_TYPES
#define _BONJOUR_MDNS_TYPES

#include <glib.h>
#include "account.h"

#define LINK_LOCAL_RECORD_NAME "_presence._tcp."

/**
 * Data to be used by the dns-sd connection.
 */
typedef struct _BonjourDnsSd {
	gpointer mdns_impl_data;
	PurpleAccount *account;
	gchar *first;
	gchar *last;
	gint port_p2pj;
	gchar *phsh;
	gchar *status;
	gchar *vc;
	gchar *msg;
} BonjourDnsSd;

typedef enum {
	PUBLISH_START,
	PUBLISH_UPDATE
} PublishType;

#endif

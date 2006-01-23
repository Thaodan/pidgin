/*
 * @file gtkconn.c GTK+ Connection API
 * @ingroup gtkui
 *
 * gaim
 *
 * Gaim is the legal property of its developers, whose names are too numerous
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "internal.h"
#include "gtkgaim.h"

#include "account.h"
#include "debug.h"
#include "notify.h"
#include "prefs.h"
#include "gtkblist.h"
#include "gtkconn.h"
#include "gtkdialogs.h"
#include "gtkstatusbox.h"
#include "gtkstock.h"
#include "gtkutils.h"
#include "util.h"

#define INITIAL_RECON_DELAY 8000
#define MAX_RECON_DELAY 600000

typedef struct {
	int delay;
	guint timeout;
} GaimAutoRecon;

/**
 * Contains accounts that are auto-reconnecting.
 * The key is a pointer to the GaimAccount and the
 * value is a pointer to a GaimAutoRecon.
 */
static GHashTable *hash = NULL;
static GHashTable *errored_accounts = NULL;

static void
gaim_gtk_connection_connect_progress(GaimConnection *gc,
		const char *text, size_t step, size_t step_count)
{
	GaimGtkBuddyList *gtkblist = gaim_gtk_blist_get_default_gtk_blist();
	if (!gtkblist)
		return;
	gtk_gaim_status_box_set_connecting(GTK_GAIM_STATUS_BOX(gtkblist->statusbox),
					   (gaim_connections_get_connecting() != NULL));
	gtk_gaim_status_box_pulse_connecting(GTK_GAIM_STATUS_BOX(gtkblist->statusbox));
}

static void
gaim_gtk_connection_connected(GaimConnection *gc)
{
	GaimAccount *account;
	GaimGtkBuddyList *gtkblist;

	account  = gaim_connection_get_account(gc);
	gtkblist = gaim_gtk_blist_get_default_gtk_blist();

	if (gtkblist != NULL)
		gtk_gaim_status_box_set_connecting(GTK_GAIM_STATUS_BOX(gtkblist->statusbox),
					   (gaim_connections_get_connecting() != NULL));

	if (hash != NULL)
		g_hash_table_remove(hash, account);

	if (g_hash_table_size(errored_accounts) > 0)
	{
		g_hash_table_remove(errored_accounts, account);
		if (g_hash_table_size(errored_accounts) == 0)
			gtk_gaim_status_box_set_error(GTK_GAIM_STATUS_BOX(gtkblist->statusbox), NULL);
	}
}

static void
gaim_gtk_connection_disconnected(GaimConnection *gc)
{
	GaimGtkBuddyList *gtkblist = gaim_gtk_blist_get_default_gtk_blist();
	if (!gtkblist)
		return;
	gtk_gaim_status_box_set_connecting(GTK_GAIM_STATUS_BOX(gtkblist->statusbox),
					   (gaim_connections_get_connecting() != NULL));

	if (gaim_connections_get_all() != NULL)
		return;

	gaim_gtkdialogs_destroy_all();
}

static void
gaim_gtk_connection_notice(GaimConnection *gc,
		const char *text)
{
}


static void
free_auto_recon(gpointer data)
{
	GaimAutoRecon *info = data;

	if (info->timeout != 0)
		g_source_remove(info->timeout);

	g_free(info);
}

static gboolean
do_signon(gpointer data)
{
	GaimAccount *account = data;
	GaimAutoRecon *info;

	gaim_debug_info("autorecon", "do_signon called\n");
	g_return_val_if_fail(account != NULL, FALSE);
	info = g_hash_table_lookup(hash, account);

	if (info)
		info->timeout = 0;

	gaim_debug_info("autorecon", "calling gaim_account_connect\n");
	gaim_account_connect(account);
	gaim_debug_info("autorecon", "done calling gaim_account_connect\n");

	return FALSE;
}

static void
gaim_gtk_connection_report_disconnect(GaimConnection *gc, const char *text)
{
	GaimGtkBuddyList *gtkblist = gaim_gtk_blist_get_default_gtk_blist();
	GaimAccount *account = NULL;
	GaimAutoRecon *info;
	GSList* errored_account;

	account = gaim_connection_get_account(gc);
	info = g_hash_table_lookup(hash, account);
	errored_account = g_hash_table_lookup(errored_accounts, account);

	if (!gc->wants_to_die) {
		if (gtkblist != NULL)
			gtk_gaim_status_box_set_error(GTK_GAIM_STATUS_BOX(gtkblist->statusbox), text);

		if (info == NULL) {
			info = g_new0(GaimAutoRecon, 1);
			g_hash_table_insert(hash, account, info);
			info->delay = INITIAL_RECON_DELAY;
		} else {
			info->delay = MIN(2 * info->delay, MAX_RECON_DELAY);
			if (info->timeout != 0)
				g_source_remove(info->timeout);
		}
		info->timeout = g_timeout_add(info->delay, do_signon, account);

		g_hash_table_insert(errored_accounts, account, NULL);
	} else {
		char *p, *s, *n=NULL ;
		if (info != NULL)
			g_hash_table_remove(hash, account);

		if (errored_account != NULL)
			g_hash_table_remove(errored_accounts, errored_account);

		if (gaim_account_get_alias(account))
		{
			n = g_strdup_printf("%s (%s) (%s)",
					gaim_account_get_username(account),
					gaim_account_get_alias(account),
					gaim_account_get_protocol_name(account));
		}
		else
		{
			n = g_strdup_printf("%s (%s)",
					gaim_account_get_username(account),
					gaim_account_get_protocol_name(account));
		}

		p = g_strdup_printf(_("%s disconnected"), n);
		s = g_strdup_printf(_("%s was disconnected due to an error. %s The account has been disabled. "
				"Correct the error and reenable the account to connect."), n, text);
		gaim_notify_error(NULL, NULL, p, s);
		g_free(p);
		g_free(s);
		g_free(n);

		/*
		 * TODO: Do we really want to disable the account when it's
		 * disconnected by wants_to_die?  This happens when you sign
		 * on from somewhere else, or when you enter an invalid password.
		 */
		gaim_account_set_enabled(account, GAIM_GTK_UI, FALSE);
	}
}

static GaimConnectionUiOps conn_ui_ops =
{
	gaim_gtk_connection_connect_progress,
	gaim_gtk_connection_connected,
	gaim_gtk_connection_disconnected,
	gaim_gtk_connection_notice,
	gaim_gtk_connection_report_disconnect,
};

GaimConnectionUiOps *
gaim_gtk_connections_get_ui_ops(void)
{
	return &conn_ui_ops;
}

static void
account_removed_cb(GaimAccount *account, gpointer user_data)
{
	g_hash_table_remove(hash, account);

	if (g_hash_table_size(errored_accounts) > 0)
	{
		g_hash_table_remove(errored_accounts, account);
		if (g_hash_table_size(errored_accounts) == 0)
		{
			GaimGtkBuddyList *gtkblist;

			gtkblist = gaim_gtk_blist_get_default_gtk_blist();
			if (gtkblist != NULL)
				gtk_gaim_status_box_set_error(GTK_GAIM_STATUS_BOX(gtkblist->statusbox), NULL);
		}
	}
}


/**************************************************************************
* GTK+ connection glue
**************************************************************************/

void *
gaim_gtk_connection_get_handle(void)
{
	static int handle;

	return &handle;
}

void
gaim_gtk_connection_init(void)
{
	hash = g_hash_table_new_full(
							g_direct_hash, g_direct_equal,
							NULL, free_auto_recon);
	errored_accounts = g_hash_table_new_full(
							g_direct_hash, g_direct_equal,
							NULL, NULL);

	gaim_signal_connect(gaim_accounts_get_handle(), "account-removed",
						gaim_gtk_connection_get_handle(),
						GAIM_CALLBACK(account_removed_cb), NULL);
}

void
gaim_gtk_connection_uninit(void)
{
	gaim_signals_disconnect_by_handle(gaim_gtk_connection_get_handle());

	g_hash_table_destroy(hash);
	g_hash_table_destroy(errored_accounts);
}

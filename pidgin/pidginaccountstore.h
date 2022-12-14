/*
 * Pidgin - Internet Messenger
 * Copyright (C) Pidgin Developers <devel@pidgin.im>
 *
 * Pidgin is the legal property of its developers, whose names are too numerous
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#if !defined(PIDGIN_GLOBAL_HEADER_INSIDE) && !defined(PIDGIN_COMPILATION)
# error "only <pidgin.h> may be included directly"
#endif

#ifndef PIDGIN_ACCOUNT_STORE_H
#define PIDGIN_ACCOUNT_STORE_H

#include <gtk/gtk.h>

#include <purple.h>

/**
 * PidginAccountStore:
 *
 * #PidginAccountStore is a #GtkListStore that automatically keeps track of
 * what accounts are currently available in libpurple.  It's intended to be
 * used any time that you need to present an account selection to the user.
 *
 * Since: 3.0.0
 */

/**
 * PidginAccountStoreColumn:
 * @PIDGIN_ACCOUNT_STORE_COLUMN_ACCOUNT: This column holds a reference to the
 *                                       #PurpleAccount.
 * @PIDGIN_ACCOUNT_STORE_COLUMN_MARKUP: This column holds a pango markup to
 *                                      display the account to the user.
 * @PIDGIN_ACCOUNT_STORE_COLUMN_ICON: This column holds an icon in a #GdkPixbuf
 *                                    for the account.
 *
 * Constants for accessing columns in a #PidginAccountStore.
 *
 * Since: 3.0.0
 */
typedef enum {
	PIDGIN_ACCOUNT_STORE_COLUMN_ACCOUNT,
	PIDGIN_ACCOUNT_STORE_COLUMN_MARKUP,
	PIDGIN_ACCOUNT_STORE_COLUMN_ICON_NAME,
	/*< private >*/
	PIDGIN_ACCOUNT_STORE_N_COLUMNS,
} PidginAccountStoreColumn;

G_BEGIN_DECLS

#define PIDGIN_TYPE_ACCOUNT_STORE pidgin_account_store_get_type()
G_DECLARE_FINAL_TYPE(PidginAccountStore, pidgin_account_store, PIDGIN,
                     ACCOUNT_STORE, GtkListStore)

/**
 * pidgin_account_store_new:
 *
 * Creates a new #PidginAccountStore that can be used anywhere a #GtkListStore
 * can be used.
 *
 * Returns: (transfer full): The new #PidginAccountStore instance.
 *
 * Since: 3.0.0
 */
GtkListStore *pidgin_account_store_new(void);

/**
 * pidgin_account_store_filter_connected:
 * @model: The #GtkTreeModel that's being filtered.
 * @iter: The #GtkTreeIter to check.
 * @data: Userdata passed to gtk_tree_model_filter_set_visible_func().
 *
 * pidgin_account_store_filter_connected() is a #GtkTreeModelFilterVisibleFunc
 * that can be set on a #GtkTreeModelFilter via
 * gtk_tree_model_filter_set_visible_func(), to only show accounts that are
 * currently connected.
 *
 * Returns: %TRUE if the account will be displayed, %FALSE otherwise.
 */
gboolean pidgin_account_store_filter_connected(GtkTreeModel *model, GtkTreeIter *iter, gpointer data);

G_END_DECLS

#endif /* PIDGIN_ACCOUNT_STORE_H */

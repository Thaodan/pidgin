/*
 * GtkBuddyNote - Store notes on particular buddies
 * Copyright (C) 2007 Etan Reisner <deryni@pidgin.im>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include "internal.h"

#include <gtkblist.h>
#include <gtkplugin.h>

#include <debug.h>
#include <version.h>

static void
append_to_tooltip(PurpleBlistNode *node, GString *text, gboolean full)
{
	if (full) {
		const gchar *note = purple_blist_node_get_string(node, "notes");

		if (note != NULL) {
			g_string_append_printf(text, _("\nBuddy Note: %s"),
			                       note);
		}
	}
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
	purple_signal_connect(pidgin_blist_get_handle(), "drawing-tooltip",
	                      plugin, PURPLE_CALLBACK(append_to_tooltip), NULL);
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	PurplePlugin *buddynote = NULL;

	buddynote = purple_plugins_find_with_id("core-plugin_pack-buddynote");

	purple_plugin_unload(buddynote);

	return TRUE;
}

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,                           /**< major version */
	PURPLE_MINOR_VERSION,                           /**< minor version */
	PURPLE_PLUGIN_STANDARD,                         /**< type */
	PIDGIN_PLUGIN_TYPE,                             /**< ui_requirement */
	0,                                              /**< flags */
	NULL,                                           /**< dependencies */
	PURPLE_PRIORITY_DEFAULT,                        /**< priority */
	"gtkbuddynote",                                 /**< id */
	N_("Buddy Notes"),                              /**< name */
	VERSION,                                        /**< version */
	N_("Store notes on particular buddies."),       /**< summary */
	N_("Adds the option to store notes for buddies "
	   "on your buddy list."),                      /**< description */
	"Etan Reisner <deryni@pidgin.im>",              /**< author */
	PURPLE_WEBSITE,                                 /**< homepage */
	plugin_load,                                    /**< load */
	plugin_unload,                                  /**< unload */
	NULL,                                           /**< destroy */
	NULL,                                           /**< ui_info */
	NULL,                                           /**< extra_info */
	NULL,                                           /**< prefs_info */
	NULL,                                           /**< actions */

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static gboolean
check_for_buddynote(gpointer data)
{
	PurplePlugin *buddynote = NULL;

	buddynote = purple_plugins_find_with_id("core-plugin_pack-buddynote");

	if (buddynote == NULL) {
		buddynote = purple_plugins_find_with_basename("buddynote");
	}

	if (buddynote != NULL) {
		PurplePluginInfo *bninfo = buddynote->info;

		bninfo->flags = PURPLE_PLUGIN_FLAG_INVISIBLE;

		info.dependencies = g_list_append(info.dependencies,
		                                  "core-plugin_pack-buddynote");
	} else {
		info.flags = PURPLE_PLUGIN_FLAG_INVISIBLE;
	}

	return FALSE;
}

static void
init_plugin(PurplePlugin *plugin)
{
	/* Use g_idle_add so that the rest of the plugins can get loaded
	 * before we do our check. */
	g_idle_add(check_for_buddynote, plugin);
}

PURPLE_INIT_PLUGIN(gtkbuddynote, init_plugin, info)

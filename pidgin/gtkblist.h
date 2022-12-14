/* pidgin
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#if !defined(PIDGIN_GLOBAL_HEADER_INSIDE) && !defined(PIDGIN_COMPILATION)
# error "only <pidgin.h> may be included directly"
#endif

#ifndef _PIDGINBLIST_H_
#define _PIDGINBLIST_H_

#include <gtk/gtk.h>

#include <purple.h>

#define PIDGIN_TYPE_BUDDY_LIST (pidgin_buddy_list_get_type())

typedef struct _PidginBuddyList PidginBuddyList;

typedef enum {
	PIDGIN_STATUS_ICON_LARGE,
	PIDGIN_STATUS_ICON_SMALL

} PidginStatusIconSize;

/**************************************************************************
 * Structures
 **************************************************************************/
/**
 * PidginBuddyList:
 * @vbox:              This is the vbox that everything important gets packed
 *                     into.  Your plugin might want to pack something in it
 *                     itself.  Go, plugins!
 * @treeview:          It's a treeview... d'uh.
 * @treemodel:         This is the treemodel.
 * @text_column:       Column
 * @refresh_timer:     The timer for refreshing every 30 seconds
 * @selected_node:     The currently selected node
 * @scrollbook:        Scrollbook for alerts
 *
 * Like, everything you need to know about the gtk buddy list
 */
struct _PidginBuddyList {
	PurpleBuddyList parent;

	GtkWidget *window;
	GtkWidget *vbox;

	GtkWidget *treeview;
	GtkTreeStore *treemodel;
	GtkTreeViewColumn *text_column;

	GtkCellRenderer *text_rend;

	GActionGroup *action_group;

	PurpleBlistNode *selected_node;
};

G_BEGIN_DECLS

/**************************************************************************
 * GTK Buddy List API
 **************************************************************************/

G_DECLARE_FINAL_TYPE(PidginBuddyList, pidgin_buddy_list, PIDGIN, BUDDY_LIST,
                     PurpleBuddyList)

/**
 * pidgin_blist_get_handle:
 *
 * Get the handle for the GTK blist system.
 *
 * Returns: the handle to the blist system
 */
void *pidgin_blist_get_handle(void);

/**
 * pidgin_blist_init:
 *
 * Initializes the GTK blist system.
 */
void pidgin_blist_init(void);

/**
 * pidgin_blist_uninit:
 *
 * Uninitializes the GTK blist system.
 */
void pidgin_blist_uninit(void);

/**
 * pidgin_blist_get_default_gtk_blist:
 *
 * Returns the default gtk buddy list
 *
 * There's normally only one buddy list window, but that isn't a necessity. This function
 * returns the PidginBuddyList we're most likely wanting to work with. This is slightly
 * cleaner than an externed global.
 *
 * Returns: (transfer none): The default GTK buddy list.
 */
PidginBuddyList *pidgin_blist_get_default_gtk_blist(void);

/**
 * pidgin_blist_refresh:
 * @list:   This is the core list that gets updated from
 *
 * Refreshes all the nodes of the buddy list.
 * This should only be called when something changes to affect most of the nodes (such as a ui preference changing)
 */
void pidgin_blist_refresh(PurpleBuddyList *list);

/**
 * pidgin_blist_get_emblem:
 * @node:   The node to return an emblem for
 *
 * Returns the blist emblem.
 *
 * This may be an existing pixbuf that has been given an additional ref,
 * so it shouldn't be modified.
 *
 * Returns: (transfer full): A GdkPixbuf for the emblem to show, or NULL
 */
GdkPixbuf *
pidgin_blist_get_emblem(PurpleBlistNode *node);

/**
 * pidgin_blist_node_is_contact_expanded:
 * @node: The node in question.
 *
 * Returns a boolean indicating if @node is part of an expanded contact.
 *
 * This only makes sense for contact and buddy nodes. %FALSE is returned
 * for other types of nodes.
 *
 * Returns: A boolean indicating if @node is part of an expanded contact.
 */
gboolean pidgin_blist_node_is_contact_expanded(PurpleBlistNode *node);

/**************************************************************************
 * GTK Buddy List sorting functions
 **************************************************************************/

typedef void (*pidgin_blist_sort_function)(PurpleBlistNode *new, PurpleBuddyList *blist, GtkTreeIter group, GtkTreeIter *cur, GtkTreeIter *iter);

/**
 * pidgin_blist_get_sort_methods:
 *
 * Gets the current list of sort methods.
 *
 * Returns: (transfer none) (element-type PidginBlistSortMethod): A GSlist of sort methods
 */
GList *pidgin_blist_get_sort_methods(void);

struct _PidginBlistSortMethod {
	char *id;
	char *name;
	pidgin_blist_sort_function func;
};

typedef struct _PidginBlistSortMethod PidginBlistSortMethod;

/**
 * pidgin_blist_sort_method_reg:
 * @id:   The unique ID of the sorting method
 * @name: The method's name.
 * @func: (scope call): A pointer to the function.
 *
 * Registers a buddy list sorting method.
 */
void pidgin_blist_sort_method_reg(const char *id, const char *name, pidgin_blist_sort_function func);

/**
 * pidgin_blist_sort_method_unreg:
 * @id: The method's id
 *
 * Unregisters a buddy list sorting method.
 */
void pidgin_blist_sort_method_unreg(const char *id);

/**
 * pidgin_blist_sort_method_set:
 * @id: The method's id.
 *
 * Sets a buddy list sorting method.
 */
void pidgin_blist_sort_method_set(const char *id);

/**
 * pidgin_blist_setup_sort_methods:
 *
 * Sets up the programs default sort methods
 */
void pidgin_blist_setup_sort_methods(void);

/**
 * pidgin_blist_update_sort_methods:
 *
 * Updates the Sorting menu on the GTK buddy list window.
 */
void pidgin_blist_update_sort_methods(void);

/**
 * pidgin_blist_joinchat_is_showable:
 *
 * Determines if showing the join chat dialog is a valid action.
 *
 * Returns: Returns TRUE if there are accounts online capable of
 *         joining chat rooms.  Otherwise returns FALSE.
 */
gboolean pidgin_blist_joinchat_is_showable(void);

/**
 * pidgin_blist_joinchat_show:
 *
 * Shows the join chat dialog.
 */
void pidgin_blist_joinchat_show(void);

/**
 * pidgin_blist_get_name_markup:
 * @buddy: The buddy to return markup from
 * @selected:  Whether this buddy is selected. If TRUE, the markup will not change the color.
 * @aliased:  TRUE to return the appropriate alias of this buddy, FALSE to return its username and status information
 *
 * Returns a buddy's Pango markup appropriate for setting in a GtkCellRenderer.
 *
 * Returns: The markup for this buddy
 */
gchar *pidgin_blist_get_name_markup(PurpleBuddy *buddy, gboolean selected, gboolean aliased);

/**
 * pidgin_blist_query_tooltip_for_node:
 * @node: The buddy list to query a tooltip for.
 * @tooltip: The tooltip object to add a tooltip to.
 *
 * Queries and creates a custom tooltip for a buddy list node.
 *
 * Returns: %TRUE if a custom tooltip was added, %FALSE otherwise.
 *
 * Since: 3.0.0
 */
gboolean pidgin_blist_query_tooltip_for_node(PurpleBlistNode *node, GtkTooltip *tooltip);

G_END_DECLS

#endif /* _PIDGINBLIST_H_ */

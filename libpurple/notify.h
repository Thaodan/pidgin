/**
 * @file notify.h Notification API
 * @ingroup core
 * @see @ref notify-signals
 */

/* purple
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
#ifndef _PURPLE_NOTIFY_H_
#define _PURPLE_NOTIFY_H_

#include <stdlib.h>
#include <glib-object.h>
#include <glib.h>

typedef struct _PurpleNotifyUserInfoEntry	PurpleNotifyUserInfoEntry;

#define  PURPLE_TYPE_NOTIFY_USER_INFO  (purple_notify_user_info_get_type())
typedef struct _PurpleNotifyUserInfo		PurpleNotifyUserInfo;

/** @copydoc _PurpleNotifySearchColumn */
typedef struct _PurpleNotifySearchColumn	PurpleNotifySearchColumn;

#include "connection.h"
#include "request.h"


/**
 * Notification close callbacks.
 */
typedef void  (*PurpleNotifyCloseCallback) (gpointer user_data);


/**
 * Notification types.
 */
typedef enum
{
	PURPLE_NOTIFY_MESSAGE = 0,   /**< Message notification.         */
	PURPLE_NOTIFY_EMAIL,         /**< Single email notification.    */
	PURPLE_NOTIFY_EMAILS,        /**< Multiple email notification.  */
	PURPLE_NOTIFY_FORMATTED,     /**< Formatted text.               */
	PURPLE_NOTIFY_SEARCHRESULTS, /**< Buddy search results.         */
	PURPLE_NOTIFY_USERINFO,      /**< Formatted userinfo text.      */
	PURPLE_NOTIFY_URI            /**< URI notification or display.  */

} PurpleNotifyType;


/**
 * Notification message types.
 */
typedef enum
{
	PURPLE_NOTIFY_MSG_ERROR   = 0, /**< Error notification.       */
	PURPLE_NOTIFY_MSG_WARNING,     /**< Warning notification.     */
	PURPLE_NOTIFY_MSG_INFO         /**< Information notification. */

} PurpleNotifyMsgType;


/**
 * The types of buttons
 */
typedef enum
{
	PURPLE_NOTIFY_BUTTON_LABELED = 0,  /**< special use, see _button_add_labeled */
	PURPLE_NOTIFY_BUTTON_CONTINUE = 1,
	PURPLE_NOTIFY_BUTTON_ADD,
	PURPLE_NOTIFY_BUTTON_INFO,
	PURPLE_NOTIFY_BUTTON_IM,
	PURPLE_NOTIFY_BUTTON_JOIN,
	PURPLE_NOTIFY_BUTTON_INVITE
} PurpleNotifySearchButtonType;


/**
 * Search results object.
 */
typedef struct
{
	GList *columns;        /**< List of the search column objects. */
	GList *rows;           /**< List of rows in the result. */
	GList *buttons;        /**< List of buttons to display. */

} PurpleNotifySearchResults;

/**
 * Types of PurpleNotifyUserInfoEntry objects
 */
typedef enum
{
	PURPLE_NOTIFY_USER_INFO_ENTRY_PAIR = 0,
	PURPLE_NOTIFY_USER_INFO_ENTRY_SECTION_BREAK,
	PURPLE_NOTIFY_USER_INFO_ENTRY_SECTION_HEADER
} PurpleNotifyUserInfoEntryType;



/**
 * Callback for a button in a search result.
 *
 * @param c         the PurpleConnection passed to purple_notify_searchresults
 * @row:       the contents of the selected row
 * @user_data: User defined data.
 */
typedef void (*PurpleNotifySearchResultsCallback)(PurpleConnection *c, GList *row,
												gpointer user_data);


/**
 * Definition of a button.
 */
typedef struct
{
	PurpleNotifySearchButtonType type;
	PurpleNotifySearchResultsCallback callback; /**< Function to be called when clicked. */
	char *label;                              /**< only for PURPLE_NOTIFY_BUTTON_LABELED */
} PurpleNotifySearchButton;


/**
 * Notification UI operations.
 */
typedef struct
{
	void *(*notify_message)(PurpleNotifyMsgType type, const char *title,
		const char *primary, const char *secondary,
		PurpleRequestCommonParameters *cpar);

	void *(*notify_email)(PurpleConnection *gc,
	                      const char *subject, const char *from,
	                      const char *to, const char *url);

	void *(*notify_emails)(PurpleConnection *gc,
	                       size_t count, gboolean detailed,
	                       const char **subjects, const char **froms,
	                       const char **tos, const char **urls);

	void *(*notify_formatted)(const char *title, const char *primary,
	                          const char *secondary, const char *text);

	void *(*notify_searchresults)(PurpleConnection *gc, const char *title,
	                              const char *primary, const char *secondary,
	                              PurpleNotifySearchResults *results, gpointer user_data);

	void (*notify_searchresults_new_rows)(PurpleConnection *gc,
	                                      PurpleNotifySearchResults *results,
	                                      void *data);

	void *(*notify_userinfo)(PurpleConnection *gc, const char *who,
	                         PurpleNotifyUserInfo *user_info);

	void *(*notify_uri)(const char *uri);

	void (*close_notify)(PurpleNotifyType type, void *ui_handle);

	/*< private >*/
	void (*_purple_reserved1)(void);
	void (*_purple_reserved2)(void);
	void (*_purple_reserved3)(void);
	void (*_purple_reserved4)(void);
} PurpleNotifyUiOps;


G_BEGIN_DECLS


/**************************************************************************/
/** Search results notification API                                       */
/**************************************************************************/
/*@{*/

/**
 * Displays results from a buddy search.  This can be, for example,
 * a window with a list of all found buddies, where you are given the
 * option of adding buddies to your buddy list.
 *
 * @gc:        The PurpleConnection handle associated with the information.
 * @title:     The title of the message.  If this is NULL, the title
 *                  will be "Search Results."
 * @primary:   The main point of the message.
 * @secondary: The secondary information.
 * @results:   The PurpleNotifySearchResults instance.
 * @cb:        The callback to call when the user closes
 *                  the notification.
 * @user_data: The data to pass to the close callback and any other
 *                  callback associated with a button.
 *
 * Returns: A UI-specific handle.
 */
void *purple_notify_searchresults(PurpleConnection *gc, const char *title,
								const char *primary, const char *secondary,
								PurpleNotifySearchResults *results, PurpleNotifyCloseCallback cb,
								gpointer user_data);

/**
 * Frees a PurpleNotifySearchResults object.
 *
 * @results: The PurpleNotifySearchResults to free.
 */
void purple_notify_searchresults_free(PurpleNotifySearchResults *results);

/**
 * Replace old rows with the new. Reuse an existing window.
 *
 * @gc:        The PurpleConnection structure.
 * @results:   The PurpleNotifySearchResults structure.
 * @data:      Data returned by the purple_notify_searchresults().
 */
void purple_notify_searchresults_new_rows(PurpleConnection *gc,
										PurpleNotifySearchResults *results,
										void *data);


/**
 * Adds a stock button that will be displayed in the search results dialog.
 *
 * @results: The search results object.
 * @type:    Type of the button. (TODO: Only one button of a given type
 *                can be displayed.)
 * @cb:      Function that will be called on the click event.
 */
void purple_notify_searchresults_button_add(PurpleNotifySearchResults *results,
										  PurpleNotifySearchButtonType type,
										  PurpleNotifySearchResultsCallback cb);


/**
 * Adds a plain labelled button that will be displayed in the search results
 * dialog.
 *
 * @results: The search results object
 * @label:   The label to display
 * @cb:      Function that will be called on the click event
 */
void purple_notify_searchresults_button_add_labeled(PurpleNotifySearchResults *results,
                                                  const char *label,
                                                  PurpleNotifySearchResultsCallback cb);


/**
 * Returns a newly created search results object.
 *
 * Returns: The new search results object.
 */
PurpleNotifySearchResults *purple_notify_searchresults_new(void);

/**
 * Returns a newly created search result column object.  The column defaults
 * to being visible.
 *
 * @title: Title of the column. NOTE: Title will get g_strdup()ed.
 *
 * Returns: The new search column object.
 */
PurpleNotifySearchColumn *purple_notify_searchresults_column_new(const char *title);

/**
 * Returns the title of the column
 *
 * @column: The search column object.
 *
 * Returns: The title of the column
 */
const char *purple_notify_searchresult_column_get_title(const PurpleNotifySearchColumn *column);

/**
 * Sets whether or not a search result column is visible.
 *
 * @column:  The search column object.
 * @visible: TRUE if visible, or FALSE if not.
 */
void purple_notify_searchresult_column_set_visible(PurpleNotifySearchColumn *column, gboolean visible);

/**
 * Returns whether or not a search result column is visible.
 *
 * @column: The search column object.
 *
 * Returns: TRUE if the search result column is visible. FALSE otherwise.
 */
gboolean purple_notify_searchresult_column_is_visible(const PurpleNotifySearchColumn *column);

/**
 * Adds a new column to the search result object.
 *
 * @results: The result object to which the column will be added.
 * @column: The column that will be added to the result object.
 */
void purple_notify_searchresults_column_add(PurpleNotifySearchResults *results,
										  PurpleNotifySearchColumn *column);

/**
 * Adds a new row of the results to the search results object.
 *
 * @results: The search results object.
 * @row:     The row of the results.
 */
void purple_notify_searchresults_row_add(PurpleNotifySearchResults *results,
									   GList *row);

/*@}*/

/**************************************************************************/
/** @name Notification API                                                */
/**************************************************************************/
/*@{*/

/**
 * Displays a notification message to the user.
 *
 * @handle:    The plugin or connection handle.
 * @type:      The notification type.
 * @title:     The title of the message.
 * @primary:   The main point of the message.
 * @secondary: The secondary information.
 * @cpar:      The #PurpleRequestCommonParameters associated with this
 *                  request, or @c NULL if none is.
 * @cb:        The callback to call when the user closes
 *                  the notification.
 * @user_data: The data to pass to the callback.
 *
 * Returns: A UI-specific handle.
 */
void *purple_notify_message(void *handle, PurpleNotifyMsgType type,
	const char *title, const char *primary, const char *secondary,
	PurpleRequestCommonParameters *cpar, PurpleNotifyCloseCallback cb,
	gpointer user_data);

/**
 * Displays a single email notification to the user.
 *
 * @handle:    The plugin or connection handle.
 * @subject:   The subject of the email.
 * @from:      The from address.
 * @to:        The destination address.
 * @url:       The URL where the message can be read.
 * @cb:        The callback to call when the user closes
 *                  the notification.
 * @user_data: The data to pass to the callback.
 *
 * Returns: A UI-specific handle.
 */
void *purple_notify_email(void *handle, const char *subject,
						const char *from, const char *to,
						const char *url, PurpleNotifyCloseCallback cb,
						gpointer user_data);

/**
 * Displays a notification for multiple emails to the user.
 *
 * @handle:    The plugin or connection handle.
 * @count:     The number of emails.  '0' can be used to signify that
 *                  the user has no unread emails and the UI should remove
 *                  the mail notification.
 * @detailed:  @c TRUE if there is information for each email in the
 *                  arrays.
 * @subjects:  The array of subjects.
 * @froms:     The array of from addresses.
 * @tos:       The array of destination addresses.
 * @urls:      The URLs where the messages can be read.
 * @cb:        The callback to call when the user closes
 *                  the notification.
 * @user_data: The data to pass to the callback.
 *
 * Returns: A UI-specific handle.
 */
void *purple_notify_emails(void *handle, size_t count, gboolean detailed,
						 const char **subjects, const char **froms,
						 const char **tos, const char **urls,
						 PurpleNotifyCloseCallback cb, gpointer user_data);

/**
 * Displays a notification with formatted text.
 *
 * The text is essentially a stripped-down format of HTML, the same that
 * IMs may send.
 *
 * @handle:    The plugin or connection handle.
 * @title:     The title of the message.
 * @primary:   The main point of the message.
 * @secondary: The secondary information.
 * @text:      The formatted text.
 * @cb:        The callback to call when the user closes
 *                  the notification.
 * @user_data: The data to pass to the callback.
 *
 * Returns: A UI-specific handle.
 */
void *purple_notify_formatted(void *handle, const char *title,
							const char *primary, const char *secondary,
							const char *text, PurpleNotifyCloseCallback cb, gpointer user_data);

/**
 * Displays user information with formatted text, passing information giving
 * the connection and username from which the user information came.
 *
 * The text is essentially a stripped-down format of HTML, the same that
 * IMs may send.
 *
 * @gc:         The PurpleConnection handle associated with the information.
 * @who:        The username associated with the information.
 * @user_info:  The PurpleNotifyUserInfo which contains the information
 * @cb:         The callback to call when the user closes the notification.
 * @user_data:  The data to pass to the callback.
 *
 * Returns:  A UI-specific handle.
 */
void *purple_notify_userinfo(PurpleConnection *gc, const char *who,
						   PurpleNotifyUserInfo *user_info, PurpleNotifyCloseCallback cb,
						   gpointer user_data);

/**
 * Returns the GType for the PurpleNotifyUserInfo boxed structure.
 */
GType purple_notify_user_info_get_type(void);

/**
 * Create a new PurpleNotifyUserInfo which is suitable for passing to
 * purple_notify_userinfo()
 *
 * Returns:  A new PurpleNotifyUserInfo, which the caller must destroy when done
 */
PurpleNotifyUserInfo *purple_notify_user_info_new(void);

/**
 * Destroy a PurpleNotifyUserInfo
 *
 * @user_info:  The PurpleNotifyUserInfo
 */
void purple_notify_user_info_destroy(PurpleNotifyUserInfo *user_info);

/**
 * Retrieve the array of PurpleNotifyUserInfoEntry objects from a
 * PurpleNotifyUserInfo
 *
 * This GQueue may be manipulated directly with normal GQueue functions such
 * as g_queue_push_tail(). Only PurpleNotifyUserInfoEntry are allowed in the
 * queue.  If a PurpleNotifyUserInfoEntry item is added to the queue, it
 * should not be freed by the caller; PurpleNotifyUserInfo will free it when
 * destroyed.
 *
 * To remove a PurpleNotifyUserInfoEntry, use
 * purple_notify_user_info_remove_entry(). Do not use the GQueue directly.
 *
 * @user_info:  The PurpleNotifyUserInfo
 *
 * Returns: (TODO const): A GQueue of PurpleNotifyUserInfoEntry objects.
 */
GQueue *purple_notify_user_info_get_entries(PurpleNotifyUserInfo *user_info);

/**
 * Create a textual representation of a PurpleNotifyUserInfo, separating
 * entries with newline
 *
 * @user_info:  The PurpleNotifyUserInfo
 * @newline:    The separation character
 */
char *purple_notify_user_info_get_text_with_newline(PurpleNotifyUserInfo *user_info, const char *newline);

/**
 * Add a label/value pair to a PurpleNotifyUserInfo object.
 * PurpleNotifyUserInfo keeps track of the order in which pairs are added.
 *
 * @user_info:  The PurpleNotifyUserInfo
 * @label:      A label, which for example might be displayed by a
 *                   UI with a colon after it ("Status:"). Do not include
 *                   a colon.  If NULL, value will be displayed without a
 *                   label.
 * @value:      The value, which might be displayed by a UI after
 *                   the label.  This should be valid HTML.  If you want
 *                   to insert plaintext then use
 *                   purple_notify_user_info_add_pair_plaintext(), instead.
 *                   If this is NULL the label will still be displayed;
 *                   the UI should treat label as independent and not
 *                   include a colon if it would otherwise.
 */
void purple_notify_user_info_add_pair_html(PurpleNotifyUserInfo *user_info, const char *label, const char *value);

/**
 * Like purple_notify_user_info_add_pair_html, but value should be plaintext
 * and will be escaped using g_markup_escape_text().
 */
void purple_notify_user_info_add_pair_plaintext(PurpleNotifyUserInfo *user_info, const char *label, const char *value);

/**
 * Like purple_notify_user_info_add_pair_html, but the pair is inserted
 * at the beginning of the list.
 */
void purple_notify_user_info_prepend_pair_html(PurpleNotifyUserInfo *user_info, const char *label, const char *value);

/**
 * Like purple_notify_user_info_prepend_pair_html, but value should be plaintext
 * and will be escaped using g_markup_escape_text().
 */
void purple_notify_user_info_prepend_pair_plaintext(PurpleNotifyUserInfo *user_info, const char *label, const char *value);

/**
 * Remove a PurpleNotifyUserInfoEntry from a PurpleNotifyUserInfo object
 * without freeing the entry.
 *
 * @user_info:        The PurpleNotifyUserInfo
 * @user_info_entry:  The PurpleNotifyUserInfoEntry
 */
void purple_notify_user_info_remove_entry(PurpleNotifyUserInfo *user_info, PurpleNotifyUserInfoEntry *user_info_entry);

/**
 * Create a new PurpleNotifyUserInfoEntry
 *
 * If added to a PurpleNotifyUserInfo object, this should not be free()'d,
 * as PurpleNotifyUserInfo will do so when destroyed.
 * purple_notify_user_info_add_pair_html(),
 * purple_notify_user_info_add_pair_plaintext(),
 * purple_notify_user_info_prepend_pair_html() and
 * purple_notify_user_info_prepend_pair_plaintext() are convenience
 * methods for creating entries and adding them to a PurpleNotifyUserInfo.
 *
 * @label:  A label, which for example might be displayed by a UI
 *               with a colon after it ("Status:"). Do not include a
 *               colon.  If NULL, value will be displayed without a label.
 * @value:  The value, which might be displayed by a UI after the
 *               label.  If NULL, label will still be displayed; the UI
 *               should then treat label as independent and not include a
 *               colon if it would otherwise.
 *
 * @result A new PurpleNotifyUserInfoEntry
 */
PurpleNotifyUserInfoEntry *purple_notify_user_info_entry_new(const char *label, const char *value);

/**
 * Destroy a PurpleNotifyUserInfoEntry
 *
 * @user_info_entry:  The PurpleNotifyUserInfoEntry
 */
void purple_notify_user_info_entry_destroy(PurpleNotifyUserInfoEntry *user_info_entry);

/**
 * Add a section break.  A UI might display this as a horizontal line.
 *
 * @user_info:  The PurpleNotifyUserInfo
 */
void purple_notify_user_info_add_section_break(PurpleNotifyUserInfo *user_info);

/**
 * Prepend a section break.  A UI might display this as a horizontal line.
 *
 * @user_info:  The PurpleNotifyUserInfo
 */
void purple_notify_user_info_prepend_section_break(PurpleNotifyUserInfo *user_info);

/**
 * Add a section header.  A UI might display this in a different font
 * from other text.
 *
 * @user_info:  The PurpleNotifyUserInfo
 * @label:      The name of the section
 */
void purple_notify_user_info_add_section_header(PurpleNotifyUserInfo *user_info, const char *label);

/**
 * Prepend a section header.  A UI might display this in a different font
 * from other text.
 *
 * @user_info:  The PurpleNotifyUserInfo
 * @label:      The name of the section
 */
void purple_notify_user_info_prepend_section_header(PurpleNotifyUserInfo *user_info, const char *label);

/**
 * Remove the last item which was added to a PurpleNotifyUserInfo. This
 * could be used to remove a section header which is not needed.
 */
void purple_notify_user_info_remove_last_item(PurpleNotifyUserInfo *user_info);

/**
 * Get the label for a PurpleNotifyUserInfoEntry
 *
 * @user_info_entry:  The PurpleNotifyUserInfoEntry
 *
 * Returns:  The label
 */
const gchar *purple_notify_user_info_entry_get_label(PurpleNotifyUserInfoEntry *user_info_entry);

/**
 * Set the label for a PurpleNotifyUserInfoEntry
 *
 * @user_info_entry:  The PurpleNotifyUserInfoEntry
 * @label:            The label
 */
void purple_notify_user_info_entry_set_label(PurpleNotifyUserInfoEntry *user_info_entry, const char *label);

/**
 * Get the value for a PurpleNotifyUserInfoEntry
 *
 * @user_info_entry:  The PurpleNotifyUserInfoEntry
 *
 * @result  The value
 */
const gchar *purple_notify_user_info_entry_get_value(PurpleNotifyUserInfoEntry *user_info_entry);

/**
 * Set the value for a PurpleNotifyUserInfoEntry
 *
 * @user_info_entry:  The PurpleNotifyUserInfoEntry
 * @value:            The value
 */
void purple_notify_user_info_entry_set_value(PurpleNotifyUserInfoEntry *user_info_entry, const char *value);


/**
 * Get the type of a PurpleNotifyUserInfoEntry
 *
 * @user_info_entry:  The PurpleNotifyUserInfoEntry
 *
 * Returns:  The PurpleNotifyUserInfoEntryType
 */
PurpleNotifyUserInfoEntryType purple_notify_user_info_entry_get_type(PurpleNotifyUserInfoEntry *user_info_entry);

/**
 * Set the type of a PurpleNotifyUserInfoEntry
 *
 * @user_info_entry:  The PurpleNotifyUserInfoEntry
 * @type:             The PurpleNotifyUserInfoEntryType
 */
void purple_notify_user_info_entry_set_type(PurpleNotifyUserInfoEntry *user_info_entry,
										  PurpleNotifyUserInfoEntryType type);

/**
 * Opens a URI or somehow presents it to the user.
 *
 * @handle: The plugin or connection handle.
 * @uri:    The URI to display or go to.
 *
 * Returns: A UI-specific handle, if any. This may only be presented if
 *         the UI code displays a dialog instead of a webpage, or something
 *         similar.
 */
void *purple_notify_uri(void *handle, const char *uri);

/**
 * Checks, if passed UI handle is valid.
 *
 * @ui_handle: The UI handle.
 * @type:      The pointer to variable, where request type may be stored
 *                  (may be @c NULL).
 *
 * Returns: TRUE, if handle is valid, FALSE otherwise.
 */
gboolean
purple_notify_is_valid_ui_handle(void *ui_handle, PurpleNotifyType *type);

/**
 * Closes a notification.
 *
 * This should be used only by the UI operation functions and part of the
 * core.
 *
 * @type:      The notification type.
 * @ui_handle: The notification UI handle.
 */
void purple_notify_close(PurpleNotifyType type, void *ui_handle);

/**
 * Closes all notifications registered with the specified handle.
 *
 * @handle: The handle.
 */
void purple_notify_close_with_handle(void *handle);

/**
 * A wrapper for purple_notify_message that displays an information message.
 */
#define purple_notify_info(handle, title, primary, secondary, cpar) \
	purple_notify_message((handle), PURPLE_NOTIFY_MSG_INFO, (title), \
		(primary), (secondary), (cpar), NULL, NULL)

/**
 * A wrapper for purple_notify_message that displays a warning message.
 */
#define purple_notify_warning(handle, title, primary, secondary, cpar) \
	purple_notify_message((handle), PURPLE_NOTIFY_MSG_WARNING, (title), \
		(primary), (secondary), (cpar), NULL, NULL)

/**
 * A wrapper for purple_notify_message that displays an error message.
 */
#define purple_notify_error(handle, title, primary, secondary, cpar) \
	purple_notify_message((handle), PURPLE_NOTIFY_MSG_ERROR, (title), \
		(primary), (secondary), (cpar), NULL, NULL)

/*@}*/

/**************************************************************************/
/** @name UI Registration Functions                                       */
/**************************************************************************/
/*@{*/

/**
 * Sets the UI operations structure to be used when displaying a
 * notification.
 *
 * @ops: The UI operations structure.
 */
void purple_notify_set_ui_ops(PurpleNotifyUiOps *ops);

/**
 * Returns the UI operations structure to be used when displaying a
 * notification.
 *
 * Returns: The UI operations structure.
 */
PurpleNotifyUiOps *purple_notify_get_ui_ops(void);

/*@}*/

/**************************************************************************/
/** @name Notify Subsystem                                                */
/**************************************************************************/
/*@{*/

/**
 * Returns the notify subsystem handle.
 *
 * Returns: The notify subsystem handle.
 */
void *purple_notify_get_handle(void);

/**
 * Initializes the notify subsystem.
 */
void purple_notify_init(void);

/**
 * Uninitializes the notify subsystem.
 */
void purple_notify_uninit(void);

/*@}*/


G_END_DECLS

#endif /* _PURPLE_NOTIFY_H_ */

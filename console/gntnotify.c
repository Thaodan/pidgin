#include <gnt.h>
#include <gntbox.h>
#include <gntbutton.h>
#include <gntlabel.h>
#include <gnttree.h>

#include <util.h>

#include "gntnotify.h"
#include "gntgaim.h"

static struct
{
	GntWidget *window;
	GntWidget *tree;
} emaildialog;

static void *
gg_notify_message(GaimNotifyMsgType type, const char *title,
		const char *primary, const char *secondary)
{
	GntWidget *window, *button;
	GntTextFormatFlags pf = 0, sf = 0;

	switch (type)
	{
		case GAIM_NOTIFY_MSG_ERROR:
			sf |= GNT_TEXT_FLAG_BOLD;
		case GAIM_NOTIFY_MSG_WARNING:
			pf |= GNT_TEXT_FLAG_UNDERLINE;
		case GAIM_NOTIFY_MSG_INFO:
			pf |= GNT_TEXT_FLAG_BOLD;
			break;
	}

	window = gnt_box_new(FALSE, TRUE);
	gnt_box_set_toplevel(GNT_BOX(window), TRUE);
	gnt_box_set_title(GNT_BOX(window), title);
	gnt_box_set_fill(GNT_BOX(window), FALSE);
	gnt_box_set_alignment(GNT_BOX(window), GNT_ALIGN_MID);

	if (primary)
		gnt_box_add_widget(GNT_BOX(window),
				gnt_label_new_with_format(primary, pf));
	if (secondary)
		gnt_box_add_widget(GNT_BOX(window),
				gnt_label_new_with_format(secondary, sf));

	button = gnt_button_new(_("OK"));
	gnt_box_add_widget(GNT_BOX(window), button);
	g_signal_connect_swapped(G_OBJECT(button), "activate", G_CALLBACK(gnt_widget_destroy), window);

	gnt_widget_show(window);
	return window;
}

/* handle is, in all/most occasions, a GntWidget * */
static void gg_close_notify(GaimNotifyType type, void *handle)
{
	gnt_widget_destroy(GNT_WIDGET(handle));
}

static void *gg_notify_formatted(const char *title, const char *primary,
		const char *secondary, const char *text)
{
	/* XXX: For now, simply strip the html and use _notify_message. For future use,
	 * there should be some way of parsing the makrups from GntTextView */
	char *unformat = gaim_markup_strip_html(text);
	char *t = g_strdup_printf("%s%s%s",
			secondary ? secondary : "",
			secondary ? "\n" : "",
			unformat ? unformat : "");

	void *ret = gg_notify_message(GAIM_NOTIFY_MSG_INFO, title, primary, t);

	g_free(t);
	g_free(unformat);

	return ret;
}

static void
reset_email_dialog()
{
	emaildialog.window = NULL;
	emaildialog.tree = NULL;
}

static void
setup_email_dialog()
{
	GntWidget *box, *tree, *button;
	if (emaildialog.window)
		return;

	emaildialog.window = box = gnt_vbox_new(FALSE);
	gnt_box_set_toplevel(GNT_BOX(box), TRUE);
	gnt_box_set_title(GNT_BOX(box), _("Emails"));
	gnt_box_set_fill(GNT_BOX(box), FALSE);
	gnt_box_set_alignment(GNT_BOX(box), GNT_ALIGN_MID);
	gnt_box_set_pad(GNT_BOX(box), 0);

	gnt_box_add_widget(GNT_BOX(box),
			gnt_label_new_with_format(_("You have mail!"), GNT_TEXT_FLAG_BOLD));

	emaildialog.tree = tree = gnt_tree_new_with_columns(3);
	gnt_tree_set_column_titles(GNT_TREE(tree), _("Account"), _("From"), _("Subject"));
	gnt_tree_set_show_title(GNT_TREE(tree), TRUE);
	gnt_tree_set_col_width(GNT_TREE(tree), 0, 15);
	gnt_tree_set_col_width(GNT_TREE(tree), 1, 25);
	gnt_tree_set_col_width(GNT_TREE(tree), 2, 25);

	gnt_box_add_widget(GNT_BOX(box), tree);

	button = gnt_button_new(_("Close"));
	gnt_box_add_widget(GNT_BOX(box), button);

	g_signal_connect_swapped(G_OBJECT(button), "activate", G_CALLBACK(gnt_widget_destroy), box);
	g_signal_connect(G_OBJECT(box), "destroy", G_CALLBACK(reset_email_dialog), NULL);
}

static void *
gg_notify_emails(GaimConnection *gc, size_t count, gboolean detailed,
		const char **subjects, const char **froms, const char **tos,
		const char **urls)
{
	GaimAccount *account = gaim_connection_get_account(gc);
	GString *message = g_string_new(NULL);
	void *ret;

	if (!detailed)
	{
		g_string_append_printf(message,
				ngettext("%s (%s) has %d new message.",
					     "%s (%s) has %d new messages.",
						 (int)count),
				tos ? *tos : gaim_account_get_username(account),
				gaim_account_get_protocol_name(account), (int)count);
	}
	else
	{
		setup_email_dialog();

		gnt_tree_add_row_after(GNT_TREE(emaildialog.tree), GINT_TO_POINTER(time(NULL)),
				gnt_tree_create_row(GNT_TREE(emaildialog.tree),
					tos ? *tos : gaim_account_get_username(account), /* XXX: Perhaps add the prpl-name */
					froms ? *froms : "[Unknown sender]",
					*subjects),
				NULL, NULL);
		gnt_widget_show(emaildialog.window);
		return NULL;
	}

	ret = gg_notify_message(GAIM_NOTIFY_MSG_INFO, _("New Mail"), _("You have mail!"), message->str);
	g_string_free(message, TRUE);
	return ret;
}

static void *
gg_notify_email(GaimConnection *gc, const char *subject, const char *from,
		const char *to, const char *url)
{
	return gg_notify_emails(gc, 1, subject != NULL,
			subject ? &subject : NULL,
			from ? &from : NULL,
			to ? &to : NULL,
			url ? &url : NULL);
}

static void *
gg_notify_userinfo(GaimConnection *gc, const char *who, const char *text)
{
	/* Xeroxed from gtknotify.c */
	char *primary;
	void *ui_handle;

	primary = g_strdup_printf(_("Info for %s"), who);
	ui_handle = gg_notify_formatted(_("Buddy Information"), primary, NULL, text);
	g_free(primary);
	return ui_handle;
}

static GaimNotifyUiOps ops = 
{
	.notify_message = gg_notify_message,
	.close_notify = gg_close_notify,       /* The rest of the notify-uiops return a GntWidget.
                                              These widgets should be destroyed from here. */
	.notify_formatted = gg_notify_formatted,
	.notify_email = gg_notify_email,
	.notify_emails = gg_notify_emails,
	.notify_userinfo = gg_notify_userinfo,

	.notify_searchresults = NULL,          /* We are going to need multi-column GntTree's for this */
	.notify_searchresults_new_rows = NULL,
	.notify_uri = NULL                     /* This is of low-priority to me */
};

GaimNotifyUiOps *gg_notify_get_ui_ops()
{
	return &ops;
}

void gg_notify_init()
{
}

void gg_notify_uninit()
{
}



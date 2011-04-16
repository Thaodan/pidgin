/*
 * @file gtkcertmgr.c GTK+ Certificate Manager API
 * @ingroup pidgin
 */

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
 *
 */

#include "internal.h"
#include "core.h"
#include "pidgin.h"
#include "pidginstock.h"

#include "certificate.h"
#include "pkcs12.h"
#include "debug.h"
#include "notify.h"
#include "request.h"

#include "gtkblist.h"
#include "gtkutils.h"

#include "gtkcertmgr.h"

/*****************************************************************************
 * X.509 tls_peers management interface                                      *
 *****************************************************************************/

typedef struct {
	GtkWidget *mgmt_widget;
	GtkTreeView *listview;
	GtkTreeSelection *listselect;
	GtkWidget *importbutton;
	GtkWidget *exportbutton;
	GtkWidget *infobutton;
	GtkWidget *deletebutton;
	PurpleCertificatePool *tls_peers;
} tls_peers_mgmt_data;

tls_peers_mgmt_data *tpm_dat = NULL;

/* Columns
   See http://developer.gnome.org/doc/API/2.0/gtk/TreeWidget.html */
enum
{
	TPM_HOSTNAME_COLUMN,
	TPM_N_COLUMNS
};

static void
tls_peers_mgmt_destroy(GtkWidget *mgmt_widget, gpointer data)
{
	purple_debug_info("certmgr",
			  "tls peers self-destructs\n");

	purple_signals_disconnect_by_handle(tpm_dat);
	purple_request_close_with_handle(tpm_dat);
	g_free(tpm_dat); tpm_dat = NULL;
}

static void
tls_peers_mgmt_repopulate_list(void)
{
	GtkTreeView *listview = tpm_dat->listview;
	PurpleCertificatePool *tls_peers;
	GList *idlist, *l;

	GtkListStore *store = GTK_LIST_STORE(
		gtk_tree_view_get_model(GTK_TREE_VIEW(listview)));

	/* First, delete everything in the list */
	gtk_list_store_clear(store);

	/* Locate the "tls_peers" pool */
	tls_peers = purple_certificate_find_pool("x509", "tls_peers");
	g_return_if_fail(tls_peers);

	/* Grab the loaded certificates */
	idlist = purple_certificate_pool_get_idlist(tls_peers);

	/* Populate the listview */
	for (l = idlist; l; l = l->next) {
		GtkTreeIter iter;
		gtk_list_store_append(store, &iter);

		gtk_list_store_set(GTK_LIST_STORE(store), &iter,
				   TPM_HOSTNAME_COLUMN, l->data,
				   -1);
	}
	purple_certificate_pool_destroy_idlist(idlist);
}

static void
tls_peers_mgmt_mod_cb(PurpleCertificatePool *pool, const gchar *id, gpointer data)
{
	g_assert (pool == tpm_dat->tls_peers);

	tls_peers_mgmt_repopulate_list();
}

static void
tls_peers_mgmt_select_chg_cb(GtkTreeSelection *ignored, gpointer data)
{
	GtkTreeSelection *select = tpm_dat->listselect;
	GtkTreeIter iter;
	GtkTreeModel *model;

	/* See if things are selected */
	if (gtk_tree_selection_get_selected(select, &model, &iter)) {
		/* Enable buttons if something is selected */
		gtk_widget_set_sensitive(GTK_WIDGET(tpm_dat->exportbutton), TRUE);
		gtk_widget_set_sensitive(GTK_WIDGET(tpm_dat->infobutton), TRUE);
		gtk_widget_set_sensitive(GTK_WIDGET(tpm_dat->deletebutton), TRUE);
	} else {
		/* Otherwise, disable them */
		gtk_widget_set_sensitive(GTK_WIDGET(tpm_dat->exportbutton), FALSE);
		gtk_widget_set_sensitive(GTK_WIDGET(tpm_dat->infobutton), FALSE);
		gtk_widget_set_sensitive(GTK_WIDGET(tpm_dat->deletebutton), FALSE);

	}
}

static void
tls_peers_mgmt_import_ok2_cb(gpointer data, const char *result)
{
	PurpleCertificate *crt = (PurpleCertificate *) data;

	/* TODO: Perhaps prompt if you're overwriting a cert? */

	/* Drop the certificate into the pool */
	if (result && *result)
		purple_certificate_pool_store(tpm_dat->tls_peers, result, crt);

	/* And this certificate is not needed any more */
	purple_certificate_destroy(crt);
}

static void
tls_peers_mgmt_import_cancel2_cb(gpointer data, const char *result)
{
	PurpleCertificate *crt = (PurpleCertificate *) data;
	purple_certificate_destroy(crt);
}

static void
tls_peers_mgmt_import_ok_cb(gpointer data, const char *filename)
{
	PurpleCertificateScheme *x509;
	PurpleCertificate *crt;

	/* Load the scheme of our tls_peers pool (ought to be x509) */
	x509 = purple_certificate_pool_get_scheme(tpm_dat->tls_peers);

	/* Now load the certificate from disk */
	crt = purple_certificate_import(x509, filename);

	/* Did it work? */
	if (crt != NULL) {
		gchar *default_hostname;
		/* Get name to add to pool as */
		/* Make a guess about what the hostname should be */
		 default_hostname = purple_certificate_get_subject_name(crt);
		/* TODO: Find a way to make sure that crt gets destroyed
		   if the window gets closed unusually, such as by handle
		   deletion */
		/* TODO: Display some more information on the certificate? */
		purple_request_input(tpm_dat,
				     _("Certificate Import"),
				     _("Specify a hostname"),
				     _("Type the host name for this certificate."),
				     default_hostname,
				     FALSE, /* Not multiline */
				     FALSE, /* Not masked? */
				     NULL,  /* No hints? */
				     _("OK"),
				     G_CALLBACK(tls_peers_mgmt_import_ok2_cb),
				     _("Cancel"),
				     G_CALLBACK(tls_peers_mgmt_import_cancel2_cb),
				     NULL, NULL, NULL, /* No account/who/conv*/
				     crt    /* Pass cert instance to callback*/
				     );

		g_free(default_hostname);
	} else {
		/* Errors! Oh no! */
		/* TODO: Perhaps find a way to be specific about what just
		   went wrong? */
		gchar * secondary;

		secondary = g_strdup_printf(_("File %s could not be imported.\nMake sure that the file is readable and in PEM format.\n"), filename);
		purple_notify_error(NULL,
				    _("Certificate Import Error"),
				    _("X.509 certificate import failed"),
				    secondary);
		g_free(secondary);
	}
}

static void
tls_peers_mgmt_import_cb(GtkWidget *button, gpointer data)
{
	/* TODO: need to tell the user that we want a .PEM file! */
	purple_request_file(tpm_dat,
			    _("Select a PEM certificate"),
			    "certificate.pem",
			    FALSE, /* Not a save dialog */
			    G_CALLBACK(tls_peers_mgmt_import_ok_cb),
			    NULL,  /* Do nothing if cancelled */
			    NULL, NULL, NULL, NULL );/* No account,conv,etc. */
}

static void
tls_peers_mgmt_export_ok_cb(gpointer data, const char *filename)
{
	PurpleCertificate *crt = (PurpleCertificate *) data;

	g_assert(filename);

	if (!purple_certificate_export(filename, crt)) {
		/* Errors! Oh no! */
		/* TODO: Perhaps find a way to be specific about what just
		   went wrong? */
		gchar * secondary;

		secondary = g_strdup_printf(_("Export to file %s failed.\nCheck that you have write permission to the target path\n"), filename);
		purple_notify_error(NULL,
				    _("Certificate Export Error"),
				    _("X.509 certificate export failed"),
				    secondary);
		g_free(secondary);
	}

	purple_certificate_destroy(crt);
}

static void
tls_peers_mgmt_export_cancel_cb(gpointer data, const char *filename)
{
	PurpleCertificate *crt = (PurpleCertificate *) data;
	/* Pressing cancel just frees the duplicated certificate */
	purple_certificate_destroy(crt);
}

static void
tls_peers_mgmt_export_cb(GtkWidget *button, gpointer data)
{
	PurpleCertificate *crt;
	GtkTreeSelection *select = tpm_dat->listselect;
	GtkTreeIter iter;
	GtkTreeModel *model;
	gchar *id;

	/* See if things are selected */
	if (!gtk_tree_selection_get_selected(select, &model, &iter)) {
		purple_debug_warning("gtkcertmgr/tls_peers_mgmt",
				     "Export clicked with no selection?\n");
		return;
	}

	/* Retrieve the selected hostname */
	gtk_tree_model_get(model, &iter, TPM_HOSTNAME_COLUMN, &id, -1);

	/* Extract the certificate from the pool now to make sure it doesn't
	   get deleted out from under us */
	crt = purple_certificate_pool_retrieve(tpm_dat->tls_peers, id);

	if (NULL == crt) {
		purple_debug_error("gtkcertmgr/tls_peers_mgmt",
				   "Id %s was not in the peers cache?!\n",
				   id);
		g_free(id);
		return;
	}
	g_free(id);

	/* TODO: inform user that it will be a PEM? */
	purple_request_file(tpm_dat,
			    _("PEM X.509 Certificate Export"),
			    "certificate.pem",
			    TRUE, /* Is a save dialog */
			    G_CALLBACK(tls_peers_mgmt_export_ok_cb),
			    G_CALLBACK(tls_peers_mgmt_export_cancel_cb),
			    NULL, NULL, NULL, /* No account,conv,etc. */
			    crt); /* Pass the certificate on to the callback */
}

static void
tls_peers_mgmt_info_cb(GtkWidget *button, gpointer data)
{
	GtkTreeSelection *select = tpm_dat->listselect;
	GtkTreeIter iter;
	GtkTreeModel *model;
	gchar *id;
	PurpleCertificate *crt;

	/* See if things are selected */
	if (!gtk_tree_selection_get_selected(select, &model, &iter)) {
		purple_debug_warning("gtkcertmgr/tls_peers_mgmt",
				     "Info clicked with no selection?\n");
		return;
	}

	/* Retrieve the selected hostname */
	gtk_tree_model_get(model, &iter, TPM_HOSTNAME_COLUMN, &id, -1);

	/* Now retrieve the certificate */
	crt = purple_certificate_pool_retrieve(tpm_dat->tls_peers, id);
	g_return_if_fail(crt);

	/* Fire the notification */
	purple_certificate_display_x509(crt);

	g_free(id);
	purple_certificate_destroy(crt);
}

static void
tls_peers_mgmt_delete_confirm_cb(gchar *id, gint choice)
{
	if (1 == choice) {
		/* Yes, delete was confirmed */
		/* Now delete the thing */
		if (!purple_certificate_pool_delete(tpm_dat->tls_peers, id)) {
			purple_debug_warning("gtkcertmgr/tls_peers_mgmt",
					     "Deletion failed on id %s\n",
					     id);
		};
	}

	g_free(id);
}

static void
tls_peers_mgmt_delete_cb(GtkWidget *button, gpointer data)
{
	GtkTreeSelection *select = tpm_dat->listselect;
	GtkTreeIter iter;
	GtkTreeModel *model;

	/* See if things are selected */
	if (gtk_tree_selection_get_selected(select, &model, &iter)) {

		gchar *id;
		gchar *primary;

		/* Retrieve the selected hostname */
		gtk_tree_model_get(model, &iter, TPM_HOSTNAME_COLUMN, &id, -1);

		/* Prompt to confirm deletion */
		primary = g_strdup_printf(
			_("Really delete certificate for %s?"), id );

		purple_request_yes_no(tpm_dat, _("Confirm certificate delete"),
				      primary, NULL, /* Can this be NULL? */
				      0, /* "yes" is the default action */
				      NULL, NULL, NULL,
				      id, /* id ownership passed to callback */
				      tls_peers_mgmt_delete_confirm_cb,
				      tls_peers_mgmt_delete_confirm_cb );

		g_free(primary);

	} else {
		purple_debug_warning("gtkcertmgr/tls_peers_mgmt",
				     "Delete clicked with no selection?\n");
		return;
	}
}

static GtkWidget *
tls_peers_mgmt_build(void)
{
	GtkWidget *bbox;
	GtkListStore *store;

	/* This block of variables will end up in tpm_dat */
	GtkTreeView *listview;
	GtkTreeSelection *select;
	GtkWidget *importbutton;
	GtkWidget *exportbutton;
	GtkWidget *infobutton;
	GtkWidget *deletebutton;
	/** Element to return to the Certmgr window to put in the Notebook */
	GtkWidget *mgmt_widget;

	/* Create a struct to store context information about this window */
	tpm_dat = g_new0(tls_peers_mgmt_data, 1);

	tpm_dat->mgmt_widget = mgmt_widget =
		gtk_hbox_new(FALSE, /* Non-homogeneous */
			     PIDGIN_HIG_BOX_SPACE);
	gtk_container_set_border_width(GTK_CONTAINER(mgmt_widget),
		PIDGIN_HIG_BOX_SPACE);
	gtk_widget_show(mgmt_widget);

	/* Ensure that everything gets cleaned up when the dialog box
	   is closed */
	g_signal_connect(G_OBJECT(mgmt_widget), "destroy",
			 G_CALLBACK(tls_peers_mgmt_destroy), NULL);

	/* List view */
	store = gtk_list_store_new(TPM_N_COLUMNS, G_TYPE_STRING);

	tpm_dat->listview = listview =
		GTK_TREE_VIEW(gtk_tree_view_new_with_model(GTK_TREE_MODEL(store)));
	g_object_unref(G_OBJECT(store));

	{
		GtkCellRenderer *renderer;
		GtkTreeViewColumn *column;

		/* Set up the display columns */
		renderer = gtk_cell_renderer_text_new();
		column = gtk_tree_view_column_new_with_attributes(
			_("Hostname"),
			renderer,
			"text", TPM_HOSTNAME_COLUMN,
			NULL);
		gtk_tree_view_append_column(GTK_TREE_VIEW(listview), column);

		gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(store),
				TPM_HOSTNAME_COLUMN, GTK_SORT_ASCENDING);
	}

	/* Get the treeview selector into the struct */
	tpm_dat->listselect = select =
		gtk_tree_view_get_selection(GTK_TREE_VIEW(listview));

	/* Force the selection mode */
	gtk_tree_selection_set_mode(select, GTK_SELECTION_SINGLE);

	/* Use a callback to enable/disable the buttons based on whether
	   something is selected */
	g_signal_connect(G_OBJECT(select), "changed",
			 G_CALLBACK(tls_peers_mgmt_select_chg_cb), NULL);

	gtk_box_pack_start(GTK_BOX(mgmt_widget), 
			pidgin_make_scrollable(GTK_WIDGET(listview), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS, GTK_SHADOW_IN, -1, -1),
			TRUE, TRUE, /* Take up lots of space */
			0);
	gtk_widget_show(GTK_WIDGET(listview));

	/* Fill the list for the first time */
	tls_peers_mgmt_repopulate_list();

	/* Right-hand side controls box */
	bbox = gtk_vbutton_box_new();
	gtk_box_pack_end(GTK_BOX(mgmt_widget), bbox,
			 FALSE, FALSE, /* Do not take up space */
			 0);
	gtk_box_set_spacing(GTK_BOX(bbox), PIDGIN_HIG_BOX_SPACE);
	gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_START);
	gtk_widget_show(bbox);

	/* Import button */
	/* TODO: This is the wrong stock button */
	tpm_dat->importbutton = importbutton =
		gtk_button_new_from_stock(GTK_STOCK_ADD);
	gtk_box_pack_start(GTK_BOX(bbox), importbutton, FALSE, FALSE, 0);
	gtk_widget_show(importbutton);
	g_signal_connect(G_OBJECT(importbutton), "clicked",
			 G_CALLBACK(tls_peers_mgmt_import_cb), NULL);


	/* Export button */
	/* TODO: This is the wrong stock button */
	tpm_dat->exportbutton = exportbutton =
		gtk_button_new_from_stock(GTK_STOCK_SAVE);
	gtk_box_pack_start(GTK_BOX(bbox), exportbutton, FALSE, FALSE, 0);
	gtk_widget_show(exportbutton);
	g_signal_connect(G_OBJECT(exportbutton), "clicked",
			 G_CALLBACK(tls_peers_mgmt_export_cb), NULL);


	/* Info button */
	tpm_dat->infobutton = infobutton =
		gtk_button_new_from_stock(PIDGIN_STOCK_INFO);
	gtk_box_pack_start(GTK_BOX(bbox), infobutton, FALSE, FALSE, 0);
	gtk_widget_show(infobutton);
	g_signal_connect(G_OBJECT(infobutton), "clicked",
			 G_CALLBACK(tls_peers_mgmt_info_cb), NULL);


	/* Delete button */
	tpm_dat->deletebutton = deletebutton =
		gtk_button_new_from_stock(GTK_STOCK_DELETE);
	gtk_box_pack_start(GTK_BOX(bbox), deletebutton, FALSE, FALSE, 0);
	gtk_widget_show(deletebutton);
	g_signal_connect(G_OBJECT(deletebutton), "clicked",
			 G_CALLBACK(tls_peers_mgmt_delete_cb), NULL);

	/* Call the "selection changed" callback, which will probably disable
	   all the buttons since nothing is selected yet */
	tls_peers_mgmt_select_chg_cb(select, NULL);

	/* Bind us to the tls_peers pool */
	tpm_dat->tls_peers = purple_certificate_find_pool("x509", "tls_peers");

	/**** libpurple signals ****/
	/* Respond to certificate add/remove by just reloading everything */
	purple_signal_connect(tpm_dat->tls_peers, "certificate-stored",
			      tpm_dat, PURPLE_CALLBACK(tls_peers_mgmt_mod_cb),
			      NULL);
	purple_signal_connect(tpm_dat->tls_peers, "certificate-deleted",
			      tpm_dat, PURPLE_CALLBACK(tls_peers_mgmt_mod_cb),
			      NULL);

	return mgmt_widget;
}

const PidginCertificateManager tls_peers_mgmt = {
	tls_peers_mgmt_build, /* Widget creation function */
	N_("SSL Servers")
};

/*****************************************************************************
 * X.509 user certificates management interface                                      *
 *****************************************************************************/

typedef struct {
	GtkWidget *mgmt_widget;
	GtkTreeView *listview;
	GtkTreeSelection *listselect;
	GtkWidget *importbutton;
	GtkWidget *exportbutton;
	GtkWidget *infobutton;
	GtkWidget *deletebutton;
	PurpleCertificatePool *user_crts;
	PurplePrivateKeyPool *user_keys;
	PurplePkcs12Scheme *pkcs12;
} user_mgmt_data;

user_mgmt_data *um_dat = NULL;

/* Columns
   See http://developer.gnome.org/doc/API/2.0/gtk/TreeWidget.html */
enum
{
	UM_NAME_COLUMN,
	UM_N_COLUMNS
};

static void
user_mgmt_destroy(GtkWidget *mgmt_widget, gpointer data)
{
	purple_debug_info("certmgr",
			  "user self-destructs\n");

	purple_signals_disconnect_by_handle(um_dat);
	purple_request_close_with_handle(um_dat);
	g_free(um_dat); um_dat = NULL;
}

static void
user_mgmt_repopulate_list(void)
{
	GtkTreeView *listview = um_dat->listview;
	PurpleCertificatePool *user_crts;
	PurplePrivateKeyPool *user_keys;
	GList *idlist, *l;

	GtkListStore *store = GTK_LIST_STORE(
		gtk_tree_view_get_model(GTK_TREE_VIEW(listview)));

	/* First, delete everything in the list */
	gtk_list_store_clear(store);

	/* Locate the "user" pools */
	user_crts = purple_certificate_find_pool("x509", "user");
	user_keys = purple_privatekey_find_pool("x509", "user");

	g_return_if_fail(user_crts);
	g_return_if_fail(user_keys);

	/* Grab the loaded certificates */
	idlist = purple_certificate_pool_get_idlist(user_crts);

	/* Populate the listview */
	for (l = idlist; l; l = l->next) {
		GtkTreeIter iter;

		if ( ! purple_privatekey_pool_contains(user_keys, l->data)) {
			purple_debug_warning("gtkcertmgr/user_mgmt",
					     "User cert %s is missing it's private key.\n",
					     (gchar*)l->data);
		}

		gtk_list_store_append(store, &iter);

		gtk_list_store_set(GTK_LIST_STORE(store), &iter,
				   UM_NAME_COLUMN, l->data,
				   -1);
	}
	purple_certificate_pool_destroy_idlist(idlist);
}

static void
user_mgmt_mod_cb(PurpleCertificatePool *pool, const gchar *id, gpointer data)
{
	g_assert (pool == um_dat->user_crts);

	user_mgmt_repopulate_list();
}

static void
user_mgmt_select_chg_cb(GtkTreeSelection *ignored, gpointer data)
{
	GtkTreeSelection *select = um_dat->listselect;
	GtkTreeIter iter;
	GtkTreeModel *model;

	/* See if things are selected */
	if (gtk_tree_selection_get_selected(select, &model, &iter)) {
		/* Enable buttons if something is selected */
		gtk_widget_set_sensitive(GTK_WIDGET(um_dat->exportbutton), TRUE);
		gtk_widget_set_sensitive(GTK_WIDGET(um_dat->infobutton), TRUE);
		gtk_widget_set_sensitive(GTK_WIDGET(um_dat->deletebutton), TRUE);
	} else {
		/* Otherwise, disable them */
		gtk_widget_set_sensitive(GTK_WIDGET(um_dat->exportbutton), FALSE);
		gtk_widget_set_sensitive(GTK_WIDGET(um_dat->infobutton), FALSE);
		gtk_widget_set_sensitive(GTK_WIDGET(um_dat->deletebutton), FALSE);

	}
}

/**********************************************************
 * Importing a crt and key from PKCS12 file
 */

typedef struct {
	PurpleCertificate *crt;
	PurplePrivateKey *key;
	char *name;
} pkcs12_import_data;

static void
pkcs12_import_data_free(pkcs12_import_data *data)
{
	purple_certificate_destroy(data->crt);
	purple_privatekey_destroy(data->key);
	g_free(data->name);
	g_free(data);
}

static void
pkcs12_import_key_password_ok_cb(gboolean result, pkcs12_import_data *data)
{
	if (!purple_certificate_pool_store(um_dat->user_crts, data->name, data->crt)) {
		purple_notify_error(um_dat, NULL, _("Failed to save imported certificate."), NULL);
		/* TODO: deleted corresponding key stored in privatekey pool */
	}

	pkcs12_import_data_free(data);
}

static void
pkcs12_import_key_password_cancel_cb(pkcs12_import_data *data) 
{
	pkcs12_import_data_free(data);
}

static void
pkcs12_import_name_ok_cb(pkcs12_import_data *data, char* name)
{
	g_free(data->name);
	data->name = g_strdup(name);

	/* TODO: What if we have the same name? */
	purple_privatekey_pool_store_request(
		um_dat->user_keys,
		data->name,
		data->key,
		pkcs12_import_key_password_ok_cb,
		pkcs12_import_key_password_cancel_cb,
		data);
}

static void
pkcs12_import_name_cancel_cb(pkcs12_import_data *data)
{
	pkcs12_import_data_free(data);
}

static void
user_mgmt_import_pkcs12(const gchar* filename, const gchar* password)
{
	PurpleCertificateScheme *x509_crts;
	PurplePrivateKeyScheme *x509_keys;
	PurpleCertificate *crt = NULL;
	PurplePrivateKey *key = NULL;
	pkcs12_import_data *data;
	gboolean result;

	purple_debug_info("gtkcertmgr/user_mgmt", "Importing pkcs12 file %s with password XXXXXX\n", filename);

	/* Load the scheme of our user pool (ought to be x509) */
	x509_crts = purple_certificate_pool_get_scheme(um_dat->user_crts);
	g_return_if_fail(x509_crts);
	x509_keys = purple_privatekey_pool_get_scheme(um_dat->user_keys);
	g_return_if_fail(x509_keys);

	/* Now load the certificate/keys from disk */
	result = purple_pkcs12_import(um_dat->pkcs12, filename, password, &crt, &key);

	/* Did it work? */
	if (result) {
		gchar *default_name;

		/* Get name to add to pool as */
		/* Make a guess about what the hostname should be */
		 default_name = purple_certificate_get_subject_name(crt);
		/* TODO: Find a way to make sure that crt & key gets destroyed
		   if the window gets closed unusually, such as by handle
		   deletion */
		/* TODO: Display some more information on the certificate? */
		
		data = g_new0(pkcs12_import_data, 1);
		data->crt = crt;
		data->key = key;
		data->name = default_name;	

		/* TODO: Enable custom cert name dialog  */
		purple_request_input(um_dat,
				     _("PKCS12 Import"),
				     _("Specify a name"),
				     _("Type the name for the imported certificate and key."),
				     default_name,
				     FALSE, /* Not multiline */
				     FALSE, /* Not masked? */
				     NULL,  /* No hints? */
				     _("OK"),
				     G_CALLBACK(pkcs12_import_name_ok_cb),
				     _("Cancel"),
				     G_CALLBACK(pkcs12_import_name_cancel_cb),
				     NULL, NULL, NULL, /* No account/who/conv*/
				     data);
	} else {
		/* Errors! Oh no! */
		/* TODO: Perhaps find a way to be specific about what just
		   went wrong? */
		gchar * secondary;

		purple_certificate_destroy(crt);
		purple_privatekey_destroy(key);

		secondary = g_strdup_printf(_("File %s could not be imported.\nMake sure that the file is readable, in PKCS12 format and you used the correct password.\n"), filename);
		purple_notify_message(NULL, PURPLE_NOTIFY_MSG_ERROR,
				      _("Certificate Import Error"),
				      _("PKCS12 certificate import failed"),
				      secondary,
				      g_free,
				      secondary);
	}
}

static void
pkcs12_import_password_ok_cb(char *filename, PurpleRequestFields *fields)
{
        const char *entry;
        gboolean remember;

        entry = purple_request_fields_get_string(fields, "password");
/*      remember = purple_request_fields_get_bool(fields, "remember");*/

        if (!entry || !*entry)
        {
                purple_notify_error(um_dat, NULL, _("A password is required to access a PKCS12 file."), NULL);
		g_free(filename);
                return;
        }
/*
        if(remember)
                purple_account_set_remember_password(account, TRUE);
*/

	purple_debug_info("gtkcertmgr/user_mgmt/import_pkcs12", "Got password for pkcs file %s\n", filename);
	user_mgmt_import_pkcs12(filename, entry);
	g_free(filename);
}

static void
pkcs12_import_password_cancel_cb( char* filename)
{
	g_free(filename);
}

static void
user_mgmt_import_ok_cb(gpointer data, char *filename)
{
	purple_debug_info("gtkcertmgr/user_mgmt/import_pkcs12", "Importing pkcs12 file %s\n", filename);
	filename = g_strdup(filename); /* othewise it goes away after this func returns */
	purple_pkcs12_request_password(
		um_dat, 
		filename,
		G_CALLBACK(pkcs12_import_password_ok_cb), 
		G_CALLBACK(pkcs12_import_password_cancel_cb),
		(void*)filename);
}

static void
user_mgmt_import_cb(GtkWidget *button, gpointer data)
{
	/* TODO: need to tell the user that we want a .PEM file! */
	purple_request_file(um_dat,
			    _("Select a PKCS12 certificate file"),
			    "certificate.p12",
			    FALSE, /* Not a save dialog */
			    G_CALLBACK(user_mgmt_import_ok_cb),
			    NULL,  /* Do nothing if cancelled */
			    NULL, NULL, NULL, NULL );/* No account,conv,etc. */
}

/**********************************************************
 * Exporting crt and key to PKCS12 file
 */

typedef struct {
	PurpleCertificate *crt;
	PurplePrivateKey *key;
	char* filename;
	char* id;
} pkcs12_export_data;

static void
pkcs12_export_data_free(pkcs12_export_data *data)
{

	g_return_if_fail(data);
	purple_certificate_destroy(data->crt);
	purple_privatekey_destroy(data->key);
	g_free(data->filename);
	g_free(data->id);
	g_free(data);

}

static void
pkcs12_export_password_ok_cb(pkcs12_export_data *data, PurpleRequestFields *fields)
{
        const char *entry;
        gboolean remember;

	purple_debug_info("certmgr/user_mgmt/pkcs12_export", "pkcs12 password ok cb\n");
        entry = purple_request_fields_get_string(fields, "password");
/*      remember = purple_request_fields_get_bool(fields, "remember");*/

        if (!entry || !*entry)
        {
                purple_notify_error(um_dat, NULL, _("A password is required to protect the PKCS12 file."), NULL);
		pkcs12_export_data_free(data);
                return;
        }
/*
        if(remember)
                purple_account_set_remember_password(account, TRUE);
*/

	purple_debug_info("gtkcertmgr/user_mgmt/export_pkcs12", "Got password for pkcs file %s\n", data->filename);

	/* Finally create the pkcs12 file */

	if (!purple_pkcs12_export(um_dat->pkcs12, data->filename, entry, data->crt, data->key)) {
		/* Errors! Oh no! */
		/* TODO: Perhaps find a way to be specific about what just
		   went wrong? */
		gchar * secondary;

		secondary = g_strdup_printf(
			_("Export to file %s failed.\nCheck that you have write "
			  "permission to the target path\n"), data->filename);

		purple_notify_message(NULL, PURPLE_NOTIFY_MSG_ERROR,
				    _("PKCS12 Export Error"),
				    _("PKCS12 certificate & key export failed"),
				    secondary,
				    NULL,
                                    NULL);
	}

	pkcs12_export_data_free(data);
}

static void
pkcs12_export_password_cancel_cb(pkcs12_export_data* data)
{
	pkcs12_export_data_free(data);
}

static void
user_mgmt_export_ok_cb(pkcs12_export_data *data, const char *filename)
{
	purple_debug_info("certmgr/user_mgmt/pkcs12_export", "file ok cb\n");
	data->filename = g_strdup(filename); /* it goes away otherwise */
	purple_pkcs12_request_password(
		um_dat, 
		data->filename,
		G_CALLBACK(pkcs12_export_password_ok_cb), 
		G_CALLBACK(pkcs12_export_password_cancel_cb),
		data);
}

static void
user_mgmt_export_cancel_cb(pkcs12_export_data *data, const char *filename)
{
	/* Pressing cancel just frees the duplicated certificate & key*/
	pkcs12_export_data_free(data);
}

static void
pkcs12_get_key_password_ok_cb(PurplePrivateKey *key, pkcs12_export_data *data)
{
	char* secondary;

	purple_debug_info("certmgr/user_mgmt/pkcs12_export", "key password ok cb\n");
	if (NULL == key) {
		purple_debug_error("gtkcertmgr/user_mgmt",
				   "Id %s was not in the user key pool or bad password\n",
				   data->id);

		secondary = g_strdup_printf(
			_("The private key named \"%s\" was not found or the key's password was incorrect."),
			data->id);

		purple_notify_message(NULL, PURPLE_NOTIFY_MSG_ERROR,
				_("PKCS12 Export Error"),
				_("PKCS12 certificate & key export failed"),
				secondary,
				NULL,
				NULL);

		pkcs12_export_data_free(data);

		return;
	}

	data->key = key;

	purple_request_file(um_dat,
			    _("PKCS12 Certificate & Key Export"),
			    "certificate.p12",
			    TRUE, /* Is a save dialog */
			    G_CALLBACK(user_mgmt_export_ok_cb),
			    G_CALLBACK(user_mgmt_export_cancel_cb),
			    NULL, NULL, NULL, /* No account,conv,etc. */
			    data); /* Pass the certificate & key on to the callback */
}

static void
pkcs12_get_key_password_cancel_cb(pkcs12_export_data *data)
{
	pkcs12_export_data_free(data);
}

static void
user_mgmt_export_cb(GtkWidget *button, void* stuff)
{
	PurpleCertificate *crt = NULL;
	GtkTreeSelection *select = um_dat->listselect;
	GtkTreeIter iter;
	GtkTreeModel *model = NULL;
	gchar *id = NULL;
	pkcs12_export_data *data = NULL;

	purple_debug_info("gtkcertmgr/user_mgmt", "1111111111111111\n");

	/* See if things are selected */
	if (!gtk_tree_selection_get_selected(select, &model, &iter)) {
		purple_debug_warning("gtkcertmgr/user_mgmt",
				     "Export clicked with no selection?\n");
		return;
	}

	/* Retrieve the selected name */
	gtk_tree_model_get(model, &iter, UM_NAME_COLUMN, &id, -1);

	/* Extract the certificate & keys from the pools now to make sure it doesn't
	   get deleted out from under us */
	crt = purple_certificate_pool_retrieve(um_dat->user_crts, id);

	if (NULL == crt) {
		purple_debug_error("gtkcertmgr/user_mgmt",
	 				   "Id %s was not in the user cert pool?!\n",
					   id);
		g_free(id);
		return;
	}

	/* stuff we will need in our callbacks */
	data = g_new0(pkcs12_export_data, 1);
	data->crt = crt;
	data->id = id;

	purple_privatekey_pool_retrieve_request(
			um_dat->user_keys,
			id,
			G_CALLBACK(pkcs12_get_key_password_ok_cb),
			G_CALLBACK(pkcs12_get_key_password_cancel_cb),
			data);
}

/**********************************************************
 * Display certificate and key info
 */

static void
user_mgmt_info_cb(GtkWidget *button, gpointer data)
{
	GtkTreeSelection *select = um_dat->listselect;
	GtkTreeIter iter;
	GtkTreeModel *model;
	gchar *id;
	PurpleCertificate *crt;

	/* See if things are selected */
	if (!gtk_tree_selection_get_selected(select, &model, &iter)) {
		purple_debug_warning("gtkcertmgr/user_mgmt",
				     "Info clicked with no selection?\n");
		return;
	}

	/* Retrieve the selected name */
	gtk_tree_model_get(model, &iter, UM_NAME_COLUMN, &id, -1);

	/* Now retrieve the certificate */
	crt = purple_certificate_pool_retrieve(um_dat->user_crts, id);
	g_return_if_fail(crt);

	/* Fire the notification */
	purple_certificate_display_x509(crt);

	g_free(id);
	purple_certificate_destroy(crt);
}

/***********************************************************
 * Delete a certificate and key
 */

static void
user_mgmt_delete_confirm_cb(gchar *id, gint choice)
{
	if (1 == choice) {
		/* Yes, delete was confirmed */
		/* Now delete the thing */
		if (!purple_certificate_pool_delete(um_dat->user_crts, id)) {
			purple_debug_warning("gtkcertmgr/user_mgmt",
					     "Deletion failed of certificate for id %s\n",
					     id);
		};
		if (!purple_privatekey_pool_delete(um_dat->user_keys, id)) {
			purple_debug_warning("gtkcertmgr/user_mgrm",
					     "Deletion failed of private key for id %s\n",
					     id);
		}
	}

	g_free(id);
}

static void
user_mgmt_delete_cb(GtkWidget *button, gpointer data)
{
	GtkTreeSelection *select = um_dat->listselect;
	GtkTreeIter iter;
	GtkTreeModel *model;

	/* See if things are selected */
	if (gtk_tree_selection_get_selected(select, &model, &iter)) {

		gchar *id;
		gchar *primary;

		/* Retrieve the selected hostname */
		gtk_tree_model_get(model, &iter, UM_NAME_COLUMN, &id, -1);

		/* Prompt to confirm deletion */
		primary = g_strdup_printf(
			_("Really delete certificate for %s?"), id );

		purple_request_yes_no(um_dat, _("Confirm certificate delete"),
				      primary, NULL, /* Can this be NULL? */
				      0, /* "yes" is the default action */
				      NULL, NULL, NULL,
				      id, /* id ownership passed to callback */
				      user_mgmt_delete_confirm_cb,
				      user_mgmt_delete_confirm_cb );

		g_free(primary);

	} else {
		purple_debug_warning("gtkcertmgr/user_mgmt",
				     "Delete clicked with no selection?\n");
		return;
	}
}

/**********************************************************
 * Setup the user certificate & key management tab
 */

static GtkWidget *
user_mgmt_build(void)
{
	GtkWidget *bbox;
	GtkListStore *store;
	GtkWidget *sw;

	/* This block of variables will end up in um_dat */
	GtkTreeView *listview;
	GtkTreeSelection *select;
	GtkWidget *importbutton;
	GtkWidget *exportbutton;
	GtkWidget *infobutton;
	GtkWidget *deletebutton;
	/** Element to return to the Certmgr window to put in the Notebook */
	GtkWidget *mgmt_widget;

	/* Create a struct to store context information about this window */
	um_dat = g_new0(user_mgmt_data, 1);

	um_dat->mgmt_widget = mgmt_widget =
		gtk_hbox_new(FALSE, /* Non-homogeneous */
			     PIDGIN_HIG_BOX_SPACE);
	gtk_container_set_border_width(GTK_CONTAINER(mgmt_widget),
		PIDGIN_HIG_BOX_SPACE);
	gtk_widget_show(mgmt_widget);

	/* Ensure that everything gets cleaned up when the dialog box
	   is closed */
	g_signal_connect(G_OBJECT(mgmt_widget), "destroy",
			 G_CALLBACK(user_mgmt_destroy), NULL);

	/* Scrolled window */
	sw = gtk_scrolled_window_new(NULL,NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
			GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(sw), GTK_SHADOW_IN);
	gtk_box_pack_start(GTK_BOX(mgmt_widget), GTK_WIDGET(sw),
			TRUE, TRUE, /* Take up lots of space */
			0);
	gtk_widget_show(GTK_WIDGET(sw));

	/* List view */
	store = gtk_list_store_new(UM_N_COLUMNS, G_TYPE_STRING);

	um_dat->listview = listview =
		GTK_TREE_VIEW(gtk_tree_view_new_with_model(GTK_TREE_MODEL(store)));
	g_object_unref(G_OBJECT(store));

	{
		GtkCellRenderer *renderer;
		GtkTreeViewColumn *column;

		/* Set up the display columns */
		renderer = gtk_cell_renderer_text_new();
		column = gtk_tree_view_column_new_with_attributes(
			_("Name"),
			renderer,
			"text", UM_NAME_COLUMN,
			NULL);
		gtk_tree_view_append_column(GTK_TREE_VIEW(listview), column);

		gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(store),
				UM_NAME_COLUMN, GTK_SORT_ASCENDING);
	}

	/* Get the treeview selector into the struct */
	um_dat->listselect = select =
		gtk_tree_view_get_selection(GTK_TREE_VIEW(listview));

	/* Force the selection mode */
	gtk_tree_selection_set_mode(select, GTK_SELECTION_SINGLE);

	/* Use a callback to enable/disable the buttons based on whether
	   something is selected */
	g_signal_connect(G_OBJECT(select), "changed",
			 G_CALLBACK(user_mgmt_select_chg_cb), NULL);

	gtk_container_add(GTK_CONTAINER(sw), GTK_WIDGET(listview));
	gtk_widget_show(GTK_WIDGET(listview));

	/* Fill the list for the first time */
	user_mgmt_repopulate_list();

	/* Right-hand side controls box */
	bbox = gtk_vbutton_box_new();
	gtk_box_pack_end(GTK_BOX(mgmt_widget), bbox,
			 FALSE, FALSE, /* Do not take up space */
			 0);
	gtk_box_set_spacing(GTK_BOX(bbox), PIDGIN_HIG_BOX_SPACE);
	gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_START);
	gtk_widget_show(bbox);

	/* Import button */
	/* TODO: This is the wrong stock button */
	um_dat->importbutton = importbutton =
		gtk_button_new_from_stock(GTK_STOCK_ADD);
	gtk_box_pack_start(GTK_BOX(bbox), importbutton, FALSE, FALSE, 0);
	gtk_widget_show(importbutton);
	g_signal_connect(G_OBJECT(importbutton), "clicked",
			 G_CALLBACK(user_mgmt_import_cb), NULL);


	/* Export button */
	/* TODO: This is the wrong stock button */
	um_dat->exportbutton = exportbutton =
		gtk_button_new_from_stock(GTK_STOCK_SAVE);
	gtk_box_pack_start(GTK_BOX(bbox), exportbutton, FALSE, FALSE, 0);
	gtk_widget_show(exportbutton);
	g_signal_connect(G_OBJECT(exportbutton), "clicked",
			 G_CALLBACK(user_mgmt_export_cb), NULL);


	/* Info button */
	um_dat->infobutton = infobutton =
		gtk_button_new_from_stock(PIDGIN_STOCK_INFO);
	gtk_box_pack_start(GTK_BOX(bbox), infobutton, FALSE, FALSE, 0);
	gtk_widget_show(infobutton);
	g_signal_connect(G_OBJECT(infobutton), "clicked",
			 G_CALLBACK(user_mgmt_info_cb), NULL);


	/* Delete button */
	um_dat->deletebutton = deletebutton =
		gtk_button_new_from_stock(GTK_STOCK_DELETE);
	gtk_box_pack_start(GTK_BOX(bbox), deletebutton, FALSE, FALSE, 0);
	gtk_widget_show(deletebutton);
	g_signal_connect(G_OBJECT(deletebutton), "clicked",
			 G_CALLBACK(user_mgmt_delete_cb), NULL);

	/* Call the "selection changed" callback, which will probably disable
	   all the buttons since nothing is selected yet */
	user_mgmt_select_chg_cb(select, NULL);

	/* Bind us to the user pool */
	um_dat->user_crts = purple_certificate_find_pool("x509", "user");
	um_dat->user_keys = purple_privatekey_find_pool("x509", "user");
	um_dat->pkcs12 = purple_pkcs12_find_scheme("pkcs12");

	/**** libpurple signals ****/
	/* Respond to certificate add/remove by just reloading everything */
	purple_signal_connect(um_dat->user_crts, "certificate-stored",
			      um_dat, PURPLE_CALLBACK(user_mgmt_mod_cb),
			      NULL);
	purple_signal_connect(um_dat->user_crts, "certificate-deleted",
			      um_dat, PURPLE_CALLBACK(user_mgmt_mod_cb),
			      NULL);

	return mgmt_widget;
}

const PidginCertificateManager user_mgmt = {
	user_mgmt_build, /* Widget creation function */
	N_("Your Certificates")
};

/*****************************************************************************
 * GTK+ main certificate manager                                             *
 *****************************************************************************/
typedef struct
{
	GtkWidget *window;
	GtkWidget *notebook;

	GtkWidget *closebutton;
} CertMgrDialog;

/* If a certificate manager window is open, this will point to it.
   So if it is set, don't open another one! */
CertMgrDialog *certmgr_dialog = NULL;

static gboolean
certmgr_close_cb(GtkWidget *w, CertMgrDialog *dlg)
{
	/* TODO: Ignoring the arguments to this function may not be ideal,
	   but there *should* only be "one dialog to rule them all" at a time*/
	pidgin_certmgr_hide();
	return FALSE;
}

void
pidgin_certmgr_show(void)
{
	CertMgrDialog *dlg;
	GtkWidget *win;
	GtkWidget *vbox;

	/* Enumerate all the certificates on file */
	{
		GList *idlist, *poollist;

		for ( poollist = purple_certificate_get_pools();
		      poollist;
		      poollist = poollist->next ) {
			PurpleCertificatePool *pool = poollist->data;
			GList *l;

			purple_debug_info("gtkcertmgr",
					  "Pool %s found for scheme %s -"
					  "Enumerating certificates:\n",
					  pool->name, pool->scheme_name);

			idlist = purple_certificate_pool_get_idlist(pool);

			for (l=idlist; l; l = l->next) {
				purple_debug_info("gtkcertmgr",
						  "- %s\n",
						  l->data ? (gchar *) l->data : "(null)");
			} /* idlist */
			purple_certificate_pool_destroy_idlist(idlist);
		} /* poollist */
	}


	/* If the manager is already open, bring it to the front */
	if (certmgr_dialog != NULL) {
		gtk_window_present(GTK_WINDOW(certmgr_dialog->window));
		return;
	}

	/* Create the dialog, and set certmgr_dialog so we never create
	   more than one at a time */
	dlg = certmgr_dialog = g_new0(CertMgrDialog, 1);

	win = dlg->window =
		pidgin_create_dialog(_("Certificate Manager"),/* Title */
				     PIDGIN_HIG_BORDER, /*Window border*/
				     "certmgr",         /* Role */
				     TRUE); /* Allow resizing */
	g_signal_connect(G_OBJECT(win), "delete_event",
			 G_CALLBACK(certmgr_close_cb), dlg);


	/* TODO: Retrieve the user-set window size and use it */
	gtk_window_set_default_size(GTK_WINDOW(win), 400, 400);

	/* Main vbox */
	vbox = pidgin_dialog_get_vbox_with_properties(GTK_DIALOG(win), FALSE, PIDGIN_HIG_BORDER);

	/* Notebook of various certificate managers */
	dlg->notebook = gtk_notebook_new();
	gtk_box_pack_start(GTK_BOX(vbox), dlg->notebook,
			   TRUE, TRUE, /* Notebook should take extra space */
			   0);
	gtk_widget_show(dlg->notebook);

	/* Close button */
	dlg->closebutton = pidgin_dialog_add_button(GTK_DIALOG(win), GTK_STOCK_CLOSE,
			G_CALLBACK(certmgr_close_cb), dlg);

	/* Add the defined certificate managers */
	/* TODO: Find a way of determining whether each is shown or not */
	/* TODO: Implement this correctly */
	gtk_notebook_append_page(GTK_NOTEBOOK (dlg->notebook),
				 (tls_peers_mgmt.build)(),
				 gtk_label_new(_(tls_peers_mgmt.label)) );
	gtk_notebook_append_page(GTK_NOTEBOOK (dlg->notebook),
				 (user_mgmt.build)(),
				 gtk_label_new(_(user_mgmt.label)) );

	gtk_widget_show(win);
}

void
pidgin_certmgr_hide(void)
{
	/* If it isn't open, do nothing */
	if (certmgr_dialog == NULL) {
		return;
	}

	purple_signals_disconnect_by_handle(certmgr_dialog);
	purple_prefs_disconnect_by_handle(certmgr_dialog);

	gtk_widget_destroy(certmgr_dialog->window);
	g_free(certmgr_dialog);
	certmgr_dialog = NULL;
}

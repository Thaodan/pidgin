/**
 * @file buddy_opt.c
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

#include "debug.h"
#include "internal.h"
#include "notify.h"
#include "request.h"

#include "buddy_info.h"
#include "buddy_list.h"
#include "buddy_opt.h"
#include "char_conv.h"
#include "header_info.h"
#include "im.h"
#include "qq_base.h"
#include "packet_parse.h"
#include "qq_network.h"
#include "utils.h"

#define PURPLE_GROUP_QQ_FORMAT          "QQ (%s)"
#define PURPLE_GROUP_QQ_UNKNOWN         "QQ Unknown"
#define PURPLE_GROUP_QQ_BLOCKED         "QQ Blocked"

#define QQ_REMOVE_BUDDY_REPLY_OK      0x00
#define QQ_REMOVE_SELF_REPLY_OK       0x00
#define QQ_ADD_BUDDY_AUTH_REPLY_OK    0x30	/* ASCII value of "0" */

enum {
	QQ_MY_AUTH_APPROVE = 0x30,	/* ASCII value of "0" */
	QQ_MY_AUTH_REJECT = 0x31,	/* ASCII value of "1" */
	QQ_MY_AUTH_REQUEST = 0x32,	/* ASCII value of "2" */
};

typedef struct _qq_add_buddy_request {
	guint32 uid;
	guint16 seq;
} qq_add_buddy_request;

/* send packet to remove a buddy from my buddy list */
static void _qq_send_packet_remove_buddy(PurpleConnection *gc, guint32 uid)
{
	gchar uid_str[11];

	g_return_if_fail(uid > 0);

	g_snprintf(uid_str, sizeof(uid_str), "%d", uid);
	qq_send_cmd(gc, QQ_CMD_DEL_BUDDY, (guint8 *) uid_str, strlen(uid_str));
}

/* try to remove myself from someone's buddy list */
static void _qq_send_packet_remove_self_from(PurpleConnection *gc, guint32 uid)
{
	guint8 raw_data[16] = {0};
	gint bytes = 0;

	g_return_if_fail(uid > 0);

	bytes += qq_put32(raw_data + bytes, uid);

	qq_send_cmd(gc, QQ_CMD_REMOVE_SELF, raw_data, bytes);
}

/* try to add a buddy without authentication */
static void _qq_send_packet_add_buddy(PurpleConnection *gc, guint32 uid)
{
	qq_data *qd = (qq_data *) gc->proto_data;
	qq_add_buddy_request *req;
	gchar uid_str[11];

	g_return_if_fail(uid > 0);

	/* we need to send the ascii code of this uid to qq server */
	g_snprintf(uid_str, sizeof(uid_str), "%d", uid);
	qq_send_cmd(gc, QQ_CMD_ADD_BUDDY_WO_AUTH, (guint8 *) uid_str, strlen(uid_str));

	/* must be set after sending packet to get the correct send_seq */
	req = g_new0(qq_add_buddy_request, 1);
	req->seq = qd->send_seq;
	req->uid = uid;
	qd->add_buddy_request = g_list_append(qd->add_buddy_request, req);
}

/* this buddy needs authentication, text conversion is done at lowest level */
static void _qq_send_packet_buddy_auth(PurpleConnection *gc, guint32 uid, const gchar response, const gchar *text)
{
	gchar *text_qq, uid_str[11];
	guint8 bar, *raw_data;
	gint bytes = 0;

	g_return_if_fail(uid != 0);

	g_snprintf(uid_str, sizeof(uid_str), "%d", uid);
	bar = 0x1f;
	raw_data = g_newa(guint8, QQ_MSG_IM_MAX);

	bytes += qq_putdata(raw_data + bytes, (guint8 *) uid_str, strlen(uid_str));
	bytes += qq_put8(raw_data + bytes, bar);
	bytes += qq_put8(raw_data + bytes, response);

	if (text != NULL) {
		text_qq = utf8_to_qq(text, QQ_CHARSET_DEFAULT);
		bytes += qq_put8(raw_data + bytes, bar);
		bytes += qq_putdata(raw_data + bytes, (guint8 *) text_qq, strlen(text_qq));
		g_free(text_qq);
	}

	qq_send_cmd(gc, QQ_CMD_BUDDY_AUTH, raw_data, bytes);
}

static void _qq_send_packet_add_buddy_auth_with_gc_and_uid(gc_and_uid *g, const gchar *text)
{
	PurpleConnection *gc;
	guint32 uid;
	g_return_if_fail(g != NULL);

	gc = g->gc;
	uid = g->uid;
	g_return_if_fail(uid != 0);

	_qq_send_packet_buddy_auth(gc, uid, QQ_MY_AUTH_REQUEST, text);
	g_free(g);
}

/* the real packet to reject and request is sent from here */
static void _qq_reject_add_request_real(gc_and_uid *g, const gchar *reason)
{
	gint uid;
	PurpleConnection *gc;

	g_return_if_fail(g != NULL);

	gc = g->gc;
	uid = g->uid;
	g_return_if_fail(uid != 0);

	_qq_send_packet_buddy_auth(gc, uid, QQ_MY_AUTH_REJECT, reason);
	g_free(g);
}

/* we approve other's request of adding me as friend */
void qq_approve_add_request_with_gc_and_uid(gc_and_uid *g)
{
	gint uid;
	PurpleConnection *gc;

	g_return_if_fail(g != NULL);

	gc = g->gc;
	uid = g->uid;
	g_return_if_fail(uid != 0);

	_qq_send_packet_buddy_auth(gc, uid, QQ_MY_AUTH_APPROVE, NULL);
	g_free(g);
}

void qq_do_nothing_with_gc_and_uid(gc_and_uid *g, const gchar *msg)
{
	g_free(g);
}

/* we reject other's request of adding me as friend */
void qq_reject_add_request_with_gc_and_uid(gc_and_uid *g)
{
	gint uid;
	gchar *msg1, *msg2;
	PurpleConnection *gc;
	gc_and_uid *g2;
	gchar *nombre;

	g_return_if_fail(g != NULL);

	gc = g->gc;
	uid = g->uid;
	g_return_if_fail(uid != 0);

	g_free(g);

	g2 = g_new0(gc_and_uid, 1);
	g2->gc = gc;
	g2->uid = uid;

	msg1 = g_strdup_printf(_("You rejected %d's request"), uid);
	msg2 = g_strdup(_("Message:"));

	nombre = uid_to_purple_name(uid);
	purple_request_input(gc, _("Reject request"), msg1, msg2,
			_("Sorry, you are not my style..."), TRUE, FALSE,
			NULL, _("Reject"), G_CALLBACK(_qq_reject_add_request_real), _("Cancel"), NULL,
			purple_connection_get_account(gc), nombre, NULL,
			g2);
	g_free(nombre);
}

void qq_add_buddy_with_gc_and_uid(gc_and_uid *g)
{
	gint uid;
	PurpleConnection *gc;

	g_return_if_fail(g != NULL);

	gc = g->gc;
	uid = g->uid;
	g_return_if_fail(uid != 0);

	_qq_send_packet_add_buddy(gc, uid);
	g_free(g);
}

void qq_block_buddy_with_gc_and_uid(gc_and_uid *g)
{
	guint32 uid;
	PurpleConnection *gc;
	PurpleBuddy buddy;
	PurpleGroup group;

	g_return_if_fail(g != NULL);

	gc = g->gc;
	uid = g->uid;
	g_return_if_fail(uid > 0);

	/* XXX: This looks very wrong */
	buddy.name = uid_to_purple_name(uid);
	group.name = PURPLE_GROUP_QQ_BLOCKED;

	qq_remove_buddy(gc, &buddy, &group);
	_qq_send_packet_remove_self_from(gc, uid);
}

/*  process reply to add_buddy_auth request */
void qq_process_add_buddy_auth_reply(guint8 *data, gint data_len, PurpleConnection *gc)
{
	qq_data *qd;
	gchar **segments, *msg_utf8;

	g_return_if_fail(data != NULL && data_len != 0);

	qd = (qq_data *) gc->proto_data;

	if (data[0] != QQ_ADD_BUDDY_AUTH_REPLY_OK) {
		purple_debug_warning("QQ", "Add buddy with auth request failed\n");
		if (NULL == (segments = split_data(data, data_len, "\x1f", 2))) {
			return;
		}
		msg_utf8 = qq_to_utf8(segments[1], QQ_CHARSET_DEFAULT);
		purple_notify_error(gc, NULL, _("Add buddy with auth request failed"), msg_utf8);
		g_free(msg_utf8);
	} else {
		purple_debug_info("QQ", "Add buddy with auth request OK\n");
	}
}

/* process the server reply for my request to remove a buddy */
void qq_process_remove_buddy_reply(guint8 *data, gint data_len, PurpleConnection *gc)
{
	qq_data *qd;

	g_return_if_fail(data != NULL && data_len != 0);

	qd = (qq_data *) gc->proto_data;

	if (data[0] != QQ_REMOVE_BUDDY_REPLY_OK) {
		/* there is no reason return from server */
		purple_debug_warning("QQ", "Remove buddy fails\n");
		purple_notify_info(gc, _("QQ Buddy"), _("Failed:"),  _("Remove buddy"));
	} else {		/* if reply */
		purple_debug_info("QQ", "Remove buddy OK\n");
		/* TODO: We don't really need to notify the user about this, do we? */
		purple_notify_info(gc, _("QQ Buddy"), _("Successed:"),  _("Remove buddy"));
	}
}

/* process the server reply for my request to remove myself from a buddy */
void qq_process_remove_self_reply(guint8 *data, gint data_len, PurpleConnection *gc)
{
	qq_data *qd;

	g_return_if_fail(data != NULL && data_len != 0);

	qd = (qq_data *) gc->proto_data;

	if (data[0] != QQ_REMOVE_SELF_REPLY_OK) {
		/* there is no reason return from server */
		purple_debug_warning("QQ", "Remove self fails\n");
		purple_notify_info(gc, _("QQ Buddy"), _("Failed:"), _("Remove from other's buddy list"));
	} else {		/* if reply */
		purple_debug_info("QQ", "Remove from a buddy OK\n");
		/* TODO: Does the user really need to be notified about this? */
		purple_notify_info(gc, _("QQ Buddy"), _("Successed:"), _("Remove from other's buddy list"));
	}
}

void qq_process_add_buddy_reply(guint8 *data, gint data_len, guint16 seq, PurpleConnection *gc)
{
	qq_data *qd;
	gint for_uid;
	gchar *msg, **segments, *uid, *reply;
	GList *list;
	PurpleBuddy *b;
	gc_and_uid *g;
	qq_add_buddy_request *req;
	gchar *nombre;

	g_return_if_fail(data != NULL && data_len != 0);

	for_uid = 0;
	qd = (qq_data *) gc->proto_data;

	list = qd->add_buddy_request;
	while (list != NULL) {
		req = (qq_add_buddy_request *) list->data;
		if (req->seq == seq) {	/* reply to this */
			for_uid = req->uid;
			qd->add_buddy_request = g_list_remove(qd->add_buddy_request, qd->add_buddy_request->data);
			g_free(req);
			break;
		}
		list = list->next;
	}

	if (for_uid == 0) {	/* we have no record for this */
		purple_debug_error("QQ", "We have no record for add buddy reply [%d], discard\n", seq);
		return;
	} else {
		purple_debug_info("QQ", "Add buddy reply [%d] is for id [%d]\n", seq, for_uid);
	}

	if (NULL == (segments = split_data(data, data_len, "\x1f", 2)))
		return;

	uid = segments[0];
	reply = segments[1];
	if (strtol(uid, NULL, 10) != qd->uid) {	/* should not happen */
		purple_debug_error("QQ", "Add buddy reply is to [%s], not me!", uid);
		g_strfreev(segments);
		return;
	}

	if (strtol(reply, NULL, 10) > 0) {	/* need auth */
		purple_debug_warning("QQ", "Add buddy attempt fails, need authentication\n");
		nombre = uid_to_purple_name(for_uid);
		b = purple_find_buddy(gc->account, nombre);
		if (b != NULL)
			purple_blist_remove_buddy(b);
		g = g_new0(gc_and_uid, 1);
		g->gc = gc;
		g->uid = for_uid;
		msg = g_strdup_printf(_("%d needs authentication"), for_uid);
		purple_request_input(gc, NULL, msg,
				_("Input request here"), /* TODO: Awkward string to fix post string freeze - standardize auth dialogues? -evands */
				_("Would you be my friend?"),
				TRUE, FALSE, NULL, _("Send"),
				G_CALLBACK
				(_qq_send_packet_add_buddy_auth_with_gc_and_uid),
				_("Cancel"), G_CALLBACK(qq_do_nothing_with_gc_and_uid),
				purple_connection_get_account(gc), nombre, NULL,
				g);
		g_free(msg);
		g_free(nombre);
	} else {	/* add OK */
		qq_add_buddy_by_recv_packet(gc, for_uid, TRUE, TRUE);
		msg = g_strdup_printf(_("Add into %d's buddy list"), for_uid);
		purple_notify_info(gc, _("QQ Buddy"), _("Successed:"), msg);
		g_free(msg);
	}
	g_strfreev(segments);
}

PurpleGroup *qq_get_purple_group(const gchar *group_name)
{
	PurpleGroup *g;

	g_return_val_if_fail(group_name != NULL, NULL);

	g = purple_find_group(group_name);
	if (g == NULL) {
		g = purple_group_new(group_name);
		purple_blist_add_group(g, NULL);
		purple_debug_warning("QQ", "Add new group: %s\n", group_name);
	}

	return g;
}

/* we add new buddy, if the received packet is from someone not in my list
 * return the PurpleBuddy that is just created */
PurpleBuddy *qq_add_buddy_by_recv_packet(PurpleConnection *gc, guint32 uid, gboolean is_known, gboolean create)
{
	PurpleAccount *a;
	PurpleBuddy *b;
	PurpleGroup *g;
	qq_data *qd;
	qq_buddy *q_bud;
	gchar *name, *group_name;

	a = gc->account;
	qd = (qq_data *) gc->proto_data;
	g_return_val_if_fail(a != NULL && uid != 0, NULL);

	group_name = is_known ?
		g_strdup_printf(PURPLE_GROUP_QQ_FORMAT, purple_account_get_username(a)) : g_strdup(PURPLE_GROUP_QQ_UNKNOWN);

	g = qq_get_purple_group(group_name);

	name = uid_to_purple_name(uid);
	b = purple_find_buddy(gc->account, name);
	/* remove old, we can not simply return here
	 * because there might be old local copy of this buddy */
	if (b != NULL)
		purple_blist_remove_buddy(b);

	b = purple_buddy_new(a, name, NULL);

	if (!create)
		b->proto_data = NULL;
	else {
		q_bud = g_new0(qq_buddy, 1);
		q_bud->uid = uid;
		b->proto_data = q_bud;
		qd->buddies = g_list_append(qd->buddies, q_bud);
		qq_send_packet_get_info(gc, q_bud->uid, FALSE);
		qq_request_get_buddies_online(gc, 0, 0);
	}

	purple_blist_add_buddy(b, NULL, g, NULL);
	purple_debug_warning("QQ", "Add new buddy: [%s]\n", name);

	g_free(name);
	g_free(group_name);

	return b;
}

/* add a buddy and send packet to QQ server
 * note that when purple load local cached buddy list into its blist
 * it also calls this funtion, so we have to
 * define qd->is_login=TRUE AFTER serv_finish_login(gc) */
void qq_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	qq_data *qd;
	guint32 uid;
	PurpleBuddy *b;
	const char *bname;

	qd = (qq_data *) gc->proto_data;
	if (!qd->is_login)
		return;		/* IMPORTANT ! */

	bname = purple_buddy_get_name(buddy);
	uid = purple_name_to_uid(bname);
	if (uid > 0)
		_qq_send_packet_add_buddy(gc, uid);
	else {
		b = purple_find_buddy(gc->account, bname);
		if (b != NULL)
			purple_blist_remove_buddy(b);
		purple_notify_error(gc, NULL,
				_("QQ Number Error"),
				_("Invalid QQ Number"));
	}
}

/* remove a buddy and send packet to QQ server accordingly */
void qq_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	qq_data *qd;
	PurpleBuddy *b;
	qq_buddy *q_bud;
	guint32 uid;
	const char *bname;

	qd = (qq_data *) gc->proto_data;
	bname = purple_buddy_get_name(buddy);
	uid = purple_name_to_uid(bname);

	if (!qd->is_login)
		return;

	if (uid > 0)
		_qq_send_packet_remove_buddy(gc, uid);

	b = purple_find_buddy(gc->account, bname);
	if (b != NULL) {
		q_bud = (qq_buddy *) b->proto_data;
		if (q_bud != NULL)
			qd->buddies = g_list_remove(qd->buddies, q_bud);
		else
			purple_debug_warning("QQ", "We have no qq_buddy record for %s\n", bname);
		/* remove buddy on blist, this does not trigger qq_remove_buddy again
		 * do this only if the request comes from block request,
		 * otherwise purple segmentation fault */
		if (g_ascii_strcasecmp(purple_group_get_name(group), PURPLE_GROUP_QQ_BLOCKED) == 0)
			purple_blist_remove_buddy(b);
	}
}

/* free add buddy request queue */
void qq_add_buddy_request_free(qq_data *qd)
{
	gint count;
	qq_add_buddy_request *p;

	count = 0;
	while (qd->add_buddy_request != NULL) {
		p = (qq_add_buddy_request *) (qd->add_buddy_request->data);
		qd->add_buddy_request = g_list_remove(qd->add_buddy_request, p);
		g_free(p);
		count++;
	}
	if (count > 0) {
		purple_debug_info("QQ", "%d add buddy requests are freed!\n", count);
	}
}

/* free up all qq_buddy */
void qq_buddies_list_free(PurpleAccount *account, qq_data *qd)
{
	gint count;
	qq_buddy *p;
	gchar *name;
	PurpleBuddy *b;

	count = 0;
	while (qd->buddies) {
		p = (qq_buddy *) (qd->buddies->data);
		qd->buddies = g_list_remove(qd->buddies, p);
		name = uid_to_purple_name(p->uid);
		b = purple_find_buddy(account, name);
		if(b != NULL)
			b->proto_data = NULL;
		else
			purple_debug_info("QQ", "qq_buddy %s not found in purple proto_data\n", name);
		g_free(name);

		g_free(p);
		count++;
	}
	if (count > 0) {
		purple_debug_info("QQ", "%d qq_buddy structures are freed!\n", count);
	}
}

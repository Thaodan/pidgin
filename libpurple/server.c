/*
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
 *
 */

/* This file is the fullcrap */

#include <glib/gi18n-lib.h>

#include "buddylist.h"
#include "debug.h"
#include "notify.h"
#include "prefs.h"
#include "purpleconversation.h"
#include "purpleconversationmanager.h"
#include "purpleprivate.h"
#include "purpleprotocol.h"
#include "purpleprotocolchat.h"
#include "purpleprotocolim.h"
#include "purpleprotocolprivacy.h"
#include "purpleprotocolserver.h"
#include "request.h"
#include "signals.h"
#include "server.h"
#include "status.h"
#include "util.h"
#include "xfer.h"

#define SECS_BEFORE_RESENDING_AUTORESPONSE 600
#define SEX_BEFORE_RESENDING_AUTORESPONSE "Only after you're married"

unsigned int
purple_serv_send_typing(PurpleConnection *gc, const char *name, PurpleIMTypingState state)
{
	if(gc) {
		PurpleProtocol *protocol = purple_connection_get_protocol(gc);
		PurpleProtocolIM *im = PURPLE_PROTOCOL_IM(protocol);

		return purple_protocol_im_send_typing(im, gc, name, state);
	}

	return 0;
}

static GSList *last_auto_responses = NULL;
struct last_auto_response {
	PurpleConnection *gc;
	char name[80];
	time_t sent;
};

static gboolean
expire_last_auto_responses(gpointer data)
{
	GSList *tmp, *cur;
	struct last_auto_response *lar;

	tmp = last_auto_responses;

	while (tmp) {
		cur = tmp;
		tmp = tmp->next;
		lar = (struct last_auto_response *)cur->data;

		if ((time(NULL) - lar->sent) > SECS_BEFORE_RESENDING_AUTORESPONSE) {
			last_auto_responses = g_slist_delete_link(last_auto_responses, cur);
			g_free(lar);
		}
	}

	return FALSE; /* do not run again */
}

static struct last_auto_response *
get_last_auto_response(PurpleConnection *gc, const char *name)
{
	GSList *tmp;
	struct last_auto_response *lar;

	/* because we're modifying or creating a lar, schedule the
	 * function to expire them as the pref dictates */
	g_timeout_add_seconds((SECS_BEFORE_RESENDING_AUTORESPONSE + 1), expire_last_auto_responses, NULL);

	tmp = last_auto_responses;

	while (tmp) {
		lar = (struct last_auto_response *)tmp->data;

		if (gc == lar->gc && !strncmp(name, lar->name, sizeof(lar->name)))
			return lar;

		tmp = tmp->next;
	}

	lar = g_new0(struct last_auto_response, 1);
	g_snprintf(lar->name, sizeof(lar->name), "%s", name);
	lar->gc = gc;
	lar->sent = 0;
	last_auto_responses = g_slist_prepend(last_auto_responses, lar);

	return lar;
}

int purple_serv_send_im(PurpleConnection *gc, PurpleMessage *msg)
{
	PurpleAccount *account = NULL;
	PurpleConversation *im = NULL;
	PurpleConversationManager *manager = NULL;
	PurplePresence *presence = NULL;
	PurpleProtocol *protocol = NULL;
	int val = -EINVAL;
	const gchar *auto_reply_pref = NULL;
	const gchar *recipient;

	g_return_val_if_fail(gc != NULL, val);
	g_return_val_if_fail(msg != NULL, val);

	protocol = purple_connection_get_protocol(gc);

	g_return_val_if_fail(protocol != NULL, val);
	g_return_val_if_fail(PURPLE_IS_PROTOCOL_IM(protocol), val);

	account  = purple_connection_get_account(gc);
	presence = purple_account_get_presence(account);
	recipient = purple_message_get_recipient(msg);

	manager = purple_conversation_manager_get_default();
	im = purple_conversation_manager_find_im(manager, account, recipient);

	/* we probably shouldn't be here if the protocol doesn't know how to send
	 * im's... but there was a similar check here before so I just reproduced
	 * it until we can reevaluate this function.
	 */
	if(PURPLE_IS_PROTOCOL_IM(protocol)) {
		PurpleProtocolIM *pim = PURPLE_PROTOCOL_IM(protocol);

		val = purple_protocol_im_send(pim, gc, msg);
	}

	/*
	 * XXX - If "only auto-reply when away & idle" is set, then shouldn't
	 * this only reset lar->sent if we're away AND idle?
	 */
	auto_reply_pref = purple_prefs_get_string("/purple/away/auto_reply");
	if((purple_connection_get_flags(gc) & PURPLE_CONNECTION_FLAG_AUTO_RESP) &&
			!purple_presence_is_available(presence) &&
			!purple_strequal(auto_reply_pref, "never")) {

		struct last_auto_response *lar;
		lar = get_last_auto_response(gc, recipient);
		lar->sent = time(NULL);
	}

	if(im && purple_im_conversation_get_send_typed_timeout(PURPLE_IM_CONVERSATION(im)))
		purple_im_conversation_stop_send_typed_timeout(PURPLE_IM_CONVERSATION(im));

	return val;
}

void purple_serv_get_info(PurpleConnection *gc, const char *name)
{
	PurpleProtocol *protocol;

	if (gc) {
		protocol = purple_connection_get_protocol(gc);
		purple_protocol_server_get_info(PURPLE_PROTOCOL_SERVER(protocol), gc,
		                                name);
	}
}

void purple_serv_set_info(PurpleConnection *gc, const char *info)
{
	PurpleProtocol *protocol;
	PurpleAccount *account;

	if (gc) {
		protocol = purple_connection_get_protocol(gc);

		if (PURPLE_PROTOCOL_IMPLEMENTS(protocol, SERVER, set_info)) {
			account = purple_connection_get_account(gc);

			purple_signal_emit(purple_accounts_get_handle(),
					"account-setting-info", account, info);

			purple_protocol_server_set_info(PURPLE_PROTOCOL_SERVER(protocol),
			                                gc, info);

			purple_signal_emit(purple_accounts_get_handle(),
					"account-set-info", account, info);
		}
	}
}

/*
 * Set buddy's alias on server roster/list
 */
void purple_serv_alias_buddy(PurpleBuddy *b)
{
	PurpleAccount *account;
	PurpleConnection *gc;
	PurpleProtocol *protocol;

	if (b) {
		account = purple_buddy_get_account(b);

		if (account) {
			gc = purple_account_get_connection(account);

			if(gc) {
				protocol = purple_connection_get_protocol(gc);
				purple_protocol_server_alias_buddy(PURPLE_PROTOCOL_SERVER(protocol),
				                                   gc,
				                                   purple_buddy_get_name(b),
				                                   purple_buddy_get_local_alias(b));
			}
		}
	}
}

void
purple_serv_got_alias(PurpleConnection *gc, const char *who, const char *alias)
{
	PurpleAccount *account;
	PurpleBuddy *b;
	PurpleConversation *im;
	PurpleConversationManager *manager;
	GSList *buddies;

	account = purple_connection_get_account(gc);
	buddies = purple_blist_find_buddies(account, who);

	manager = purple_conversation_manager_get_default();

	while (buddies != NULL)
	{
		const char *server_alias;

		b = buddies->data;
		buddies = g_slist_delete_link(buddies, buddies);

		server_alias = purple_buddy_get_server_alias(b);

		if (purple_strequal(server_alias, alias))
			continue;

		purple_buddy_set_server_alias(b, alias);

		im = purple_conversation_manager_find_im(manager, account,
		                                         purple_buddy_get_name(b));
		if (im != NULL && alias != NULL && !purple_strequal(alias, who))
		{
			char *escaped = g_markup_escape_text(who, -1);
			char *escaped2 = g_markup_escape_text(alias, -1);
			char *tmp = g_strdup_printf(_("%s is now known as %s.\n"),
										escaped, escaped2);

			purple_conversation_write_system_message(
				im, tmp,
				PURPLE_MESSAGE_NO_LINKIFY);

			g_free(tmp);
			g_free(escaped2);
			g_free(escaped);
		}
	}
}

void
purple_serv_got_private_alias(PurpleConnection *gc, const char *who, const char *alias)
{
	PurpleAccount *account = NULL;
	GSList *buddies = NULL;
	PurpleBuddy *b = NULL;

	account = purple_connection_get_account(gc);
	buddies = purple_blist_find_buddies(account, who);

	while(buddies != NULL) {
		const char *balias;
		b = buddies->data;

		buddies = g_slist_delete_link(buddies, buddies);

		balias = purple_buddy_get_local_alias(b);
		if (purple_strequal(balias, alias))
			continue;

		purple_buddy_set_local_alias(b, alias);
	}
}

/*
 * Move a buddy from one group to another on server.
 *
 * Note: For now we'll not deal with changing gc's at the same time, but
 * it should be possible.  Probably needs to be done, someday.  Although,
 * the UI for that would be difficult, because groups are Purple-wide.
 */
void purple_serv_move_buddy(PurpleBuddy *buddy, PurpleGroup *orig, PurpleGroup *dest)
{
	PurpleAccount *account;
	PurpleConnection *gc;
	PurpleProtocol *protocol;

	g_return_if_fail(buddy != NULL);
	g_return_if_fail(orig != NULL);
	g_return_if_fail(dest != NULL);

	account = purple_buddy_get_account(buddy);
	gc = purple_account_get_connection(account);

	if (gc) {
		protocol = purple_connection_get_protocol(gc);
		purple_protocol_server_group_buddy(PURPLE_PROTOCOL_SERVER(protocol),
		                                   gc, purple_buddy_get_name(buddy),
		                                   purple_group_get_name(orig),
		                                   purple_group_get_name(dest));
	}
}

void purple_serv_add_permit(PurpleConnection *gc, const char *name)
{
	if (gc) {
		PurpleProtocol *protocol = purple_connection_get_protocol(gc);
		PurpleProtocolPrivacy *privacy = PURPLE_PROTOCOL_PRIVACY(protocol);

		purple_protocol_privacy_add_permit(privacy, gc, name);
	}
}

void purple_serv_add_deny(PurpleConnection *gc, const char *name)
{
	if (gc) {
		PurpleProtocol *protocol = purple_connection_get_protocol(gc);
		PurpleProtocolPrivacy *privacy = PURPLE_PROTOCOL_PRIVACY(protocol);

		purple_protocol_privacy_add_deny(privacy, gc, name);
	}
}

void purple_serv_remove_permit(PurpleConnection *gc, const char *name)
{
	if (gc) {
		PurpleProtocol *protocol = purple_connection_get_protocol(gc);
		PurpleProtocolPrivacy *privacy = PURPLE_PROTOCOL_PRIVACY(protocol);

		purple_protocol_privacy_remove_permit(privacy, gc, name);
	}
}

void purple_serv_remove_deny(PurpleConnection *gc, const char *name)
{
	if (gc) {
		PurpleProtocol *protocol = purple_connection_get_protocol(gc);
		PurpleProtocolPrivacy *privacy = PURPLE_PROTOCOL_PRIVACY(protocol);

		purple_protocol_privacy_remove_deny(privacy, gc, name);
	}
}

void
purple_serv_set_permit_deny(PurpleConnection *gc) {
	if(gc) {
		PurpleProtocol *protocol = purple_connection_get_protocol(gc);

		if(PURPLE_IS_PROTOCOL_PRIVACY(protocol)) {
			PurpleProtocolPrivacy *privacy = PURPLE_PROTOCOL_PRIVACY(protocol);

			/*
			 * this is called when either you import a buddy list, and make lots
			 * of changes that way, or when the user toggles the permit/deny mode
			 * in the prefs. In either case you should probably be resetting and
			 * resending the permit/deny info when you get this.
			 */
			purple_protocol_privacy_set_permit_deny(privacy, gc);
		}
	}
}

void purple_serv_join_chat(PurpleConnection *gc, GHashTable *data)
{
	PurpleProtocol *protocol;

	if (gc) {
		protocol = purple_connection_get_protocol(gc);
		purple_protocol_chat_join(PURPLE_PROTOCOL_CHAT(protocol), gc, data);
	}
}


void purple_serv_reject_chat(PurpleConnection *gc, GHashTable *data)
{
	PurpleProtocol *protocol;

	if (gc) {
		protocol = purple_connection_get_protocol(gc);
		purple_protocol_chat_reject(PURPLE_PROTOCOL_CHAT(protocol), gc, data);
	}
}

void purple_serv_chat_invite(PurpleConnection *gc, int id, const char *message, const char *name)
{
	PurpleAccount *account;
	PurpleConversation *chat;
	PurpleConversationManager *manager;
	PurpleProtocol *protocol = NULL;
	char *buffy;

	account = purple_connection_get_account(gc);
	manager = purple_conversation_manager_get_default();
	chat = purple_conversation_manager_find_chat_by_id(manager, account, id);

	if(chat == NULL)
		return;

	if(gc)
		protocol = purple_connection_get_protocol(gc);

	buffy = message && *message ? g_strdup(message) : NULL;
	purple_signal_emit(purple_conversations_get_handle(), "chat-inviting-user",
					 chat, name, &buffy);

	if(protocol) {
		purple_protocol_chat_invite(PURPLE_PROTOCOL_CHAT(protocol), gc, id,
		                            buffy, name);
	}

	purple_signal_emit(purple_conversations_get_handle(), "chat-invited-user",
					 chat, name, buffy);

	g_free(buffy);
}

/* Ya know, nothing uses this except purple_chat_conversation_finalize(),
 * I think I'll just merge it into that later...
 * Then again, something might want to use this, from outside protocol-land
 * to leave a chat without destroying the conversation.
 */
void purple_serv_chat_leave(PurpleConnection *gc, int id)
{
	PurpleProtocol *protocol;

	protocol = purple_connection_get_protocol(gc);
	purple_protocol_chat_leave(PURPLE_PROTOCOL_CHAT(protocol), gc, id);
}

int purple_serv_chat_send(PurpleConnection *gc, int id, PurpleMessage *msg)
{
	PurpleProtocol *protocol;
	protocol = purple_connection_get_protocol(gc);

	g_return_val_if_fail(msg != NULL, -EINVAL);

	if (PURPLE_PROTOCOL_IMPLEMENTS(protocol, CHAT, send)) {
		return purple_protocol_chat_send(PURPLE_PROTOCOL_CHAT(protocol), gc,
		                                 id, msg);
	}

	return -EINVAL;
}

/*
 * woo. i'm actually going to comment this function. isn't that fun. make
 * sure to follow along, kids
 */
void purple_serv_got_im(PurpleConnection *gc, const char *who, const char *msg,
				 PurpleMessageFlags flags, time_t mtime)
{
	PurpleAccount *account;
	PurpleConversation *im;
	PurpleConversationManager *manager;
	char *message, *name;
	char *angel, *buffy;
	int plugin_return;
	PurpleMessage *pmsg;

	g_return_if_fail(msg != NULL);

	account = purple_connection_get_account(gc);

	if (mtime < 0) {
		purple_debug_error("server",
				"purple_serv_got_im ignoring negative timestamp\n");
		/* TODO: Would be more appropriate to use a value that indicates
		   that the timestamp is unknown, and surface that in the UI. */
		mtime = time(NULL);
	}

	/*
	 * XXX: Should we be setting this here, or relying on protocols to set it?
	 */
	flags |= PURPLE_MESSAGE_RECV;

	if (!purple_account_privacy_check(account, who)) {
		purple_signal_emit(purple_conversations_get_handle(), "blocked-im-msg",
				account, who, msg, flags, (unsigned int)mtime);
		return;
	}

	manager = purple_conversation_manager_get_default();

	/*
	 * We should update the conversation window buttons and menu,
	 * if it exists.
	 */
	im = purple_conversation_manager_find_im(manager, account, who);

	/*
	 * Make copies of the message and the sender in case plugins want
	 * to free these strings and replace them with a modified version.
	 */
	buffy = g_strdup(msg);
	angel = g_strdup(who);

	plugin_return = GPOINTER_TO_INT(
		purple_signal_emit_return_1(purple_conversations_get_handle(),
								  "receiving-im-msg", account,
								  &angel, &buffy, im, &flags));

	if (!buffy || !angel || plugin_return) {
		g_free(buffy);
		g_free(angel);
		return;
	}

	name = angel;
	message = buffy;

	purple_signal_emit(purple_conversations_get_handle(), "received-im-msg",
	                   account, name, message, im, flags);

	/* search for conversation again in case it was created by received-im-msg handler */
	if(im == NULL) {
		im = purple_conversation_manager_find_im(manager, account, name);
	}

	if(im == NULL) {
		im = purple_im_conversation_new(account, name);
	}

	pmsg = purple_message_new_incoming(name, message, flags, mtime);
	purple_conversation_write_message(im, pmsg);
	g_free(message);
	g_object_unref(G_OBJECT(pmsg));

	/*
	 * Don't autorespond if:
	 *
	 *  - it's not supported on this connection
	 *  - we are available
	 *  - or it's disabled
	 *  - or we're not idle and the 'only auto respond if idle' pref
	 *    is set
	 */
	if (purple_connection_get_flags(gc) & PURPLE_CONNECTION_FLAG_AUTO_RESP)
	{
		PurplePresence *presence;
		PurpleStatus *status;
		PurpleStatusType *status_type;
		PurpleStatusPrimitive primitive;
		const gchar *auto_reply_pref;
		const char *away_msg = NULL;
		gboolean mobile = FALSE;

		auto_reply_pref = purple_prefs_get_string("/purple/away/auto_reply");

		presence = purple_account_get_presence(account);
		status = purple_presence_get_active_status(presence);
		status_type = purple_status_get_status_type(status);
		primitive = purple_status_type_get_primitive(status_type);
		mobile = purple_presence_is_status_primitive_active(presence, PURPLE_STATUS_MOBILE);
		if ((primitive == PURPLE_STATUS_AVAILABLE) ||
			(primitive == PURPLE_STATUS_INVISIBLE) ||
			mobile ||
		    purple_strequal(auto_reply_pref, "never") ||
		    (!purple_presence_is_idle(presence) && purple_strequal(auto_reply_pref, "awayidle")))
		{
			g_free(name);
			return;
		}

		away_msg = g_value_get_string(
			purple_status_get_attr_value(status, "message"));

		if ((away_msg != NULL) && (*away_msg != '\0')) {
			struct last_auto_response *lar;
			time_t now = time(NULL);

			/*
			 * This used to be based on the conversation window. But um, if
			 * you went away, and someone sent you a message and got your
			 * auto-response, and then you closed the window, and then they
			 * sent you another one, they'd get the auto-response back too
			 * soon. Besides that, we need to keep track of this even if we've
			 * got a queue. So the rest of this block is just the auto-response,
			 * if necessary.
			 */
			lar = get_last_auto_response(gc, name);
			if ((now - lar->sent) >= SECS_BEFORE_RESENDING_AUTORESPONSE)
			{
				/*
				 * We don't want to send an autoresponse in response to the other user's
				 * autoresponse.  We do, however, not want to then send one in response to the
				 * _next_ message, so we still set lar->sent to now.
				 */
				lar->sent = now;

				if (!(flags & PURPLE_MESSAGE_AUTO_RESP))
				{
					PurpleMessage *msg;
					const gchar *me = purple_account_get_name_for_display(account);

					msg = purple_message_new_outgoing(me, name,
						away_msg, PURPLE_MESSAGE_AUTO_RESP);

					purple_serv_send_im(gc, msg);
					purple_conversation_write_message(PURPLE_CONVERSATION(im), msg);

					g_object_unref(G_OBJECT(msg));
				}
			}
		}
	}

	g_free(name);
}

void
purple_serv_got_typing(PurpleConnection *gc, const char *name, int timeout,
                       PurpleIMTypingState state)
{
	PurpleAccount *account;
	PurpleConversation *conv;
	PurpleConversationManager *manager;

	account = purple_connection_get_account(gc);

	manager = purple_conversation_manager_get_default();
	conv = purple_conversation_manager_find_im(manager, account, name);
	if(PURPLE_IS_IM_CONVERSATION(conv)) {
		PurpleIMConversation *im = PURPLE_IM_CONVERSATION(conv);

		purple_im_conversation_set_typing_state(im, state);

		if(timeout > 0) {
			purple_im_conversation_start_typing_timeout(im, timeout);
		}
	} else {
		switch (state)
		{
			case PURPLE_IM_TYPING:
				purple_signal_emit(purple_conversations_get_handle(),
								   "buddy-typing", account, name);
				break;
			case PURPLE_IM_TYPED:
				purple_signal_emit(purple_conversations_get_handle(),
								   "buddy-typed", account, name);
				break;
			case PURPLE_IM_NOT_TYPING:
				purple_signal_emit(purple_conversations_get_handle(),
								   "buddy-typing-stopped", account, name);
				break;
		}
	}
}

void
purple_serv_got_typing_stopped(PurpleConnection *gc, const char *name) {
	PurpleAccount *account;
	PurpleConversation *conv;
	PurpleConversationManager *manager;

	account = purple_connection_get_account(gc);

	manager = purple_conversation_manager_get_default();
	conv = purple_conversation_manager_find_im(manager, account, name);
	if(conv != NULL) {
		PurpleIMConversation *im = PURPLE_IM_CONVERSATION(conv);
		if(purple_im_conversation_get_typing_state(im) == PURPLE_IM_NOT_TYPING) {
			return;
		}

		purple_im_conversation_stop_typing_timeout(im);
		purple_im_conversation_set_typing_state(im, PURPLE_IM_NOT_TYPING);
	}
	else
	{
		purple_signal_emit(purple_conversations_get_handle(),
		                   "buddy-typing-stopped", account, name);
	}
}

struct chat_invite_data {
	PurpleConnection *gc;
	GHashTable *components;
};

static void chat_invite_data_free(struct chat_invite_data *cid)
{
	if (cid->components)
		g_hash_table_destroy(cid->components);
	g_free(cid);
}


static void chat_invite_reject(struct chat_invite_data *cid)
{
	purple_serv_reject_chat(cid->gc, cid->components);
	chat_invite_data_free(cid);
}


static void chat_invite_accept(struct chat_invite_data *cid)
{
	purple_serv_join_chat(cid->gc, cid->components);
	chat_invite_data_free(cid);
}



void purple_serv_got_chat_invite(PurpleConnection *gc, const char *name,
						  const char *who, const char *message, GHashTable *data)
{
	PurpleAccount *account;
	struct chat_invite_data *cid;
	int plugin_return;

	g_return_if_fail(name != NULL);
	g_return_if_fail(who != NULL);

	account = purple_connection_get_account(gc);
	if (!purple_account_privacy_check(account, who)) {
		purple_signal_emit(purple_conversations_get_handle(), "chat-invite-blocked",
				account, who, name, message, data);
		return;
	}

	cid = g_new0(struct chat_invite_data, 1);

	plugin_return = GPOINTER_TO_INT(purple_signal_emit_return_1(
					purple_conversations_get_handle(),
					"chat-invited", account, who, name, message, data));

	cid->gc = gc;
	cid->components = data;

	if (plugin_return == 0)
	{
		char *buf2;

		if (message != NULL)
		{
			buf2 = g_strdup_printf(
				   _("%s has invited %s to the chat room %s:\n%s"),
				   who, purple_account_get_username(account), name, message);
		}
		else
			buf2 = g_strdup_printf(
				   _("%s has invited %s to the chat room %s\n"),
				   who, purple_account_get_username(account), name);


		purple_request_accept_cancel(gc, NULL,
			_("Accept chat invitation?"), buf2,
			PURPLE_DEFAULT_ACTION_NONE,
			purple_request_cpar_from_connection(gc), cid,
			G_CALLBACK(chat_invite_accept),
			G_CALLBACK(chat_invite_reject));
		g_free(buf2);
	}
	else if (plugin_return > 0)
		chat_invite_accept(cid);
	else
		chat_invite_reject(cid);
}

PurpleConversation *purple_serv_got_joined_chat(PurpleConnection *gc,
											   int id, const char *name)
{
	PurpleConversation *chat;
	PurpleAccount *account;

	account = purple_connection_get_account(gc);

	g_return_val_if_fail(account != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	chat = purple_chat_conversation_new(account, name);
	g_return_val_if_fail(chat != NULL, NULL);

	if (!g_slist_find(purple_connection_get_active_chats(gc), chat))
		_purple_connection_add_active_chat(gc, PURPLE_CHAT_CONVERSATION(chat));

	purple_chat_conversation_set_id(PURPLE_CHAT_CONVERSATION(chat), id);

	purple_signal_emit(purple_conversations_get_handle(), "chat-joined", chat);

	return chat;
}

void purple_serv_got_chat_left(PurpleConnection *g, int id)
{
	GSList *bcs;
	PurpleChatConversation *chat = NULL;

	for (bcs = purple_connection_get_active_chats(g); bcs != NULL; bcs = bcs->next) {
		if (purple_chat_conversation_get_id(
				PURPLE_CHAT_CONVERSATION(bcs->data)) == id) {
			chat = (PurpleChatConversation *)bcs->data;
			break;
		}
	}

	if (!chat)
		return;

	purple_debug_info("server", "Leaving room: %s",
	                  purple_conversation_get_name(PURPLE_CONVERSATION(chat)));

	_purple_connection_remove_active_chat(g, chat);

	purple_chat_conversation_leave(chat);

	purple_signal_emit(purple_conversations_get_handle(), "chat-left", chat);
}

void purple_serv_got_join_chat_failed(PurpleConnection *gc, GHashTable *data)
{
	purple_signal_emit(purple_conversations_get_handle(), "chat-join-failed",
					gc, data);
}

void purple_serv_got_chat_in(PurpleConnection *g, int id, const char *who,
					  PurpleMessageFlags flags, const char *message, time_t mtime)
{
	GSList *bcs;
	PurpleChatConversation *chat = NULL;
	char *buffy, *angel;
	int plugin_return;
	PurpleMessage *pmsg;

	g_return_if_fail(who != NULL);
	g_return_if_fail(message != NULL);

	if (mtime < 0) {
		purple_debug_error("server",
				"purple_serv_got_chat_in ignoring negative timestamp\n");
		/* TODO: Would be more appropriate to use a value that indicates
		   that the timestamp is unknown, and surface that in the UI. */
		mtime = time(NULL);
	}

	for (bcs = purple_connection_get_active_chats(g); bcs != NULL; bcs = bcs->next) {
		if (purple_chat_conversation_get_id(
				PURPLE_CHAT_CONVERSATION(bcs->data)) == id) {
			chat = (PurpleChatConversation *)bcs->data;
			break;
		}
	}

	if (!chat)
		return;

	/* Did I send the message? */
	if (purple_strequal(purple_chat_conversation_get_nick(chat),
			purple_normalize(purple_conversation_get_account(
			PURPLE_CONVERSATION(chat)), who))) {
		flags |= PURPLE_MESSAGE_SEND;
		flags &= ~PURPLE_MESSAGE_RECV; /* Just in case some protocol sets it! */
	} else {
		flags |= PURPLE_MESSAGE_RECV;
	}

	/*
	 * Make copies of the message and the sender in case plugins want
	 * to free these strings and replace them with a modified version.
	 */
	buffy = g_strdup(message);
	angel = g_strdup(who);

	plugin_return = GPOINTER_TO_INT(
		purple_signal_emit_return_1(purple_conversations_get_handle(),
								  "receiving-chat-msg", purple_connection_get_account(g),
								  &angel, &buffy, chat, &flags));

	if (!buffy || !angel || plugin_return) {
		g_free(buffy);
		g_free(angel);
		return;
	}

	who = angel;
	message = buffy;

	purple_signal_emit(purple_conversations_get_handle(), "received-chat-msg", purple_connection_get_account(g),
					 who, message, chat, flags);

	if (flags & PURPLE_MESSAGE_RECV) {
		pmsg = purple_message_new_incoming(who, message, flags, mtime);
	} else {
		PurpleAccount *account = purple_connection_get_account(g);
		GDateTime *dt = g_date_time_new_from_unix_local((gint64)mtime);
		const gchar *me = purple_account_get_name_for_display(account);

		pmsg = purple_message_new_outgoing(me, who, message, flags);
		purple_message_set_timestamp(pmsg, dt);
		g_date_time_unref(dt);
	}
	purple_conversation_write_message(PURPLE_CONVERSATION(chat), pmsg);

	g_free(angel);
	g_free(buffy);

	g_object_unref(G_OBJECT(pmsg));
}

void purple_serv_send_file(PurpleConnection *gc, const char *who, const char *file)
{
	PurpleProtocol *protocol;

	if (gc) {
		protocol = purple_connection_get_protocol(gc);

		if(PURPLE_IS_PROTOCOL_XFER(protocol)) {
			PurpleProtocolXfer *xfer = PURPLE_PROTOCOL_XFER(protocol);

			if(purple_protocol_xfer_can_receive(xfer, gc, who)) {
				purple_protocol_xfer_send_file(xfer,
						gc, who, file);
			}
		}
	}
}

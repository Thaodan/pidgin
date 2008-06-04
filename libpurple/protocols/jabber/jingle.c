/*
 * purple - Jabber Protocol Plugin
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

#include "config.h"
#include "purple.h"
#include "jingle.h"
#include "xmlnode.h"
#include "iq.h"

#include <stdlib.h>
#include <string.h>
#include <glib.h>

#ifdef USE_VV

#include <gst/farsight/fs-candidate.h>

#define JINGLE "urn:xmpp:tmp:jingle"
#define JINGLE_AUDIO "urn:xmpp:tmp:jingle:apps:audio-rtp"
#define JINGLE_VIDEO "urn:xmpp:tmp:jingle:apps:video-rtp"
#define TRANSPORT_ICEUDP "urn:xmpp:tmp:jingle:transports:ice-udp"

typedef struct {
	char *id;
	JabberStream *js;
	PurpleMedia *media;
	char *remote_jid;
	char *initiator;
	gboolean is_initiator;
	gboolean session_started;
	GHashTable *contents;	/* JingleSessionContent table */
} JingleSession;

typedef struct {
	gchar *name;
	JingleSession *session;
	gchar *creator;
	gchar *sender;
	gchar *transport_type;
	gchar *type;
} JingleSessionContent;

static void
jabber_jingle_session_content_create_internal(JingleSession *session,
					      const gchar *name,
					      const gchar *creator,
					      const gchar *sender,
					      const gchar *transport_type,
					      const gchar *type)
{
	JingleSessionContent *content = g_new0(JingleSessionContent, 1);
	content->session = session;
	content->name = g_strdup(name);
	content->creator = g_strdup(creator);
	content->sender = g_strdup(sender);
	content->transport_type = g_strdup(transport_type);
	content->type = g_strdup(type);

	if (!session->contents) {
		purple_debug_info("jingle", "Creating hash table for contents\n");
		session->contents = g_hash_table_new(g_str_hash, g_str_equal);
	}
	purple_debug_info("jingle", "inserting content with name == \"%s\" into table\n",
			  content->name);
	g_hash_table_insert(session->contents, content->name, content);
}

static void
jabber_jingle_session_destroy_content(JingleSessionContent *content)
{
	purple_debug_info("jingle", "destroying content with name == \"%s\"\n",
			  content->name);
	g_hash_table_remove(content->session->contents, content->name);
	g_free(content->name);
	g_free(content->creator);
	g_free(content->sender);
	g_free(content->transport_type);
	g_free(content->type);
	g_free(content);
}

static const gchar *
jabber_jingle_session_content_get_name(const JingleSessionContent *jsc)
{
	return jsc->name;
}

static JingleSession *
jabber_jingle_session_content_get_session(const JingleSessionContent *jsc)
{
	return jsc->session;
}

static const gchar *
jabber_jingle_session_content_get_creator(const JingleSessionContent *jsc)
{
	return jsc->creator;
}

static const gchar *
jabber_jingle_session_content_get_sender(const JingleSessionContent *jsc)
{
	return jsc->sender;
}

static const gchar *
jabber_jingle_session_content_get_transport_type(const JingleSessionContent *jsc)
{
	return jsc->transport_type;
}

static gboolean
jabber_jingle_session_content_is_transport_type(const JingleSessionContent *jsc,
						const gchar *transport_type)
{
	return !strcmp(jabber_jingle_session_content_get_transport_type(jsc),
			transport_type);
}

static const gchar *
jabber_jingle_session_content_get_type(const JingleSessionContent *jsc)
{
	return jsc->type;
}

static gboolean
jabber_jingle_session_content_is_type(const JingleSessionContent *jsc,
				      const gchar *type)
{
	return !strcmp(jabber_jingle_session_content_get_type(jsc), type);
}

static gboolean
jabber_jingle_session_content_is_vv(const JingleSessionContent *jsc)
{
	return jabber_jingle_session_content_is_type(jsc, JINGLE_AUDIO) ||
			jabber_jingle_session_content_is_type(jsc, JINGLE_VIDEO);
}

static void
jabber_jingle_session_content_set_sender(JingleSessionContent *jsc,
					    const char *sender)
{
	if (jsc->sender)
		g_free(jsc->sender);
	jsc->sender = g_strdup(sender);
}

static gboolean
jabber_jingle_session_equal(gconstpointer a, gconstpointer b)
{
	purple_debug_info("jingle", 
					  "jabber_jingle_session_equal, comparing %s and %s\n",
					  ((JingleSession *)a)->id,
					  ((JingleSession *)b)->id);
	return !strcmp(((JingleSession *) a)->id, ((JingleSession *) b)->id);
}

static JingleSession *
jabber_jingle_session_create_internal(JabberStream *js,
									  const char *id)
{
    JingleSession *sess = g_new0(JingleSession, 1);
	sess->js = js;
		
	if (id) {
		sess->id = g_strdup(id);
	} else if (js) {
		/* init the session ID... */
		sess->id = jabber_get_next_id(js);
	}
	
	/* insert it into the hash table */
	if (!js->sessions) {
		purple_debug_info("jingle", "Creating hash table for sessions\n");
		js->sessions = g_hash_table_new(g_str_hash, g_str_equal);
	}
	purple_debug_info("jingle", "inserting session with key: %s into table\n",
					  sess->id);
	g_hash_table_insert(js->sessions, sess->id, sess);

	sess->session_started = FALSE;

	return sess;
}

static JabberStream *
jabber_jingle_session_get_js(const JingleSession *sess)
{
	return sess->js;
}

static JingleSession *
jabber_jingle_session_create(JabberStream *js)
{
	JingleSession *sess = jabber_jingle_session_create_internal(js, NULL);
	sess->is_initiator = TRUE;	
	return sess;
}

static JingleSession *
jabber_jingle_session_create_by_id(JabberStream *js, const char *id)
{
	JingleSession *sess = jabber_jingle_session_create_internal(js, id);
	sess->is_initiator = FALSE;
	return sess;
}

static const char *
jabber_jingle_session_get_id(const JingleSession *sess)
{
	return sess->id;
}

static void
jabber_jingle_session_destroy(JingleSession *sess)
{
	GList *contents = g_hash_table_get_values(sess->contents);
	g_hash_table_remove(sess->js->sessions, sess->id);
	g_free(sess->id);
	g_object_unref(sess->media);

	for (; contents; contents = contents->next)
		jabber_jingle_session_destroy_content(contents->data);

	g_list_free(contents);
	g_free(sess);
}

static JingleSession *
jabber_jingle_session_find_by_id(JabberStream *js, const char *id)
{
	purple_debug_info("jingle", "find_by_id %s\n", id);
	purple_debug_info("jingle", "hash table: %p\n", js->sessions);
	purple_debug_info("jingle", "hash table size %d\n",
					  g_hash_table_size(js->sessions));
	purple_debug_info("jingle", "lookup: %p\n", g_hash_table_lookup(js->sessions, id));  
	return (JingleSession *) g_hash_table_lookup(js->sessions, id);
}

static JingleSession *
jabber_jingle_session_find_by_jid(JabberStream *js, const char *jid)
{
	GList *values = g_hash_table_get_values(js->sessions);
	GList *iter = values;
	gboolean use_bare = strchr(jid, '/') == NULL;

	for (; iter; iter = iter->next) {
		JingleSession *session = (JingleSession *)iter->data;
		gchar *cmp_jid = use_bare ? jabber_get_bare_jid(session->remote_jid)
					  : g_strdup(session->remote_jid);
		if (!strcmp(jid, cmp_jid)) {
			g_free(cmp_jid);
			g_list_free(values);
			return session;
		}
		g_free(cmp_jid);
	}

	g_list_free(values);
	return NULL;	
}

static GList *
jabber_jingle_get_codecs(const xmlnode *description)
{
	GList *codecs = NULL;
	xmlnode *codec_element = NULL;
	const char *encoding_name,*id, *clock_rate;
	FsCodec *codec;
	
	for (codec_element = xmlnode_get_child(description, "payload-type") ;
		 codec_element ;
		 codec_element = xmlnode_get_next_twin(codec_element)) {
		encoding_name = xmlnode_get_attrib(codec_element, "name");
		id = xmlnode_get_attrib(codec_element, "id");
		clock_rate = xmlnode_get_attrib(codec_element, "clockrate");

		codec = fs_codec_new(atoi(id), encoding_name, 
				     FS_MEDIA_TYPE_AUDIO, 
				     clock_rate ? atoi(clock_rate) : 0);
		codecs = g_list_append(codecs, codec);		 
	}
	return codecs;
}

static GList *
jabber_jingle_get_candidates(const xmlnode *transport)
{
	GList *candidates = NULL;
	xmlnode *candidate = NULL;
	FsCandidate *c;
	
	for (candidate = xmlnode_get_child(transport, "candidate") ;
		 candidate ;
		 candidate = xmlnode_get_next_twin(candidate)) {
		const char *type = xmlnode_get_attrib(candidate, "type");
		c = fs_candidate_new(xmlnode_get_attrib(candidate, "component"), 
							atoi(xmlnode_get_attrib(candidate, "component")),
							strcmp(type, "host") == 0 ?
							FS_CANDIDATE_TYPE_HOST :
							strcmp(type, "prflx") == 0 ?
							FS_CANDIDATE_TYPE_PRFLX :
							strcmp(type, "relay") == 0 ?
							FS_CANDIDATE_TYPE_RELAY :
							strcmp(type, "srflx") == 0 ?
							FS_CANDIDATE_TYPE_SRFLX : 0,
							strcmp(xmlnode_get_attrib(candidate, "protocol"),
							  "udp") == 0 ? 
				 				FS_NETWORK_PROTOCOL_UDP :
				 				FS_NETWORK_PROTOCOL_TCP,
							xmlnode_get_attrib(candidate, "ip"),
							atoi(xmlnode_get_attrib(candidate, "port")));
		candidates = g_list_append(candidates, c);
	}
	
	return candidates;
}

static JingleSessionContent *
jabber_jingle_session_get_content(const JingleSession *session,
				  const char *name)
{
	return (JingleSession *) name ?
			g_hash_table_lookup(session->contents, name) : NULL;
}

static GList *
jabber_jingle_session_get_contents(const JingleSession *session)
{
	return g_hash_table_get_values(session->contents);
}

static PurpleMedia *
jabber_jingle_session_get_media(const JingleSession *sess)
{
	return sess->media;
}

static void
jabber_jingle_session_set_media(JingleSession *sess, PurpleMedia *media)
{
	sess->media = media;
}

static const char *
jabber_jingle_session_get_remote_jid(const JingleSession *sess)
{
	return sess->remote_jid;
}

static void
jabber_jingle_session_set_remote_jid(JingleSession *sess, 
									 const char *remote_jid)
{
	sess->remote_jid = strdup(remote_jid);
}

static const char *
jabber_jingle_session_get_initiator(const JingleSession *sess)
{
	return sess->initiator;
}

static void
jabber_jingle_session_set_initiator(JingleSession *sess,
									const char *initiator)
{
	sess->initiator = g_strdup(initiator);
}

static gboolean
jabber_jingle_session_is_initiator(const JingleSession *sess)
{
	return sess->is_initiator;
}

static void
jabber_jingle_session_add_payload_types(const JingleSessionContent *jsc,
					xmlnode *description)
{
	JingleSession *session = jabber_jingle_session_content_get_session(jsc);
	PurpleMedia *media = jabber_jingle_session_get_media(session);
	/* change this to the generic function when PurpleMedia supports video */
	GList *codecs = purple_media_get_local_audio_codecs(media);

	for (; codecs ; codecs = codecs->next) {
		FsCodec *codec = (FsCodec*)codecs->data;
		char id[8], clockrate[10], channels[10];
		xmlnode *payload = xmlnode_new_child(description, "payload-type");
		
		g_snprintf(id, sizeof(id), "%d", codec->id);
		g_snprintf(clockrate, sizeof(clockrate), "%d", codec->clock_rate);
		g_snprintf(channels, sizeof(channels), "%d",
			   codec->channels == 0 ? 1 : codec->channels);
		
		xmlnode_set_attrib(payload, "name", codec->encoding_name);
		xmlnode_set_attrib(payload, "id", id);
		xmlnode_set_attrib(payload, "clockrate", clockrate);
		xmlnode_set_attrib(payload, "channels", channels);
	}
	fs_codec_list_destroy(codecs);
}

static xmlnode *
jabber_jingle_session_add_description_vv(const JingleSessionContent *jsc,
					 xmlnode *description)
{
	xmlnode_set_attrib(description, "profile", "RTP/AVP");
	return description;
}

static xmlnode *
jabber_jingle_session_add_description(const JingleSessionContent *jsc,
				      xmlnode *content)
{
	xmlnode *description = xmlnode_new_child(content, "description");
	xmlnode_set_namespace(description,
			jabber_jingle_session_content_get_type(jsc));

	if (jabber_jingle_session_content_is_vv(jsc))
		return jabber_jingle_session_add_description_vv(jsc, description);
	else
		return description;
}

static xmlnode *
jabber_jingle_session_add_candidate_iceudp(xmlnode *transport,
					   FsCandidate *c,
					   FsCandidate *remote)
{
	char port[8];
	char prio[8];
	char component[8];
	xmlnode *candidate = xmlnode_new_child(transport, "candidate");
	
	g_snprintf(port, sizeof(port), "%d", c->port);
	g_snprintf(prio, sizeof(prio), "%d", c->priority);
	g_snprintf(component, sizeof(component), "%d", c->component_id);
	
	xmlnode_set_attrib(candidate, "component", component);
	xmlnode_set_attrib(candidate, "foundation", "1"); /* what about this? */
	xmlnode_set_attrib(candidate, "generation", "0"); /* ? */
	xmlnode_set_attrib(candidate, "ip", c->ip);
	xmlnode_set_attrib(candidate, "network", "0"); /* ? */
	xmlnode_set_attrib(candidate, "port", port);
	xmlnode_set_attrib(candidate, "priority", prio); /* Is this correct? */
	xmlnode_set_attrib(candidate, "protocol",
			   c->proto == FS_NETWORK_PROTOCOL_UDP ?
			   "udp" : "tcp");
	if (c->username)
		xmlnode_set_attrib(transport, "ufrag", c->username);
	if (c->password)
		xmlnode_set_attrib(transport, "pwd", c->password);
	
	xmlnode_set_attrib(candidate, "type", 
			   c->type == FS_CANDIDATE_TYPE_HOST ? 
			   "host" :
			   c->type == FS_CANDIDATE_TYPE_PRFLX ? 
			   "prflx" :
		       	   c->type == FS_CANDIDATE_TYPE_RELAY ? 
			   "relay" :
			   c->type == FS_CANDIDATE_TYPE_SRFLX ?
			   "srflx" : NULL);

	/* relay */
	if (c->type == FS_CANDIDATE_TYPE_RELAY) {
		/* set rel-addr and rel-port? How? */
	}

	if (remote) {
		char remote_port[8];
		g_snprintf(remote_port, sizeof(remote_port), "%d", remote->port);
		xmlnode_set_attrib(candidate, "rem-addr", remote->ip);
		xmlnode_set_attrib(candidate, "rem-port", remote_port);
	}

	return candidate;
}

static xmlnode *
jabber_jingle_session_add_transport(const JingleSessionContent *jsc,
				    xmlnode *content)
{
	xmlnode *transport = xmlnode_new_child(content, "transport");
	const gchar *transport_type = jabber_jingle_session_content_get_transport_type(jsc);
	xmlnode_set_namespace(transport, transport_type);
	return transport;
}

static xmlnode *
jabber_jingle_session_add_content(const JingleSessionContent *jsc,
				  xmlnode *jingle)
{
	xmlnode *content = xmlnode_new_child(jingle, "content");
	xmlnode_set_attrib(content, "creator",
			   jabber_jingle_session_content_get_creator(jsc));
	xmlnode_set_attrib(content, "name",
			   jabber_jingle_session_content_get_name(jsc));
	xmlnode_set_attrib(content, "sender",
			   jabber_jingle_session_content_get_sender(jsc));
	return content;
}


static xmlnode *
jabber_jingle_session_add_jingle(const JingleSession *sess,
				 JabberIq *iq, const char *action)
{
	xmlnode *jingle = iq ? xmlnode_new_child(iq->node, "jingle") : 
				xmlnode_new("jingle");
	xmlnode_set_namespace(jingle, JINGLE);
	xmlnode_set_attrib(jingle, "action", action);
	xmlnode_set_attrib(jingle, "initiator", 
			   jabber_jingle_session_get_initiator(sess));
	if (jabber_jingle_session_is_initiator(sess))
		xmlnode_set_attrib(jingle, "responder",
				jabber_jingle_session_get_remote_jid(sess));
	else {
		gchar *responder = g_strdup_printf("%s@%s/%s",
				sess->js->user->node,
				sess->js->user->domain,
				sess->js->user->resource);
		xmlnode_set_attrib(jingle, "responder", responder);
		g_free(responder);
	}
	xmlnode_set_attrib(jingle, "sid", jabber_jingle_session_get_id(sess));
	
	return jingle;
}

static JabberIq *
jabber_jingle_session_create_ack(JabberStream *js, xmlnode *packet)
{
	JabberIq *result = jabber_iq_new(js, JABBER_IQ_RESULT);
	jabber_iq_set_id(result, xmlnode_get_attrib(packet, "id"));
	xmlnode_set_attrib(result->node, "from", xmlnode_get_attrib(packet, "to"));
	xmlnode_set_attrib(result->node, "to", xmlnode_get_attrib(packet, "from"));
	return result;
}

static JabberIq *
jabber_jingle_session_create_iq(const JingleSession *session)
{
	JabberIq *result = jabber_iq_new(jabber_jingle_session_get_js(session),
					 JABBER_IQ_SET);
	gchar *from = g_strdup_printf("%s@%s/%s", session->js->user->node,
				      session->js->user->domain,
				      session->js->user->resource);
	xmlnode_set_attrib(result->node, "from", from);
	g_free(from);
	xmlnode_set_attrib(result->node, "to",
			   jabber_jingle_session_get_remote_jid(session));
	return result;
}

static xmlnode *
jabber_jingle_session_create_description(const JingleSession *sess)
{
    GList *codecs = purple_media_get_local_audio_codecs(sess->media);
    xmlnode *description = xmlnode_new("description");

	xmlnode_set_namespace(description, JINGLE_AUDIO);
	
	/* get codecs */
	for (; codecs ; codecs = codecs->next) {
		FsCodec *codec = (FsCodec*)codecs->data;
		char id[8], clockrate[10], channels[10];
		xmlnode *payload = xmlnode_new_child(description, "payload-type");
		
		g_snprintf(id, sizeof(id), "%d", codec->id);
		g_snprintf(clockrate, sizeof(clockrate), "%d", codec->clock_rate);
		g_snprintf(channels, sizeof(channels), "%d", codec->channels);
		
		xmlnode_set_attrib(payload, "name", codec->encoding_name);
		xmlnode_set_attrib(payload, "id", id);
		xmlnode_set_attrib(payload, "clockrate", clockrate);
		xmlnode_set_attrib(payload, "channels", channels);
    }
    
    fs_codec_list_destroy(codecs);
    return description;
}

static xmlnode *
jabber_jingle_session_create_content_accept(const JingleSession *sess)
{
	xmlnode *jingle = 
		jabber_jingle_session_add_jingle(sess, NULL, "content-accept");

	xmlnode *content = xmlnode_new_child(jingle, "content");
	xmlnode *description = jabber_jingle_session_create_description(sess);

	xmlnode_set_attrib(content, "creator", "initiator");
	xmlnode_set_attrib(content, "name", "audio-content");
	xmlnode_set_attrib(content, "profile", "RTP/AVP");

	xmlnode_insert_child(content, description);

	return jingle;
}

static xmlnode *
jabber_jingle_session_create_content_replace(const JingleSession *sess,
					     FsCandidate *native_candidate,
					     FsCandidate *remote_candidate)
{
	xmlnode *jingle = 
		jabber_jingle_session_add_jingle(sess, NULL, "content-replace");
	xmlnode *content = NULL;
	xmlnode *transport = NULL;

	purple_debug_info("jingle", "creating content-modify for native candidate %s " \
			  ", remote candidate %s\n", native_candidate->candidate_id,
			  remote_candidate->candidate_id);

	content = xmlnode_new_child(jingle, "content");
	xmlnode_set_attrib(content, "creator", "initiator");
	xmlnode_set_attrib(content, "name", "audio-content");
	xmlnode_set_attrib(content, "profile", "RTP/AVP");
	
	/* get top codec from codec_intersection to put here... */
	/* later on this should probably handle changing codec */

	xmlnode_insert_child(content, jabber_jingle_session_create_description(sess));

	transport = xmlnode_new_child(content, "transport");
	xmlnode_set_namespace(transport, TRANSPORT_ICEUDP);
	jabber_jingle_session_add_candidate_iceudp(transport, native_candidate,
						   remote_candidate);

	purple_debug_info("jingle", "End create content modify\n");
	
	return jingle;
}

static JabberIq *
jabber_jingle_session_create_session_accept(const JingleSession *session,
					    FsCandidate *local,
					    FsCandidate *remote)
{
	JabberIq *request = jabber_jingle_session_create_iq(session);
	xmlnode *jingle =
		jabber_jingle_session_add_jingle(session, request,
						 "session-accept");
	GList *contents = jabber_jingle_session_get_contents(session);

	for (; contents; contents = contents->next) {
		JingleSessionContent *jsc = contents->data;
		xmlnode *content = jabber_jingle_session_add_content(jsc, jingle);
		xmlnode *description = jabber_jingle_session_add_description(jsc, content);
		xmlnode *transport = jabber_jingle_session_add_transport(jsc, content);
		if (jabber_jingle_session_content_is_vv(jsc))
			jabber_jingle_session_add_payload_types(jsc, description);
		if (jabber_jingle_session_content_is_transport_type(jsc, TRANSPORT_ICEUDP))
			jabber_jingle_session_add_candidate_iceudp(transport, local, remote);
	}

	return request;
}

static JabberIq *
jabber_jingle_session_create_session_info(const JingleSession *session,
					  const gchar *type)
{
	JabberIq *request = jabber_jingle_session_create_iq(session);
	xmlnode *jingle =
		jabber_jingle_session_add_jingle(session, request,
						 "session-info");
	xmlnode *info = xmlnode_new_child(jingle, type);
	xmlnode_set_namespace(info, JINGLE_AUDIO ":info");
	return request;
}

static JabberIq *
jabber_jingle_session_create_session_initiate(const JingleSession *session)
{
	JabberIq *request = jabber_jingle_session_create_iq(session);
	xmlnode *jingle =
		jabber_jingle_session_add_jingle(session, request,
						 "session-initiate");
	GList *contents = jabber_jingle_session_get_contents(session);

	for (; contents; contents = contents->next) {
		JingleSessionContent *jsc = contents->data;
		xmlnode *content = jabber_jingle_session_add_content(jsc, jingle);
		xmlnode *description = jabber_jingle_session_add_description(jsc, content);
		if (jabber_jingle_session_content_is_vv(jsc))
			jabber_jingle_session_add_payload_types(jsc, description);
		jabber_jingle_session_add_transport(jsc, content);
	}

	return request;
}

static JabberIq *
jabber_jingle_session_create_session_terminate(const JingleSession *sess,
					       const char *reasoncode,
					       const char *reasontext)
{
	JabberIq *request = jabber_jingle_session_create_iq(sess);
	xmlnode *jingle = 
		jabber_jingle_session_add_jingle(sess, request,
						 "session-terminate");
	xmlnode *reason = xmlnode_new_child(jingle, "reason");
	xmlnode *condition = xmlnode_new_child(reason, "condition");
	xmlnode_new_child(condition, reasoncode);
	if (reasontext) {
		xmlnode *text = xmlnode_new_child(reason, "text");
		xmlnode_insert_data(text, reasontext, strlen(reasontext));
	}
	
	return request;
}

static JabberIq *
jabber_jingle_session_create_transport_info(const JingleSessionContent *jsc,
					    FsCandidate *candidate)
{
	JingleSession *session = 
			jabber_jingle_session_content_get_session(jsc);
	JabberIq *request = jabber_jingle_session_create_iq(session);
	xmlnode *jingle =
		jabber_jingle_session_add_jingle(session, request,
						 "transport-info");
	xmlnode *content = jabber_jingle_session_add_content(jsc, jingle);
	xmlnode *transport = jabber_jingle_session_add_transport(jsc, content);
	jabber_jingle_session_add_candidate_iceudp(transport, candidate, NULL);
	return request;
}

static void
jabber_jingle_session_send_content_accept(JingleSession *session)
{
	JabberIq *result = jabber_iq_new(jabber_jingle_session_get_js(session),
					 JABBER_IQ_SET);
	xmlnode *jingle = jabber_jingle_session_create_content_accept(session);
	xmlnode_set_attrib(result->node, "to",
			   jabber_jingle_session_get_remote_jid(session));

	xmlnode_insert_child(result->node, jingle);
	jabber_iq_send(result);
}

static void
jabber_jingle_session_send_session_accept(JingleSession *session)
{
	/* create transport-info packages */
	PurpleMedia *media = jabber_jingle_session_get_media(session);
	GList *contents = jabber_jingle_session_get_contents(session);
	for (; contents; contents = contents->next) {
		JingleSessionContent *jsc = contents->data;
		GList *candidates = purple_media_get_local_audio_candidates(
				jabber_jingle_session_get_media(session));
		purple_debug_info("jabber",
				  "jabber_session_candidates_prepared: %d candidates\n",
				  g_list_length(candidates));
		for (; candidates; candidates = candidates->next) {
			FsCandidate *candidate = candidates->data;
			JabberIq *result = jabber_jingle_session_create_transport_info(jsc,
					candidate);
			jabber_iq_send(result);
		}
		fs_candidate_list_destroy(candidates);
	}

	jabber_iq_send(jabber_jingle_session_create_session_accept(session, 
			purple_media_get_local_candidate(media),
			purple_media_get_remote_candidate(media)));

	purple_debug_info("jabber", "Sent session accept, starting stream\n");
	gst_element_set_state(purple_media_get_audio_pipeline(session->media), GST_STATE_PLAYING);

	session->session_started = TRUE;
}

static void
jabber_jingle_session_send_session_reject(JingleSession *session)
{
	jabber_iq_send(jabber_jingle_session_create_session_terminate(session,
			"decline", NULL));
	jabber_jingle_session_destroy(session);
}

static void
jabber_jingle_session_send_session_terminate(JingleSession *session)
{
	jabber_iq_send(jabber_jingle_session_create_session_terminate(session,
			"no-error", NULL));
	jabber_jingle_session_destroy(session);
}

static void
jabber_jingle_session_content_create_media(JingleSession *session,
					     PurpleMediaStreamType type)
{
	gchar sender[10] = "";

	if (type & PURPLE_MEDIA_AUDIO) {
		if (type == PURPLE_MEDIA_SEND_AUDIO)
			strcpy(sender, "initiator");
		else if (type == PURPLE_MEDIA_RECV_AUDIO)
			strcpy(sender, "responder");
		else
			strcpy(sender, "both");
		jabber_jingle_session_content_create_internal(session,
				"audio-content", "initiator", sender,
				TRANSPORT_ICEUDP, JINGLE_AUDIO);
	} else if (type & PURPLE_MEDIA_VIDEO) {
		if (type == PURPLE_MEDIA_SEND_VIDEO)
			strcpy(sender, "initiator");
		else if (type == PURPLE_MEDIA_RECV_VIDEO)
			strcpy(sender, "responder");
		else
			strcpy(sender, "both");
		jabber_jingle_session_content_create_internal(session,
				"video-content", "initiator", sender,
				TRANSPORT_ICEUDP, JINGLE_VIDEO);
	}
}

static void
jabber_jingle_session_content_create_parse(JingleSession *session,
					   xmlnode *jingle)
{
	xmlnode *content = xmlnode_get_child(jingle, "content");
	xmlnode *description = xmlnode_get_child(content, "description");
	xmlnode *transport = xmlnode_get_child(content, "transport");

	const gchar *creator = xmlnode_get_attrib(content, "creator");
	const gchar *sender = xmlnode_get_attrib(content, "sender");

	jabber_jingle_session_content_create_internal(session,
						      xmlnode_get_attrib(content, "name"),
						      creator ? creator : "initiator",
						      sender ? sender : "both",
						      xmlnode_get_namespace(transport),
						      xmlnode_get_namespace(description));
}

/* callback called when new local transport candidate(s) are available on the
	Farsight stream */
static void
jabber_jingle_session_candidates_prepared(PurpleMedia *media, JingleSession *session)
{
#if 0
	if (!jabber_jingle_session_is_initiator(session)) {
		/* create transport-info packages */
		GList *contents = jabber_jingle_session_get_contents(session);
		for (; contents; contents = contents->next) {
			JingleSessionContent *jsc = contents->data;
			GList *candidates = purple_media_get_local_audio_candidates(
					jabber_jingle_session_get_media(session));
			purple_debug_info("jabber",
					  "jabber_session_candidates_prepared: %d candidates\n",
					  g_list_length(candidates));
			for (; candidates; candidates = candidates->next) {
				FsCandidate *candidate = candidates->data;
				JabberIq *result = jabber_jingle_session_create_transport_info(jsc,
						candidate);
				jabber_iq_send(result);
			}
			fs_candidate_list_destroy(candidates);
		}
	}
#endif
}

/* callback called when a pair of transport candidates (local and remote)
	has been established */
static void
jabber_jingle_session_candidate_pair_established(PurpleMedia *media,
						 FsCandidate *native_candidate,
						 FsCandidate *remote_candidate,
						 JingleSession *session)
{
#if 0
	purple_debug_info("jabber", "jabber_candidate_pair_established called\n");
	/* if we are the responder, we should send a sesson-accept message */
	if (!jabber_jingle_session_is_initiator(session) &&
			!session->session_started) {
		jabber_iq_send(jabber_jingle_session_create_session_accept(session, 
				native_candidate, remote_candidate));
	}
#endif
}

static gboolean
jabber_jingle_session_initiate_media_internal(JingleSession *session,
					      const char *initiator,
					      const char *remote_jid)
{
	PurpleMedia *media = NULL;

	media = purple_media_manager_create_media(purple_media_manager_get(), 
						  session->js->gc, "fsrtpconference", remote_jid);

	if (!media) {
		purple_debug_error("jabber", "Couldn't create fsrtpconference\n");
		return FALSE;
	}

	/* this will need to be changed to "nice" once the libnice transmitter is finished */
	if (!purple_media_add_stream(media, remote_jid, PURPLE_MEDIA_AUDIO, "rawudp")) {
		purple_debug_error("jabber", "Couldn't create audio stream\n");
		purple_media_reject(media);
		return FALSE;
	}

	jabber_jingle_session_set_remote_jid(session, remote_jid);
	jabber_jingle_session_set_initiator(session, initiator);
	jabber_jingle_session_set_media(session, media);

	/* connect callbacks */
	g_signal_connect_swapped(G_OBJECT(media), "accepted", 
				 G_CALLBACK(jabber_jingle_session_send_session_accept), session);
	g_signal_connect_swapped(G_OBJECT(media), "reject", 
				 G_CALLBACK(jabber_jingle_session_send_session_reject), session);
	g_signal_connect_swapped(G_OBJECT(media), "hangup", 
				 G_CALLBACK(jabber_jingle_session_send_session_terminate), session);
	g_signal_connect(G_OBJECT(media), "candidates-prepared", 
				 G_CALLBACK(jabber_jingle_session_candidates_prepared), session);
	g_signal_connect(G_OBJECT(media), "candidate-pair", 
				 G_CALLBACK(jabber_jingle_session_candidate_pair_established), session);

	purple_media_ready(media);

	return TRUE;
}

static void
jabber_jingle_session_initiate_result_cb(JabberStream *js, xmlnode *packet, gpointer data)
{
	const char *from = xmlnode_get_attrib(packet, "from");
	JingleSession *session = jabber_jingle_session_find_by_jid(js, from);
	PurpleMedia *media = session->media;
	GList *contents;

	if (!strcmp(xmlnode_get_attrib(packet, "type"), "error")) {
		purple_media_got_hangup(media);
		return;
	}

	/* catch errors */
	if (xmlnode_get_child(packet, "error")) {
		purple_media_got_hangup(media);
		return;
	}

	/* create transport-info packages */
	contents = jabber_jingle_session_get_contents(session);
	for (; contents; contents = contents->next) {
		JingleSessionContent *jsc = contents->data;
		GList *candidates = purple_media_get_local_audio_candidates(
				jabber_jingle_session_get_media(session));
		purple_debug_info("jabber",
				  "jabber_session_candidates_prepared: %d candidates\n",
				  g_list_length(candidates));
		for (; candidates; candidates = candidates->next) {
			FsCandidate *candidate = candidates->data;
			JabberIq *result = jabber_jingle_session_create_transport_info(jsc,
					candidate);
			jabber_iq_send(result);
		}
		fs_candidate_list_destroy(candidates);
	}
}

PurpleMedia *
jabber_jingle_session_initiate_media(JabberStream *js, const char *who, 
				     PurpleMediaStreamType type)
{
	/* create content negotiation */
	JabberIq *request;
	JingleSession *session;
	JabberBuddy *jb;
	JabberBuddyResource *jbr;
	
	char *jid = NULL, *me = NULL;

	/* construct JID to send to */
	jb = jabber_buddy_find(js, who, FALSE);
	if (!jb) {
		purple_debug_error("jabber", "Could not find Jabber buddy\n");
		return NULL;
	}
	jbr = jabber_buddy_find_resource(jb, NULL);
	if (!jbr) {
		purple_debug_error("jabber", "Could not find buddy's resource\n");
	}

	if ((strchr(who, '/') == NULL) && jbr && (jbr->name != NULL)) {
		jid = g_strdup_printf("%s/%s", who, jbr->name);
	} else {
		jid = g_strdup(who);
	}
	
	session = jabber_jingle_session_create(js);
	/* set ourselves as initiator */
	me = g_strdup_printf("%s@%s/%s", js->user->node, js->user->domain, js->user->resource);

	if (!jabber_jingle_session_initiate_media_internal(session, me, jid)) {
		g_free(jid);
		g_free(me);
		jabber_jingle_session_destroy(session);
		return NULL;
	}

	g_free(jid);
	g_free(me);

	jabber_jingle_session_content_create_media(session, type);

	/* create request */
	request = jabber_jingle_session_create_session_initiate(session);
	jabber_iq_set_callback(request, jabber_jingle_session_initiate_result_cb, NULL);

	/* send request to other part */	
	jabber_iq_send(request);

	return session->media;
}

void
jabber_jingle_session_terminate_session_media(JabberStream *js, const gchar *who)
{
	JingleSession *session;

	session = jabber_jingle_session_find_by_jid(js, who);

	if (session)
		purple_media_hangup(session->media);
}

void
jabber_jingle_session_terminate_sessions(JabberStream *js)
{
	GList *values = g_hash_table_get_values(js->sessions);

	for (; values; values = values->next) {
		JingleSession *session = (JingleSession *)values->data;
		purple_media_hangup(session->media);
	}

	g_list_free(values);
}

void
jabber_jingle_session_handle_content_replace(JabberStream *js, xmlnode *packet)
{
	xmlnode *jingle = xmlnode_get_child(packet, "jingle");
	const char *sid = xmlnode_get_attrib(jingle, "sid");
	JingleSession *session = jabber_jingle_session_find_by_id(js, sid);

	if (!jabber_jingle_session_is_initiator(session) && session->session_started) {
		JabberIq *result = jabber_iq_new(js, JABBER_IQ_RESULT);
		JabberIq *accept = jabber_iq_new(js, JABBER_IQ_SET);
		xmlnode *content_accept = NULL;

		/* send acknowledement */
		xmlnode_set_attrib(result->node, "id", xmlnode_get_attrib(packet, "id"));
		xmlnode_set_attrib(result->node, "to", xmlnode_get_attrib(packet, "from"));
		jabber_iq_send(result);

		/* send content-accept */
		content_accept = jabber_jingle_session_create_content_accept(session);
		xmlnode_set_attrib(accept->node, "id", xmlnode_get_attrib(packet, "id"));
		xmlnode_set_attrib(accept->node, "to", xmlnode_get_attrib(packet, "from"));
		xmlnode_insert_child(accept->node, content_accept);

		jabber_iq_send(accept);
	}
}

void
jabber_jingle_session_handle_session_accept(JabberStream *js, xmlnode *packet)
{
	JabberIq *result = jabber_iq_new(js, JABBER_IQ_RESULT);
	xmlnode *jingle = xmlnode_get_child(packet, "jingle");
	xmlnode *content = xmlnode_get_child(jingle, "content");
	const char *sid = xmlnode_get_attrib(jingle, "sid");
	const char *action = xmlnode_get_attrib(jingle, "action");
	JingleSession *session = jabber_jingle_session_find_by_id(js, sid);
	GList *remote_codecs = NULL;
	GList *remote_transports = NULL;
	GList *codec_intersection;
	FsCodec *top = NULL;
	xmlnode *description = NULL;
	xmlnode *transport = NULL;

	/* We should probably check validity of the incoming XML... */

	xmlnode_set_attrib(result->node, "to",
			   jabber_jingle_session_get_remote_jid(session));
	jabber_iq_set_id(result, xmlnode_get_attrib(packet, "id"));

	description = xmlnode_get_child(content, "description");
	transport = xmlnode_get_child(content, "transport");

	/* fetch codecs from remote party */
	purple_debug_info("jabber", "get codecs from session-accept\n");
	remote_codecs = jabber_jingle_get_codecs(description);
	purple_debug_info("jabber", "get transport candidates from session accept\n");
	remote_transports = jabber_jingle_get_candidates(transport);

	purple_debug_info("jabber", "Got %d codecs from responder\n",
			  g_list_length(remote_codecs));
	purple_debug_info("jabber", "Got %d transport candidates from responder\n",
			  g_list_length(remote_transports));

	purple_debug_info("jabber", "Setting remote codecs on stream\n");

	purple_media_set_remote_audio_codecs(session->media, 
					     jabber_jingle_session_get_remote_jid(session),
					     remote_codecs);

	codec_intersection = purple_media_get_negotiated_audio_codecs(session->media);
	purple_debug_info("jabber", "codec_intersection contains %d elems\n",
			  g_list_length(codec_intersection));
	/* get the top codec */
	if (g_list_length(codec_intersection) > 0) {
		top = (FsCodec *) codec_intersection->data;
		purple_debug_info("jabber", "Found a suitable codec on stream = %d\n",
				  top->id);

		/* we have found a suitable codec, but we will not start the stream
		   just yet, wait for transport negotiation to complete... */
	}
	/* if we also got transport candidates, add them to our streams
	   list of known remote candidates */
	if (g_list_length(remote_transports) > 0) {
		purple_media_add_remote_audio_candidates(session->media,
							 jabber_jingle_session_get_remote_jid(session),
							 remote_transports);
		fs_candidate_list_destroy(remote_transports);
	}
	if (g_list_length(codec_intersection) == 0 &&
			g_list_length(remote_transports)) {
		/* we didn't get any candidates and the codec intersection is empty,
		   this means this was not a content-accept message and we couldn't
		   find any suitable codecs, should return error and hang up */

	}

	g_list_free(codec_intersection);

	if (!strcmp(action, "session-accept")) {
		purple_media_got_accept(jabber_jingle_session_get_media(session));
		purple_debug_info("jabber", "Got session-accept, starting stream\n");
		gst_element_set_state(purple_media_get_audio_pipeline(session->media),
				      GST_STATE_PLAYING);
	}

	jabber_iq_send(result);

	session->session_started = TRUE;
}

void
jabber_jingle_session_handle_session_info(JabberStream *js, xmlnode *packet)
{
	purple_debug_info("jingle", "got session-info\n");
	jabber_iq_send(jabber_jingle_session_create_ack(js, packet));
}

void 
jabber_jingle_session_handle_session_initiate(JabberStream *js, xmlnode *packet)
{
	JingleSession *session = NULL;
	xmlnode *jingle = xmlnode_get_child(packet, "jingle");
	xmlnode *content = NULL;
	xmlnode *description = NULL;
	xmlnode *transport = NULL;
	const char *sid = NULL;
	const char *initiator = NULL;
	GList *codecs = NULL;

	if (!jingle) {
		purple_debug_error("jabber", "Malformed request");
		return;
	}

	sid = xmlnode_get_attrib(jingle, "sid");
	initiator = xmlnode_get_attrib(jingle, "initiator");

	if (jabber_jingle_session_find_by_id(js, sid)) {
		/* This should only happen if you start a session with yourself */
		purple_debug_error("jabber", "Jingle session with id={%s} already exists\n", sid);
		return;
	}
	session = jabber_jingle_session_create_by_id(js, sid);

	/* init media */
	content = xmlnode_get_child(jingle, "content");
	if (!content) {
		purple_debug_error("jabber", "jingle tag must contain content tag\n");
		/* should send error here */
		return;
	}

	description = xmlnode_get_child(content, "description");

	if (!description) {
		purple_debug_error("jabber", "content tag must contain description tag\n");
		/* we should create an error iq here */
		return;
	}

	transport = xmlnode_get_child(content, "transport");

	if (!transport) {
		purple_debug_error("jingle", "content tag must contain transport tag\n");
		/* we should create an error iq here */
		return;
	}

	if (!jabber_jingle_session_initiate_media_internal(session, initiator, initiator)) {
		purple_debug_error("jabber", "Couldn't start media session with %s\n", initiator);
		jabber_jingle_session_destroy(session);
		/* we should create an error iq here */
		return;
	}

	jabber_jingle_session_content_create_parse(session, jingle);

	codecs = jabber_jingle_get_codecs(description);

	purple_media_set_remote_audio_codecs(session->media, initiator, codecs);

	jabber_iq_send(jabber_jingle_session_create_ack(js, packet));
	jabber_iq_send(jabber_jingle_session_create_session_info(session, "ringing"));
}

void
jabber_jingle_session_handle_session_terminate(JabberStream *js, xmlnode *packet)
{
	xmlnode *jingle = xmlnode_get_child(packet, "jingle");
	const char *sid = xmlnode_get_attrib(jingle, "sid");
	JingleSession *session = jabber_jingle_session_find_by_id(js, sid);

	if (!session) {
		purple_debug_error("jabber", "jabber_handle_session_terminate couldn't find session\n");
		return;
	}

	/* maybe we should look at the reasoncode to determine if it was
	   a hangup or a reject, and call different callbacks to purple_media */
	gst_element_set_state(purple_media_get_audio_pipeline(session->media), GST_STATE_NULL);

	purple_media_got_hangup(jabber_jingle_session_get_media(session));
	jabber_iq_send(jabber_jingle_session_create_ack(js, packet));
	jabber_jingle_session_destroy(session);
}

void
jabber_jingle_session_handle_transport_info(JabberStream *js, xmlnode *packet)
{
	JabberIq *result = jabber_iq_new(js, JABBER_IQ_RESULT);
	xmlnode *jingle = xmlnode_get_child(packet, "jingle");
	xmlnode *content = xmlnode_get_child(jingle, "content");
	xmlnode *transport = xmlnode_get_child(content, "transport");
	GList *remote_candidates = jabber_jingle_get_candidates(transport);
	const char *sid = xmlnode_get_attrib(jingle, "sid");
	JingleSession *session = jabber_jingle_session_find_by_id(js, sid);

	if (!session)
		purple_debug_error("jabber", "jabber_handle_session_candidates couldn't find session\n");

	/* send acknowledement */
	xmlnode_set_attrib(result->node, "id", xmlnode_get_attrib(packet, "id"));
	xmlnode_set_attrib(result->node, "to", xmlnode_get_attrib(packet, "from"));
	jabber_iq_send(result);

	/* add candidates to our list of remote candidates */
	if (g_list_length(remote_candidates) > 0) {
		purple_media_add_remote_audio_candidates(session->media,
							 xmlnode_get_attrib(packet, "from"),
							 remote_candidates);
		fs_candidate_list_destroy(remote_candidates);
	}
}

#endif /* USE_VV */

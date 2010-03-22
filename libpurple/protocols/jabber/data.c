/*
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
 * GNU Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "internal.h"

#include <stdlib.h>
#include <glib.h>
#include <string.h>

#include "data.h"
#include "debug.h"
#include "xmlnode.h"
#include "util.h"
#include "iq.h"

static GHashTable *local_data_by_alt = NULL;
static GHashTable *local_data_by_cid = NULL;
static GHashTable *remote_data_by_cid = NULL;

JabberData *
jabber_data_create_from_data(gconstpointer rawdata, gsize size, const char *type,
	gboolean ephemeral, JabberStream *js)
{
	JabberData *data = g_new0(JabberData, 1);
	gchar *checksum = jabber_calculate_data_hash(rawdata, size, "sha1");
	gchar cid[256];

	g_snprintf(cid, sizeof(cid), "sha1+%s@bob.xmpp.org", checksum);
	g_free(checksum);

	data->cid = g_strdup(cid);
	data->type = g_strdup(type);
	data->size = size;
	data->ephemeral = ephemeral;

	data->data = g_memdup(rawdata, size);

	return data;
}


static gboolean
jabber_data_has_valid_hash(const JabberData *data)
{
	const gchar *cid = jabber_data_get_cid(data);
	gchar **cid_parts = g_strsplit(cid, "@", -1);
	gchar **iter;
	int num_parts = 0;

	purple_debug_info("jabber", "validating BoB hash %s\n", cid);
	
	for (iter = cid_parts; *iter != NULL ; iter++) {
		num_parts++;
	}

	if (num_parts == 2 && purple_strequal(cid_parts[1], "bob.xmpp.org")) {
		gchar **sub_parts = g_strsplit(cid_parts[0], "+", -1);

		num_parts = 0;
		for (iter = sub_parts ; *iter != NULL ; iter++) {
			num_parts++;
		}

		if (num_parts == 2) {
			const gchar *hash_algo = sub_parts[0];
			const gchar *hash_value = sub_parts[1];
			gchar *digest =
				jabber_calculate_data_hash(jabber_data_get_data(data),
				    jabber_data_get_size(data), hash_algo);

			purple_debug_info("jabber", "BoB expecting hash: %s\n", digest);
			
			if (digest) {
				gboolean result = purple_strequal(digest, hash_value);

				if (!result) {
					purple_debug_error("jabber", "invalid BoB hash\n");
				}
				g_free(digest);
				return result;
			} else {
				purple_debug_info("jabber", "unknown BoB hash algo\n");
				return FALSE;
			}
		} else {
			return TRUE;
		}
	} else {
		return TRUE;
	}
}

static void
jabber_data_delete(gpointer cbdata)
{
	JabberData *data = cbdata;
	g_free(data->cid);
	g_free(data->type);
	g_free(data->data);
	g_free(data);
}


JabberData *
jabber_data_create_from_xml(xmlnode *tag)
{
	JabberData *data;
	gchar *raw_data = NULL;
	const gchar *cid, *type;

	/* check if this is a "data" tag */
	if (strcmp(tag->name, "data") != 0) {
		purple_debug_error("jabber", "Invalid data element\n");
		return NULL;
	}

	cid = xmlnode_get_attrib(tag, "cid");
	type = xmlnode_get_attrib(tag, "type");

	if (!cid || !type) {
		purple_debug_error("jabber", "cid or type missing\n");
		return NULL;
	}

	raw_data = xmlnode_get_data(tag);

	if (raw_data == NULL || *raw_data == '\0') {
		purple_debug_error("jabber", "data element was empty");
		g_free(raw_data);
		return NULL;
	}

	data = g_new0(JabberData, 1);
	data->data = purple_base64_decode(raw_data, &data->size);
	g_free(raw_data);

	if (data->data == NULL) {
		purple_debug_error("jabber", "Malformed base64 data\n");
		g_free(data);
		return NULL;
	}

	data->cid = g_strdup(cid);
	data->type = g_strdup(type);

	if (!jabber_data_has_valid_hash(data)) {
		jabber_data_delete(data);
		return NULL;
	}

	return data;
}

void
jabber_data_destroy(JabberData *data)
{
	jabber_data_delete(data);
}

const char *
jabber_data_get_cid(const JabberData *data)
{
	return data->cid;
}


const char *
jabber_data_get_type(const JabberData *data)
{
	return data->type;
}

gsize
jabber_data_get_size(const JabberData *data)
{
	return data->size;
}

gpointer
jabber_data_get_data(const JabberData *data)
{
	return data->data;
}

xmlnode *
jabber_data_get_xml_definition(const JabberData *data)
{
	xmlnode *tag = xmlnode_new("data");
	char *base64data = purple_base64_encode(data->data, data->size);

	xmlnode_set_namespace(tag, NS_BOB);
	xmlnode_set_attrib(tag, "cid", data->cid);
	xmlnode_set_attrib(tag, "type", data->type);

	xmlnode_insert_data(tag, base64data, -1);

	g_free(base64data);

	return tag;
}

xmlnode *
jabber_data_get_xhtml_im(const JabberData *data, const gchar *alt)
{
	xmlnode *img = xmlnode_new("img");
	char src[128];

	xmlnode_set_attrib(img, "alt", alt);
	g_snprintf(src, sizeof(src), "cid:%s", data->cid);
	xmlnode_set_attrib(img, "src", src);

	return img;
}

static xmlnode *
jabber_data_get_xml_request(const gchar *cid)
{
	xmlnode *tag = xmlnode_new("data");

	xmlnode_set_namespace(tag, NS_BOB);
	xmlnode_set_attrib(tag, "cid", cid);

	return tag;
}


typedef struct {
	gpointer userdata;
	gchar *alt;
	gboolean ephemeral;
	JabberDataRequestCallback *cb;
} JabberDataRequestData;

static void
jabber_data_request_cb(JabberStream *js, const char *from,
	JabberIqType type, const char *id, xmlnode *packet, gpointer data)
{
	JabberDataRequestData *request_data = (JabberDataRequestData *) data;
	gpointer userdata = request_data->userdata;
	gchar *alt = request_data->alt;
	gboolean ephemeral = request_data->ephemeral;
	JabberDataRequestCallback *cb = request_data->cb;
	
	xmlnode *data_element = xmlnode_get_child(packet, "data");
	xmlnode *item_not_found = xmlnode_get_child(packet, "item-not-found");

	/* did we get a data element as result? */
	if (data_element && type == JABBER_IQ_RESULT) {
		JabberData *data = jabber_data_create_from_xml(data_element);

		if (data) {
			if (!ephemeral) {
				jabber_data_associate_remote(data);
			}
			cb(data, alt, userdata);
		} else {
			/* could not validate hash when creating data from XML */
			purple_debug_info("jabber",
			    "hash validation failed on requested BoB object\n");
			cb(NULL, alt, userdata);
		}
	} else if (item_not_found) {
		purple_debug_info("jabber",
			"Responder didn't recognize requested data\n");
		cb(NULL, alt, userdata);
	} else {
		purple_debug_error("jabber", "Unknown response to data request\n");
		cb(NULL, alt, userdata);
	}

	g_free(request_data);
}

void
jabber_data_request(JabberStream *js, const gchar *cid, const gchar *who, 
    gchar *alt, gboolean ephemeral, JabberDataRequestCallback cb,
    gpointer userdata)
{
	JabberIq *request = jabber_iq_new(js, JABBER_IQ_GET);
	xmlnode *data_request = jabber_data_get_xml_request(cid);
	JabberDataRequestData *data = g_new0(JabberDataRequestData, 1);

	data->userdata = userdata;
	data->alt = alt;
	data->ephemeral = ephemeral;
	data->cb = cb;
	
	xmlnode_set_attrib(request->node, "to", who);
	jabber_iq_set_callback(request, jabber_data_request_cb, data);
	xmlnode_insert_child(request->node, data_request);
	jabber_iq_send(request);
}

const JabberData *
jabber_data_find_local_by_alt(const gchar *alt)
{
	purple_debug_info("jabber", "looking up local data object with alt = %s\n", alt);
	return g_hash_table_lookup(local_data_by_alt, alt);
}

const JabberData *
jabber_data_find_local_by_cid(const gchar *cid)
{
	purple_debug_info("jabber", "lookup local data object with cid = %s\n", cid);
	return g_hash_table_lookup(local_data_by_cid, cid);
}

const JabberData *
jabber_data_find_remote_by_cid(const gchar *cid)
{
	purple_debug_info("jabber", "lookup remote data object with cid = %s\n", cid);

	return g_hash_table_lookup(remote_data_by_cid, cid);
}

void
jabber_data_associate_local(JabberData *data, const gchar *alt)
{
	purple_debug_info("jabber", "associating local data object\n alt = %s, cid = %s\n",
		alt , jabber_data_get_cid(data));
	if (alt)
		g_hash_table_insert(local_data_by_alt, g_strdup(alt), data);
	g_hash_table_insert(local_data_by_cid, g_strdup(jabber_data_get_cid(data)),
		data);
}

void
jabber_data_associate_remote(JabberData *data)
{
	purple_debug_info("jabber", "associating remote data object, cid = %s\n",
		jabber_data_get_cid(data));
	g_hash_table_insert(remote_data_by_cid, g_strdup(jabber_data_get_cid(data)),
		data);
}

void
jabber_data_parse(JabberStream *js, const char *who, JabberIqType type,
                  const char *id, xmlnode *data_node)
{
	JabberIq *result = NULL;
	const char *cid = xmlnode_get_attrib(data_node, "cid");
	const JabberData *data = cid ? jabber_data_find_local_by_cid(cid) : NULL;

	if (!data) {
		xmlnode *item_not_found = xmlnode_new("item-not-found");

		result = jabber_iq_new(js, JABBER_IQ_ERROR);
		if (who)
			xmlnode_set_attrib(result->node, "to", who);
		xmlnode_set_attrib(result->node, "id", id);
		xmlnode_insert_child(result->node, item_not_found);
	} else {
		result = jabber_iq_new(js, JABBER_IQ_RESULT);
		if (who)
			xmlnode_set_attrib(result->node, "to", who);
		xmlnode_set_attrib(result->node, "id", id);
		xmlnode_insert_child(result->node,
							 jabber_data_get_xml_definition(data));
		/* if the data object is temporary, destroy it and remove the references
		 to it */
		if (data->ephemeral) {
			g_hash_table_remove(local_data_by_cid, cid);
		}
	}
	jabber_iq_send(result);
}

void
jabber_data_init(void)
{
	purple_debug_info("jabber", "creating hash tables for data objects\n");
	local_data_by_alt = g_hash_table_new_full(g_str_hash, g_str_equal,
		g_free, NULL);
	local_data_by_cid = g_hash_table_new_full(g_str_hash, g_str_equal,
		g_free, jabber_data_delete);
	remote_data_by_cid = g_hash_table_new_full(g_str_hash, g_str_equal,
		g_free, jabber_data_delete);

	jabber_iq_register_handler("data", NS_BOB, jabber_data_parse);
}

void
jabber_data_uninit(void)
{
	purple_debug_info("jabber", "destroying hash tables for data objects\n");
	g_hash_table_destroy(local_data_by_alt);
	g_hash_table_destroy(local_data_by_cid);
	g_hash_table_destroy(remote_data_by_cid);
	local_data_by_alt = local_data_by_cid = remote_data_by_cid = NULL;
}

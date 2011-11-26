/**
 * @file ssl-gnutls.c GNUTLS SSL plugin.
 *
 * purple
 *
 * Copyright (C) 2003 Christian Hammond <chipx86@gnupdate.org>
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
#include "internal.h"
#include "debug.h"
#include "certificate.h"
#include "privatekey.h"
#include "pkcs12.h"
#include "plugin.h"
#include "sslconn.h"
#include "version.h"
#include "util.h"

#define SSL_GNUTLS_PLUGIN_ID "ssl-gnutls"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs12.h>

typedef struct
{
	gnutls_session_t session;
	guint handshake_handler;
	guint handshake_timer;
} PurpleSslGnutlsData;

static gboolean
ssl_gnutls_set_client_auth(gnutls_certificate_client_credentials cred,
				PurpleCertificate * pcrt,
				PurplePrivateKey * pkey);

#define PURPLE_SSL_GNUTLS_DATA(gsc) ((PurpleSslGnutlsData *)gsc->private_data)

static gnutls_certificate_client_credentials xcred = NULL;

/* The GNUTLS get client credentials callback does not support user supplied
   data so we have to maintain that outselves. Annoying. 
   The key is a gnutls_session_t pointer and the value is a PurpleSslConnection pointer.
*/
GHashTable *sslConnTable;

#ifdef HAVE_GNUTLS_PRIORITY_FUNCS
/* Priority strings.  The default one is, well, the default (and is always
 * set).  The hash table is of the form hostname => priority (both
 * char *).
 *
 * We only use a gnutls_priority_t for the default on the assumption that
 * that's the more common case.  Improvement patches (like matching on
 * subdomains) welcome.
 */
static gnutls_priority_t default_priority = NULL;
static GHashTable *host_priorities = NULL;
#endif

static unsigned int
gnutls_get_default_crypt_flags()
{
#if GNUTLS_VERSION_MAJOR >= 2 && GNUTLS_VERSION_MINOR >= 10
	purple_debug_info("gnutls", "Using AES 256 to encrypt.\n");
	return GNUTLS_PKCS_USE_PBES2_AES_256;
#else
	purple_debug_info("gnutls", "Using 3DES to encrypt.\n");
	return GNUTLS_PKCS_USE_PBES2_3DES;
#endif
}

/* Taken from gchecksum.c */
static gchar hex_digits[] = "0123456789abcdef";

static gchar *
hex_encode(guint8 *buf, gsize buf_len)
{
  gint len = buf_len * 2;
  gint i;
  gchar *retval;

  retval = g_new (gchar, len + 1);

  for (i = 0; i < len; i++)
    {
      guint8 byte = buf[i];

      retval[2 * i] = hex_digits[byte >> 4];
      retval[2 * i + 1] = hex_digits[byte & 0xf];
    }

  retval[len] = 0;

  return retval;
}

static void
ssl_gnutls_log(int level, const char *str)
{
	/* GnuTLS log messages include the '\n' */
	purple_debug_misc("gnutls", "lvl %d: %s", level, str);
}


/*
 * GNUTLS doesn't offer a means to pass custom context to the certificate 
 * retrieve function (yeah, not good design) so we have to declare globals
 * to hold the cert/key chosen by the user. We don't just set the 
 * gnutls_certificate_client_creds and let gnutls figure it out because servers
 * aren't good about listing all intermediate CAs in the CERTIFICATE REQUEST
 * message. This will break clients that have a cert issued by an intermediate
 * CA. We just return whatever cert the client selected instead.
 */
static gnutls_x509_crt_t client_auth_certs[1] = { NULL };
static gnutls_x509_privkey_t client_auth_key = NULL;

static int
ssl_gnutls_certificate_retrieve_function(
		gnutls_session_t session,
		const gnutls_datum_t* req_ca_dn, int nreqs,
		const gnutls_pk_algorithm_t* pk_algos, int pk_algos_length,
		gnutls_retr_st* st)
{
	if (NULL == client_auth_certs[0]) {
		purple_debug_error("gnutls", "Tried to retrieve a client cert but none was set.\n");
		return -1;
	}

	if (NULL == client_auth_key) {
		purple_debug_error("gnutls", "Tried to retrieve a client key but none was set.\n");
		return -1;
	}

	purple_debug_info("gnutls", "retrieving certificates for the ssl handshake\n");

	/* TODO: Check that client_auth_certs algo matches pk_algos */

	st->type = GNUTLS_CRT_X509;
	st->cert.x509 = client_auth_certs;
	st->ncerts = 1;
	st->key.x509 = client_auth_key;
	st->deinit_all = 0;

	return 0;
}

static void
ssl_gnutls_init_gnutls(void)
{
	const char *debug_level;
	const char *host_priorities_str;

	purple_debug_info("gnutls", "libgnutls version = %s\n", gnutls_check_version(NULL));

	debug_level = g_getenv("PURPLE_GNUTLS_DEBUG");
	if (debug_level) {
		int level = atoi(debug_level);
		if (level < 0) {
			purple_debug_warning("gnutls", "Assuming log level 0 instead of %d\n",
			                     level);
			level = 0;
		}

		/* "The level is an integer between 0 and 9. Higher values mean more verbosity." */
		gnutls_global_set_log_level(level);
		gnutls_global_set_log_function(ssl_gnutls_log);
	}

	/* Expected format: host=priority;host2=priority;*=priority
	 * where "*" is used to override the default priority string for
	 * libpurple.
	 */
	host_priorities_str = g_getenv("PURPLE_GNUTLS_PRIORITIES");
	if (host_priorities_str) {
#ifndef HAVE_GNUTLS_PRIORITY_FUNCS
		purple_debug_warning("gnutls", "Warning, PURPLE_GNUTLS_PRIORITIES "
		                     "environment variable set, but we were built "
		                     "against an older GnuTLS that doesn't support "
		                     "this. :-(");
#else /* HAVE_GNUTLS_PRIORITY_FUNCS */
		char **entries = g_strsplit(host_priorities_str, ";", -1);
		char *default_priority_str = NULL;
		guint i;

		host_priorities = g_hash_table_new_full(g_str_hash, g_str_equal,
		                                        g_free, g_free);

		for (i = 0; entries[i]; ++i) {
			char *host = entries[i];
			char *equals = strchr(host, '=');
			char *prio_str;

			if (equals) {
				*equals = '\0';
				prio_str = equals + 1;

				/* Empty? */
				if (*prio_str == '\0') {
					purple_debug_warning("gnutls", "Ignoring empty priority "
					                               "string for %s\n", host);
				} else {
					/* TODO: Validate each of these and complain */
					if (purple_strequal(host, "*")) {
						/* Override the default priority */
						g_free(default_priority_str);
						default_priority_str = g_strdup(prio_str);
					} else
						g_hash_table_insert(host_priorities, g_strdup(host),
						                    g_strdup(prio_str));
				}
			}
		}

		if (default_priority_str) {
			if (gnutls_priority_init(&default_priority, default_priority_str, NULL)) {
				purple_debug_warning("gnutls", "Unable to set default priority to %s\n",
				                     default_priority_str);
				/* Versions of GnuTLS as of 2.8.6 (2010-03-31) don't free/NULL
				 * this on error.
				 */
				gnutls_free(default_priority);
				default_priority = NULL;
			}

			g_free(default_priority_str);
		}

		g_strfreev(entries);
#endif /* HAVE_GNUTLS_PRIORITY_FUNCS */
	}

#ifdef HAVE_GNUTLS_PRIORITY_FUNCS
	/* Make sure we set have a default priority! */
	if (!default_priority) {
		if (gnutls_priority_init(&default_priority, "NORMAL:%SSL3_RECORD_VERSION", NULL)) {
			/* See comment above about memory leak */
			gnutls_free(default_priority);
			gnutls_priority_init(&default_priority, "NORMAL", NULL);
		}
	}
#endif /* HAVE_GNUTLS_PRIORITY_FUNCS */

	gnutls_global_init();

	gnutls_certificate_allocate_credentials(&xcred);

	/* TODO: I can likely remove this */
	gnutls_certificate_set_x509_trust_file(xcred, "ca.pem",
		GNUTLS_X509_FMT_PEM);
	
/*	gnutls_certificate_client_set_retrieve_function(xcred, ssl_gnutls_certificate_retrieve_function);*/
}

static gboolean
ssl_gnutls_init(void)
{
	/* Use direct hashing since the key is a pointer. */
	sslConnTable = g_hash_table_new(NULL, NULL);

	return TRUE;
}

static void
ssl_gnutls_uninit(void)
{
	g_hash_table_destroy(sslConnTable);
	gnutls_global_deinit();

	gnutls_certificate_free_credentials(xcred);
	xcred = NULL;

#ifdef HAVE_GNUTLS_PRIORITY_FUNCS
	if (host_priorities) {
		g_hash_table_destroy(host_priorities);
		host_priorities = NULL;
	}

	gnutls_priority_deinit(default_priority);
	default_priority = NULL;
#endif
}

static void
ssl_gnutls_verified_cb(PurpleCertificateVerificationStatus st,
		       gpointer userdata)
{
	PurpleSslConnection *gsc = (PurpleSslConnection *) userdata;

	if (st == PURPLE_CERTIFICATE_VALID) {
		/* Certificate valid? Good! Do the connection! */
		gsc->connect_cb(gsc->connect_cb_data, gsc, PURPLE_INPUT_READ);
	} else {
		/* Otherwise, signal an error */
		if(gsc->error_cb != NULL)
			gsc->error_cb(gsc, PURPLE_SSL_CERTIFICATE_INVALID,
				      gsc->connect_cb_data);
		purple_ssl_close(gsc);
	}
}



static void ssl_gnutls_handshake_cb(gpointer data, gint source,
		PurpleInputCondition cond)
{
	PurpleSslConnection *gsc = data;
	PurpleSslGnutlsData *gnutls_data = PURPLE_SSL_GNUTLS_DATA(gsc);
	ssize_t ret;

	/*purple_debug_info("gnutls", "Handshaking with %s\n", gsc->host);*/
	ret = gnutls_handshake(gnutls_data->session);

	if(ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
		return;

	purple_input_remove(gnutls_data->handshake_handler);
	gnutls_data->handshake_handler = 0;

	if(ret != 0) {
		purple_debug_error("gnutls", "Handshake failed. Error %s\n",
			gnutls_strerror(ret));

		if(gsc->error_cb != NULL)
			gsc->error_cb(gsc, PURPLE_SSL_HANDSHAKE_FAILED,
				gsc->connect_cb_data);

		purple_ssl_close(gsc);
	} else {
		/* Now we are cooking with gas! */
		PurpleSslOps *ops = purple_ssl_get_ops();
		GList * peers = ops->get_peer_certificates(gsc);

		PurpleCertificateScheme *x509 =
			purple_certificate_find_scheme("x509");

		GList * l;

		/* TODO: Remove all this debugging babble */
		purple_debug_info("gnutls", "Handshake complete\n");

		for (l=peers; l; l = l->next) {
			PurpleCertificate *crt = l->data;
			GByteArray *z =
				x509->get_fingerprint_sha1(crt);
			gchar * fpr =
				purple_base16_encode_chunked(z->data,
							     z->len);

			purple_debug_info("gnutls/x509",
					  "Key print: %s\n",
					  fpr);

			/* Kill the cert! */
			x509->destroy_certificate(crt);

			g_free(fpr);
			g_byte_array_free(z, TRUE);
		}
		g_list_free(peers);

		{
			const gnutls_datum_t *cert_list;
			unsigned int cert_list_size = 0;
			gnutls_session_t session=gnutls_data->session;
			guint i;

			cert_list =
				gnutls_certificate_get_peers(session, &cert_list_size);

			purple_debug_info("gnutls",
					    "Peer provided %d certs\n",
					    cert_list_size);
			for (i=0; i<cert_list_size; i++)
			{
				gchar fpr_bin[256];
				gsize fpr_bin_sz = sizeof(fpr_bin);
				gchar * fpr_asc = NULL;
				gchar tbuf[256];
				gsize tsz=sizeof(tbuf);
				gchar * tasc = NULL;
				gnutls_x509_crt_t cert;

				gnutls_x509_crt_init(&cert);
				gnutls_x509_crt_import (cert, &cert_list[i],
						GNUTLS_X509_FMT_DER);

				gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA,
						fpr_bin, &fpr_bin_sz);

				fpr_asc =
						purple_base16_encode_chunked((const guchar *)fpr_bin, fpr_bin_sz);

				purple_debug_info("gnutls",
						"Lvl %d SHA1 fingerprint: %s\n",
						i, fpr_asc);

				tsz=sizeof(tbuf);
				gnutls_x509_crt_get_serial(cert,tbuf,&tsz);
				tasc=purple_base16_encode_chunked((const guchar *)tbuf, tsz);
				purple_debug_info("gnutls",
						"Serial: %s\n",
						tasc);
				g_free(tasc);

				tsz=sizeof(tbuf);
				gnutls_x509_crt_get_dn (cert, tbuf, &tsz);
				purple_debug_info("gnutls",
						"Cert DN: %s\n",
						tbuf);
				tsz=sizeof(tbuf);
				gnutls_x509_crt_get_issuer_dn (cert, tbuf, &tsz);
				purple_debug_info("gnutls",
						"Cert Issuer DN: %s\n",
						tbuf);

				g_free(fpr_asc);
				fpr_asc = NULL;
				gnutls_x509_crt_deinit(cert);
			}
		}

		/* TODO: The following logic should really be in libpurple */
		/* If a Verifier was given, hand control over to it */
		if (gsc->verifier) {
			GList *peers;
			/* First, get the peer cert chain */
			peers = purple_ssl_get_peer_certificates(gsc);

			/* Now kick off the verification process */
			purple_certificate_verify(gsc->verifier,
						  gsc->host,
						  peers,
						  ssl_gnutls_verified_cb,
						  gsc);

			purple_certificate_destroy_list(peers);
		} else {
			/* Otherwise, just call the "connection complete"
			   callback */
			gsc->connect_cb(gsc->connect_cb_data, gsc, cond);
		}
	}

}

static gboolean
start_handshake_cb(gpointer data)
{
	PurpleSslConnection *gsc = data;
	PurpleSslGnutlsData *gnutls_data = PURPLE_SSL_GNUTLS_DATA(gsc);

	purple_debug_info("gnutls", "Starting handshake with %s\n", gsc->host);

	gnutls_data->handshake_timer = 0;

	ssl_gnutls_handshake_cb(gsc, gsc->fd, PURPLE_INPUT_READ);
	return FALSE;
}

static void
ssl_gnutls_connect(PurpleSslConnection *gsc)
{
	PurpleSslGnutlsData *gnutls_data;

	gnutls_data = g_new0(PurpleSslGnutlsData, 1);
	gsc->private_data = gnutls_data;

	gnutls_init(&gnutls_data->session, GNUTLS_CLIENT);

	/* State for the credentials retrieve function. */
	g_hash_table_insert(sslConnTable, gnutls_data->session, gsc);

#ifdef HAVE_GNUTLS_PRIORITY_FUNCS
	{
		const char *prio_str = NULL;
		gboolean set = FALSE;

		/* Let's see if someone has specified a specific priority */
		if (gsc->host && host_priorities)
			prio_str = g_hash_table_lookup(host_priorities, gsc->host);

		if (prio_str)
			set = (GNUTLS_E_SUCCESS ==
					gnutls_priority_set_direct(gnutls_data->session, prio_str,
				                               NULL));

		if (!set)
			gnutls_priority_set(gnutls_data->session, default_priority);
	}
#else
	gnutls_set_default_priority(gnutls_data->session);
#endif

	gnutls_priority_set_direct(gnutls_data->session,
		cert_type_priority, NULL);

	purple_debug_info("gnutls", "client cert id: %s cert:%p key:%p\n",
		gsc->certificate_id, gsc->certificate, gsc->key);

	if (NULL != gsc->certificate_id 
			&& NULL != gsc->certificate
			&& NULL != gsc->key) {
		purple_debug_info("gnutls/handshake",
			"Authenticating with certificate/key %s\n",
			gsc->certificate_id);
		ssl_gnutls_set_client_auth(xcred, gsc->certificate, gsc->key);
	}

	gnutls_credentials_set(gnutls_data->session, GNUTLS_CRD_CERTIFICATE,
		xcred);

	gnutls_transport_set_ptr(gnutls_data->session, GINT_TO_POINTER(gsc->fd));

	/* SNI support. */
	if (gsc->host && !g_hostname_is_ip_address(gsc->host))
		gnutls_server_name_set(gnutls_data->session, GNUTLS_NAME_DNS, gsc->host, strlen(gsc->host));

	gnutls_data->handshake_handler = purple_input_add(gsc->fd,
		PURPLE_INPUT_READ, ssl_gnutls_handshake_cb, gsc);

	/* Orborde asks: Why are we configuring a callback, then
	   (almost) immediately calling it?

	   Answer: gnutls_handshake (up in handshake_cb) needs to be called
	   once in order to get the ball rolling on the SSL connection.
	   Once it has done so, only then will the server reply, triggering
	   the callback.

	   Since the logic driving gnutls_handshake is the same with the first
	   and subsequent calls, we'll just fire the callback immediately to
	   accomplish this.
	*/
	gnutls_data->handshake_timer = purple_timeout_add(0, start_handshake_cb,
	                                                  gsc);
}

static void
ssl_gnutls_close(PurpleSslConnection *gsc)
{
	PurpleSslGnutlsData *gnutls_data = PURPLE_SSL_GNUTLS_DATA(gsc);

	if(!gnutls_data)
		return;

	if(gnutls_data->handshake_handler)
		purple_input_remove(gnutls_data->handshake_handler);
	if (gnutls_data->handshake_timer)
		purple_timeout_remove(gnutls_data->handshake_timer);

	/* Remove state needed for credential retrieve callback. */
	g_hash_table_remove(sslConnTable, gnutls_data->session);

	gnutls_bye(gnutls_data->session, GNUTLS_SHUT_RDWR);

	gnutls_deinit(gnutls_data->session);

	g_free(gnutls_data);
	gsc->private_data = NULL;
}

static size_t
ssl_gnutls_read(PurpleSslConnection *gsc, void *data, size_t len)
{
	PurpleSslGnutlsData *gnutls_data = PURPLE_SSL_GNUTLS_DATA(gsc);
	ssize_t s = 0;

	if(gnutls_data)
		s = gnutls_record_recv(gnutls_data->session, data, len);

	if(s == GNUTLS_E_AGAIN || s == GNUTLS_E_INTERRUPTED) {
		s = -1;
		errno = EAGAIN;

#ifdef GNUTLS_E_PREMATURE_TERMINATION
	} else if (s == GNUTLS_E_PREMATURE_TERMINATION) {
		purple_debug_warning("gnutls", "Received a FIN on the TCP socket "
				"for %s. This either means that the remote server closed "
				"the socket without sending us a Close Notify alert or a "
				"man-in-the-middle injected a FIN into the TCP stream. "
				"Assuming it's the former.\n", gsc->host);
#else
	} else if (s == GNUTLS_E_UNEXPECTED_PACKET_LENGTH) {
		purple_debug_warning("gnutls", "Received packet of unexpected "
				"length on the TCP socket for %s. Among other "
				"possibilities this might mean that the remote server "
				"closed the socket without sending us a Close Notify alert. "
				"Assuming that's the case for compatibility, however, note "
				"that it's quite possible that we're incorrectly ignoing "
				"a real error.\n", gsc->host);
#endif
		/*
		 * Summary:
		 * Always treat a closed TCP connection as if the remote server cleanly
		 * terminated the SSL session.
		 *
		 * Background:
		 * Most TLS servers send a Close Notify alert before sending TCP FIN
		 * when closing a session. This informs us at the TLS layer that the
		 * connection is being cleanly closed. Without this it's more
		 * difficult for us to determine whether the session was closed
		 * cleanly (we would need to resort to having the application layer
		 * perform this check, e.g. by looking at the Content-Length HTTP
		 * header for HTTP connections).
		 *
		 * There ARE servers that don't send Close Notify and we want to be
		 * compatible with them. And so we don't require Close Notify. This
		 * seems to match the behavior of libnss. This is a slightly
		 * unfortunate situation. It means a malicious MITM can inject a FIN
		 * into our TCP stream and cause our encrypted session to termiate
		 * and we won't indicate any problem to the user.
		 *
		 * GnuTLS < 3.0.0 returned the UNEXPECTED_PACKET_LENGTH error on EOF.
		 * GnuTLS >= 3.0.0 added the PREMATURE_TERMINATION error to allow us
		 * to detect the problem more specifically.
		 *
		 * For historical discussion see:
		 * https://developer.pidgin.im/ticket/16172
		 * http://trac.adiumx.com/intertrac/ticket%3A16678
		 * https://bugzilla.mozilla.org/show_bug.cgi?id=508698#c4
		 * http://lists.gnu.org/archive/html/gnutls-devel/2008-03/msg00058.html
		 * Or search for GNUTLS_E_UNEXPECTED_PACKET_LENGTH or
		 * GNUTLS_E_PREMATURE_TERMINATION
		 */
		s = 0;

	} else if(s < 0) {
		purple_debug_error("gnutls", "receive failed: %s\n",
				gnutls_strerror(s));
		s = -1;
		/*
		 * TODO: Set errno to something more appropriate.  Or even
		 *       better: allow ssl plugins to keep track of their
		 *       own error message, then add a new ssl_ops function
		 *       that returns the error message.
		 */
		errno = EIO;
	}

	return s;
}

static size_t
ssl_gnutls_write(PurpleSslConnection *gsc, const void *data, size_t len)
{
	PurpleSslGnutlsData *gnutls_data = PURPLE_SSL_GNUTLS_DATA(gsc);
	ssize_t s = 0;

	/* XXX: when will gnutls_data be NULL? */
	if(gnutls_data)
		s = gnutls_record_send(gnutls_data->session, data, len);

	if(s == GNUTLS_E_AGAIN || s == GNUTLS_E_INTERRUPTED) {
		s = -1;
		errno = EAGAIN;
	} else if(s < 0) {
		purple_debug_error("gnutls", "send failed: %s\n",
				gnutls_strerror(s));
		s = -1;
		/*
		 * TODO: Set errno to something more appropriate.  Or even
		 *       better: allow ssl plugins to keep track of their
		 *       own error message, then add a new ssl_ops function
		 *       that returns the error message.
		 */
		errno = EIO;
	}

	return s;
}

/* Forward declarations are fun! */
static PurpleCertificate *
x509_import_from_datum(const gnutls_datum_t dt, gnutls_x509_crt_fmt_t mode);
/* indeed! */
static gboolean
x509_certificate_signed_by(PurpleCertificate * crt,
			   PurpleCertificate * issuer);
static void
x509_destroy_certificate(PurpleCertificate * crt);

static GList *
ssl_gnutls_get_peer_certificates(PurpleSslConnection * gsc)
{
	PurpleSslGnutlsData *gnutls_data = PURPLE_SSL_GNUTLS_DATA(gsc);
	PurpleCertificate *prvcrt = NULL;

	/* List of Certificate instances to return */
	GList * peer_certs = NULL;

	/* List of raw certificates as given by GnuTLS */
	const gnutls_datum_t *cert_list;
	unsigned int cert_list_size = 0;

	unsigned int i;

	/* This should never, ever happen. */
	g_return_val_if_fail( gnutls_certificate_type_get (gnutls_data->session) == GNUTLS_CRT_X509, NULL);

	/* Get the certificate list from GnuTLS */
	/* TODO: I am _pretty sure_ this doesn't block or do other exciting things */
	cert_list = gnutls_certificate_get_peers(gnutls_data->session,
						 &cert_list_size);

	/* Convert each certificate to a Certificate and append it to the list */
	for (i = 0; i < cert_list_size; i++) {
		PurpleCertificate * newcrt = x509_import_from_datum(cert_list[i],
							      GNUTLS_X509_FMT_DER);
		/* Append is somewhat inefficient on linked lists, but is easy
		   to read. If someone complains, I'll change it.
		   TODO: Is anyone complaining? (Maybe elb?) */
		/* only append if previous cert was actually signed by this one.
		 * Thanks Microsoft. */
		if ((newcrt != NULL) && ((prvcrt == NULL) || x509_certificate_signed_by(prvcrt, newcrt))) {
			peer_certs = g_list_append(peer_certs, newcrt);
			prvcrt = newcrt;
		} else {
			x509_destroy_certificate(newcrt);
			purple_debug_error("gnutls", "Dropping further peer certificates "
			                             "because the chain is broken!\n");
			break;
		}
	}

	/* cert_list doesn't need free()-ing */

	return peer_certs;
}

 
/************************************************************************/
/* X.509 functionality                                                  */
/************************************************************************/
const gchar * SCHEME_NAME = "x509";

static PurpleCertificateScheme x509_gnutls;

/** Refcounted GnuTLS certificate data instance */
typedef struct {
	gint refcount;
	gnutls_x509_crt_t crt;
} x509_crtdata_t;

/** Helper functions for reference counting */
static x509_crtdata_t *
x509_crtdata_addref(x509_crtdata_t *cd)
{
	(cd->refcount)++;
	return cd;
}

static void
x509_crtdata_delref(x509_crtdata_t *cd)
{
	(cd->refcount)--;

	if (cd->refcount < 0)
		g_critical("Refcount of x509_crtdata_t is %d, which is less "
				"than zero!\n", cd->refcount);

	/* If the refcount reaches zero, kill the structure */
	if (cd->refcount <= 0) {
		/* Kill the internal data */
		gnutls_x509_crt_deinit( cd->crt );
		/* And kill the struct */
		g_free( cd );
	}
}

/** Helper macro to retrieve the GnuTLS crt_t from a PurpleCertificate */
#define X509_GET_GNUTLS_DATA(pcrt) ( ((x509_crtdata_t *) ((pcrt)->data))->crt)

/** Transforms a gnutls_datum containing an X.509 certificate into a Certificate instance under the x509_gnutls scheme.
 *
 * @param dt   Datum to transform
 * @param mode GnuTLS certificate format specifier (GNUTLS_X509_FMT_PEM for
 *             reading from files, and GNUTLS_X509_FMT_DER for converting
 *             "over the wire" certs for SSL)
 *
 * @return A newly allocated Certificate structure of the x509_gnutls scheme
 */
static PurpleCertificate *
x509_import_from_datum(const gnutls_datum_t dt, gnutls_x509_crt_fmt_t mode)
{
	/* Internal certificate data structure */
	x509_crtdata_t *certdat;
	/* New certificate to return */
	PurpleCertificate * crt;

	/* Allocate and prepare the internal certificate data */
	certdat = g_new0(x509_crtdata_t, 1);
	if (gnutls_x509_crt_init(&(certdat->crt)) != 0) {
		g_free(certdat);
		return NULL;
	}
	certdat->refcount = 0;

	/* Perform the actual certificate parse */
	/* Yes, certdat->crt should be passed as-is */
	if (gnutls_x509_crt_import(certdat->crt, &dt, mode) != 0) {
		g_free(certdat);
		return NULL;
	}

	/* Allocate the certificate and load it with data */
	crt = g_new0(PurpleCertificate, 1);
	crt->scheme = &x509_gnutls;
	crt->data = x509_crtdata_addref(certdat);

	return crt;
}

/** Imports a PEM-formatted X.509 certificate from the specified file.
 * @param filename Filename to import from. Format is PEM
 *
 * @return A newly allocated Certificate structure of the x509_gnutls scheme
 */
static PurpleCertificate *
x509_import_from_file(const gchar * filename)
{
	PurpleCertificate *crt;  /* Certificate being constructed */
	gchar *buf;        /* Used to load the raw file data */
	gsize buf_sz;      /* Size of the above */
	gnutls_datum_t dt; /* Struct to pass down to GnuTLS */

	purple_debug_info("gnutls",
			  "Attempting to load X.509 certificate from %s\n",
			  filename);

	/* Next, we'll simply yank the entire contents of the file
	   into memory */
	/* TODO: Should I worry about very large files here? */
	if (!g_file_get_contents(filename,
			&buf,
			&buf_sz,
			NULL      /* No error checking for now */
			)) {
		return NULL;
	}

	/* Load the datum struct */
	dt.data = (unsigned char *) buf;
	dt.size = buf_sz;

	/* Perform the conversion; files should be in PEM format */
	crt = x509_import_from_datum(dt, GNUTLS_X509_FMT_PEM);

	/* Cleanup */
	g_free(buf);

	return crt;
}

/** Imports a number of PEM-formatted X.509 certificates from the specified file.
 * @param filename Filename to import from. Format is PEM
 *
 * @return A newly allocated GSList of Certificate structures of the x509_gnutls scheme
 */
static GSList *
x509_importcerts_from_file(const gchar * filename)
{
	PurpleCertificate *crt;  /* Certificate being constructed */
	gchar *buf;        /* Used to load the raw file data */
	gchar *begin, *end;
	GSList *crts = NULL;
	gsize buf_sz;      /* Size of the above */
	gnutls_datum_t dt; /* Struct to pass down to GnuTLS */

	purple_debug_info("gnutls",
			  "Attempting to load X.509 certificates from %s\n",
			  filename);

	/* Next, we'll simply yank the entire contents of the file
	   into memory */
	/* TODO: Should I worry about very large files here? */
	g_return_val_if_fail(
		g_file_get_contents(filename,
			    &buf,
			    &buf_sz,
			    NULL      /* No error checking for now */
		),
		NULL);

	begin = buf;
	while((end = strstr(begin, "-----END CERTIFICATE-----")) != NULL) {
		end += sizeof("-----END CERTIFICATE-----")-1;
		/* Load the datum struct */
		dt.data = (unsigned char *) begin;
		dt.size = (end-begin);

		/* Perform the conversion; files should be in PEM format */
		crt = x509_import_from_datum(dt, GNUTLS_X509_FMT_PEM);
		if (crt != NULL) {
			crts = g_slist_prepend(crts, crt);
		}
		begin = end;
	}

	/* Cleanup */
	g_free(buf);

	return crts;
}

/**
 * Exports a PEM-formatted X.509 certificate to the specified file.
 * @param filename Filename to export to. Format will be PEM
 * @param crt      Certificate to export
 *
 * @return TRUE if success, otherwise FALSE
 */
static gboolean
x509_export_certificate(const gchar *filename, PurpleCertificate *crt)
{
	gnutls_x509_crt_t crt_dat; /* GnuTLS cert struct */
	int ret;
	gchar * out_buf; /* Data to output */
	size_t out_size; /* Output size */
	gboolean success = FALSE;

	/* Paranoia paranoia paranoia! */
	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(crt->scheme == &x509_gnutls, FALSE);
	g_return_val_if_fail(crt->data, FALSE);

	crt_dat = X509_GET_GNUTLS_DATA(crt);

	/* Obtain the output size required */
	out_size = 0;
	ret = gnutls_x509_crt_export(crt_dat, GNUTLS_X509_FMT_PEM,
				     NULL, /* Provide no buffer yet */
				     &out_size /* Put size here */
		);
	g_return_val_if_fail(ret == GNUTLS_E_SHORT_MEMORY_BUFFER, FALSE);

	/* Now allocate a buffer and *really* export it */
	out_buf = g_new0(gchar, out_size);
	ret = gnutls_x509_crt_export(crt_dat, GNUTLS_X509_FMT_PEM,
				     out_buf, /* Export to our new buffer */
				     &out_size /* Put size here */
		);
	if (ret != 0) {
		purple_debug_error("gnutls/x509",
				   "Failed to export cert to buffer with code %d\n",
				   ret);
		g_free(out_buf);
		return FALSE;
	}

	/* Write it out to an actual file */
	success = purple_util_write_data_to_file_absolute(filename,
							  out_buf, out_size);

	g_free(out_buf);
	return success;
}

static PurpleCertificate *
x509_copy_certificate(PurpleCertificate *crt)
{
	x509_crtdata_t *crtdat;
	PurpleCertificate *newcrt;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_gnutls, NULL);

	crtdat = (x509_crtdata_t *) crt->data;

	newcrt = g_new0(PurpleCertificate, 1);
	newcrt->scheme = &x509_gnutls;
	newcrt->data = x509_crtdata_addref(crtdat);

	return newcrt;
}
/** Frees a Certificate
 *
 * Destroys a Certificate's internal data structures and frees the pointer
 * given.
 * @param crt Certificate instance to be destroyed. It WILL NOT be destroyed
 *            if it is not of the correct CertificateScheme. Can be NULL
 *
 */
static void
x509_destroy_certificate(PurpleCertificate * crt)
{
	if (NULL == crt) return;

	/* Check that the scheme is x509_gnutls */
	if ( crt->scheme != &x509_gnutls ) {
		purple_debug_error("gnutls",
				   "destroy_certificate attempted on certificate of wrong scheme (scheme was %s, expected %s)\n",
				   crt->scheme->name,
				   SCHEME_NAME);
		return;
	}

	g_return_if_fail(crt->data != NULL);
	g_return_if_fail(crt->scheme != NULL);

	/* Use the reference counting system to free (or not) the
	   underlying data */
	x509_crtdata_delref((x509_crtdata_t *)crt->data);

	/* Kill the structure itself */
	g_free(crt);
}

/** Determines whether one certificate has been issued and signed by another
 *
 * @param crt       Certificate to check the signature of
 * @param issuer    Issuer's certificate
 *
 * @return TRUE if crt was signed and issued by issuer, otherwise FALSE
 * @TODO  Modify this function to return a reason for invalidity?
 */
static gboolean
x509_certificate_signed_by(PurpleCertificate * crt,
			   PurpleCertificate * issuer)
{
	gnutls_x509_crt_t crt_dat;
	gnutls_x509_crt_t issuer_dat;
	unsigned int verify; /* used to store result from GnuTLS verifier */
	int ret;
	gchar *crt_id = NULL;
	gchar *issuer_id = NULL;

	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(issuer, FALSE);

	/* Verify that both certs are the correct scheme */
	g_return_val_if_fail(crt->scheme == &x509_gnutls, FALSE);
	g_return_val_if_fail(issuer->scheme == &x509_gnutls, FALSE);

	/* TODO: check for more nullness? */

	crt_dat = X509_GET_GNUTLS_DATA(crt);
	issuer_dat = X509_GET_GNUTLS_DATA(issuer);

	/* Ensure crt issuer matches the name on the issuer cert. */
	ret = gnutls_x509_crt_check_issuer(crt_dat, issuer_dat);
	if (ret <= 0) {

		if (ret < 0) {
			purple_debug_error("gnutls/x509",
					   "GnuTLS error %d while checking certificate issuer match.",
					   ret);
		} else {
			gchar *crt_id, *issuer_id, *crt_issuer_id;
			crt_id = purple_certificate_get_unique_id(crt);
			issuer_id = purple_certificate_get_unique_id(issuer);
			crt_issuer_id =
				purple_certificate_get_issuer_unique_id(crt);
			purple_debug_info("gnutls/x509",
					  "Certificate %s is issued by "
					  "%s, which does not match %s.\n",
					  crt_id ? crt_id : "(null)",
					  crt_issuer_id ? crt_issuer_id : "(null)",
					  issuer_id ? issuer_id : "(null)");
			g_free(crt_id);
			g_free(issuer_id);
			g_free(crt_issuer_id);
		}

		/* The issuer is not correct, or there were errors */
		return FALSE;
	}

	/* Check basic constraints extension (if it exists then the CA flag must
	   be set to true, and it must exist for certs with version 3 or higher. */
	ret = gnutls_x509_crt_get_basic_constraints(issuer_dat, NULL, NULL, NULL);
	if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
		if (gnutls_x509_crt_get_version(issuer_dat) >= 3) {
			/* Reject cert (no basic constraints and cert version is >= 3). */
			gchar *issuer_id = purple_certificate_get_unique_id(issuer);
			purple_debug_info("gnutls/x509", "Rejecting cert because the "
					"basic constraints extension is missing from issuer cert "
					"for %s. The basic constraints extension is required on "
					"all version 3 or higher certs (this cert is version %d).",
					issuer_id ? issuer_id : "(null)",
					gnutls_x509_crt_get_version(issuer_dat));
			g_free(issuer_id);
			return FALSE;
		} else {
			/* Allow cert (no basic constraints and cert version is < 3). */
			purple_debug_info("gnutls/x509", "Basic constraint extension is "
					"missing from issuer cert for %s. Allowing this because "
					"the cert is version %d and the basic constraints "
					"extension is only required for version 3 or higher "
					"certs.", issuer_id ? issuer_id : "(null)",
					gnutls_x509_crt_get_version(issuer_dat));
		}
	} else if (ret <= 0) {
		/* Reject cert (CA flag is false in basic constraints). */
		gchar *issuer_id = purple_certificate_get_unique_id(issuer);
		purple_debug_info("gnutls/x509", "Rejecting cert because the CA flag "
				"is set to false in the basic constraints extension for "
				"issuer cert %s. ret=%d\n",
				issuer_id ? issuer_id : "(null)", ret);
		g_free(issuer_id);
		return FALSE;
	}

	/* Now, check the signature */
	/* The second argument is a ptr to an array of "trusted" issuer certs,
	   but we're only using one trusted one */
	ret = gnutls_x509_crt_verify(crt_dat, &issuer_dat, 1,
				     /* Permit signings by X.509v1 certs
					(Verisign and possibly others have
					root certificates that predate the
					current standard) */
				     GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT,
				     &verify);

	if (ret != 0) {
		purple_debug_error("gnutls/x509",
				   "Attempted certificate verification caused a GnuTLS error code %d. I will just say the signature is bad, but you should look into this.\n", ret);
		return FALSE;
	}

#ifdef HAVE_GNUTLS_CERT_INSECURE_ALGORITHM
	if (verify & GNUTLS_CERT_INSECURE_ALGORITHM) {
		/*
		 * A certificate in the chain is signed with an insecure
		 * algorithm. Put a warning into the log to make this error
		 * perfectly clear as soon as someone looks at the debug log is
		 * generated.
		 */
		crt_id = purple_certificate_get_unique_id(crt);
		issuer_id = purple_certificate_get_issuer_unique_id(crt);
		purple_debug_warning("gnutls/x509",
				"Insecure hash algorithm used by %s to sign %s\n",
				issuer_id, crt_id);
	}
#endif

	if (verify & GNUTLS_CERT_INVALID) {
		/* Signature didn't check out, but at least
		   there were no errors*/
		if (!crt_id)
			crt_id = purple_certificate_get_unique_id(crt);
		if (!issuer_id)
			issuer_id = purple_certificate_get_issuer_unique_id(crt);
		purple_debug_error("gnutls/x509",
				  "Bad signature from %s on %s\n",
				  issuer_id, crt_id);
		g_free(crt_id);
		g_free(issuer_id);

		return FALSE;
	} /* if (ret, etc.) */

	/* If we got here, the signature is good */
	return TRUE;
}

static GByteArray *
x509_shasum(PurpleCertificate *crt, gnutls_digest_algorithm_t algo)
{
	size_t hashlen = (algo == GNUTLS_DIG_SHA1) ? 20 : 32;
	size_t tmpsz = hashlen; /* Throw-away variable for GnuTLS to stomp on*/
	gnutls_x509_crt_t crt_dat;
	GByteArray *hash; /**< Final hash container */
	guchar hashbuf[hashlen]; /**< Temporary buffer to contain hash */

	g_return_val_if_fail(crt, NULL);

	crt_dat = X509_GET_GNUTLS_DATA(crt);

	/* Extract the fingerprint */
	g_return_val_if_fail(
		0 == gnutls_x509_crt_get_fingerprint(crt_dat, algo,
						     hashbuf, &tmpsz),
		NULL);

	/* This shouldn't happen */
	g_return_val_if_fail(tmpsz == hashlen, NULL);

	/* Okay, now create and fill hash array */
	hash = g_byte_array_new();
	g_byte_array_append(hash, hashbuf, hashlen);

	return hash;
}

static GByteArray *
x509_sha1sum(PurpleCertificate *crt)
{
	return x509_shasum(crt, GNUTLS_DIG_SHA1);
}

static GByteArray *
x509_sha256sum(PurpleCertificate *crt)
{
	return x509_shasum(crt, GNUTLS_DIG_SHA256);
}

static gchar *
x509_cert_dn (PurpleCertificate *crt)
{
	gnutls_x509_crt_t cert_dat;
	gchar *dn = NULL;
	size_t dn_size;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_gnutls, NULL);

	cert_dat = X509_GET_GNUTLS_DATA(crt);

	/* Figure out the length of the Distinguished Name */
	/* Claim that the buffer is size 0 so GnuTLS just tells us how much
	   space it needs */
	dn_size = 0;
	gnutls_x509_crt_get_dn(cert_dat, dn, &dn_size);

	/* Now allocate and get the Distinguished Name */
	/* Old versions of GnuTLS have an off-by-one error in reporting
	   the size of the needed buffer in some functions, so allocate
	   an extra byte */
	dn = g_new0(gchar, ++dn_size);
	if (0 != gnutls_x509_crt_get_dn(cert_dat, dn, &dn_size)) {
		purple_debug_error("gnutls/x509",
				   "Failed to get Distinguished Name\n");
		g_free(dn);
		return NULL;
	}

	return dn;
}

static gchar *
x509_issuer_dn (PurpleCertificate *crt)
{
	gnutls_x509_crt_t cert_dat;
	gchar *dn = NULL;
	size_t dn_size;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_gnutls, NULL);

	cert_dat = X509_GET_GNUTLS_DATA(crt);

	/* Figure out the length of the Distinguished Name */
	/* Claim that the buffer is size 0 so GnuTLS just tells us how much
	   space it needs */
	dn_size = 0;
	gnutls_x509_crt_get_issuer_dn(cert_dat, dn, &dn_size);

	/* Now allocate and get the Distinguished Name */
	/* Old versions of GnuTLS have an off-by-one error in reporting
	   the size of the needed buffer in some functions, so allocate
	   an extra byte */
	dn = g_new0(gchar, ++dn_size);
	if (0 != gnutls_x509_crt_get_issuer_dn(cert_dat, dn, &dn_size)) {
		purple_debug_error("gnutls/x509",
				   "Failed to get issuer's Distinguished "
				   "Name\n");
		g_free(dn);
		return NULL;
	}

	return dn;
}

static gchar *
x509_common_name (PurpleCertificate *crt)
{
	gnutls_x509_crt_t cert_dat;
	gchar *cn = NULL;
	size_t cn_size;
	int ret;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_gnutls, NULL);

	cert_dat = X509_GET_GNUTLS_DATA(crt);

	/* Figure out the length of the Common Name */
	/* Claim that the buffer is size 0 so GnuTLS just tells us how much
	   space it needs */
	cn_size = 0;
	gnutls_x509_crt_get_dn_by_oid(cert_dat,
				      GNUTLS_OID_X520_COMMON_NAME,
				      0, /* First CN found, please */
				      0, /* Not in raw mode */
				      cn, &cn_size);

	/* Now allocate and get the Common Name */
	/* Old versions of GnuTLS have an off-by-one error in reporting
	   the size of the needed buffer in some functions, so allocate
	   an extra byte */
	cn = g_new0(gchar, ++cn_size);
	ret = gnutls_x509_crt_get_dn_by_oid(cert_dat,
					    GNUTLS_OID_X520_COMMON_NAME,
					    0, /* First CN found, please */
					    0, /* Not in raw mode */
					    cn, &cn_size);
	if (ret != 0) {
		purple_debug_error("gnutls/x509",
				   "Failed to get Common Name\n");
		g_free(cn);
		return NULL;
	}

	return cn;
}

static gboolean
x509_check_name (PurpleCertificate *crt, const gchar *name)
{
	gnutls_x509_crt_t crt_dat;

	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(crt->scheme == &x509_gnutls, FALSE);
	g_return_val_if_fail(name, FALSE);

	crt_dat = X509_GET_GNUTLS_DATA(crt);

	if (gnutls_x509_crt_check_hostname(crt_dat, name)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

static gboolean
x509_times (PurpleCertificate *crt, time_t *activation, time_t *expiration)
{
	gnutls_x509_crt_t crt_dat;
	/* GnuTLS time functions return this on error */
	const time_t errval = (time_t) (-1);
	gboolean success = TRUE;

	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(crt->scheme == &x509_gnutls, FALSE);

	crt_dat = X509_GET_GNUTLS_DATA(crt);

	if (activation) {
		*activation = gnutls_x509_crt_get_activation_time(crt_dat);
		if (*activation == errval)
			success = FALSE;
	}
	if (expiration) {
		*expiration = gnutls_x509_crt_get_expiration_time(crt_dat);
		if (*expiration == errval)
			success = FALSE;
	}

	return success;
}

/* GNUTLS_KEYID_USE_BEST_KNOWN was added in gnutls 3.4.1, but can't ifdef it
 * because it's an enum member. Older versions will ignore it, which means
 * using SHA1 instead of SHA256 to compare pubkeys. But hey, not my fault. */
#if GNUTLS_VERSION_NUMBER < 0x030401
#define KEYID_FLAG (1<<30)
#else
#define KEYID_FLAG GNUTLS_KEYID_USE_BEST_KNOWN
#endif


/* X.509 certificate operations provided by this plugin */
static PurpleCertificateScheme x509_gnutls = {
	"x509",                          /* Scheme name */
	N_("X.509 Certificates"),        /* User-visible scheme name */
	x509_import_from_file,           /* Certificate import function */
	x509_export_certificate,         /* Certificate export function */
	x509_copy_certificate,           /* Copy */
	x509_destroy_certificate,        /* Destroy cert */
	x509_certificate_signed_by,      /* Signature checker */
	x509_sha1sum,                    /* SHA1 fingerprint */
	x509_cert_dn,                    /* Unique ID */
	x509_issuer_dn,                  /* Issuer Unique ID */
	x509_common_name,                /* Subject name */
	x509_check_name,                 /* Check subject name */
	x509_times,                      /* Activation/Expiration time */
	x509_importcerts_from_file,      /* Multiple certificates import function */

	NULL,
	NULL,
	sizeof(PurpleCertificateScheme), /* struct_size */
	x509_sha256sum,                  /* SHA256 fingerprint */
	x509_compare_pubkeys,            /* Compare public keys */
};

/**********************************************************
 * X.509 Private Key operations                           *
 **********************************************************/

const gchar * KEY_SCHEME_NAME = "x509";

static PurplePrivateKeyScheme x509_key_gnutls;

/** Refcounted GnuTLS private key data instance */
typedef struct {
	gint refcount;
	gnutls_x509_privkey_t key;
} x509_keydata_t;

/** Helper functions for reference counting */
static x509_keydata_t *
x509_keydata_addref(x509_keydata_t *kd)
{
	(kd->refcount)++;
	return kd;
}

static void
x509_keydata_delref(x509_keydata_t *kd)
{
	(kd->refcount)--;

	if (kd->refcount < 0)
		g_critical("Refcount of x509_keydata_t is %d, which is less "
				"than zero!\n", kd->refcount);

	/* If the refcount reaches zero, kill the structure */
	if (kd->refcount <= 0) {
		/* Kill the internal data */
		if (kd->key) {
			purple_debug_info("gnutls", "deinit gnutls_x509_privkey_t %p\n", kd->key);
			gnutls_x509_privkey_deinit( kd->key );
		}
		purple_debug_info("gnutls", "free x509_key_data_t\n");
		/* And kill the struct */
		g_free( kd );
	}
}

/** Helper macro to retrieve the GnuTLS crt_t from a PurplePrivateKey */
#define X509_GET_GNUTLS_KEYDATA(pkey) ( ((x509_keydata_t *) (pkey->data))->key)

static gboolean
read_pkcs8_file(const gchar* filename, gnutls_datum_t *dt, gnutls_x509_crt_fmt_t * fmt)
{
	gchar *buf = NULL; /* Used to load the raw file data */
	gsize buf_sz;      /* Size of the above */

	purple_debug_info("gnutls/x509key",
			  "Attempting to load PKCS8 file from %s\n",
			  filename);

	/* Next, we'll simply yank the entire contents of the file
	   into memory */
	/* TODO: Should I worry about very large files here? */
	if (!g_file_get_contents(filename,
			&buf, &buf_sz, NULL /* No error checking for now */)) {
		if (buf != NULL) g_free(buf);
		return FALSE;
	}
	
	*fmt = GNUTLS_X509_FMT_DER;
	#define PEM_PKCS8_HDR "-----BEGIN ENCRYPTED PRIVATE KEY-----"
	if (0 == strncmp(buf, PEM_PKCS8_HDR, sizeof(PEM_PKCS8_HDR)-1)) 
		*fmt = GNUTLS_X509_FMT_PEM;

	dt->data = (unsigned char*) buf;
	dt->size = buf_sz;

	return TRUE;
}

static PurplePrivateKey*
x509_import_key(const gchar * filename, const gchar * password)
{
	/* Internal key data structure */
	x509_keydata_t *keydat;
	/* New key to return */
	PurplePrivateKey * key;
	gnutls_datum_t dt;
	gnutls_x509_crt_fmt_t fmt;
	int rv;

	/* Allocate and prepare the internal key data */
	keydat = g_new0(x509_keydata_t, 1);
	if (GNUTLS_E_SUCCESS != gnutls_x509_privkey_init(&keydat->key)) {
		g_free(keydat);
		return NULL;
	}
	keydat->refcount = 0;

	key = g_new0(PurplePrivateKey, 1);
	key->scheme = &x509_key_gnutls;
	key->data = x509_keydata_addref(keydat); 

	if (read_pkcs8_file(filename, &dt, &fmt)) {
		rv = gnutls_x509_privkey_import_pkcs8(keydat->key, &dt, fmt, password, 0);
		g_free(dt.data);
		purple_debug_info("gnutls", "New gnutls_x509_privkey_t %p\n", keydat->key);
		if (GNUTLS_E_SUCCESS != rv) {
			purple_debug_error("gnutls/x509key",
					   "Error importing key from %s: %s\n",
					   filename, gnutls_strerror(rv));
			gnutls_x509_privkey_deinit(keydat->key);
			g_free(keydat);
			g_free(key);
			return NULL;
		}
	}

	return key;
}

static gboolean 
x509_export_key(const gchar *filename, PurplePrivateKey *key, const gchar* password)
{
	gnutls_x509_privkey_t key_dat; /* GnuTLS key struct */
	int ret;
	gchar * out_buf; /* Data to output */
	size_t out_size; /* Output size */
	gboolean success = FALSE;
	unsigned int flags;

	/* Paranoia paranoia paranoia! */
	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(key->scheme == &x509_key_gnutls, FALSE);
	g_return_val_if_fail(key->data, FALSE);

	key_dat = X509_GET_GNUTLS_KEYDATA(key);

	flags = gnutls_get_default_crypt_flags();

	/* Obtain the output size required */
	out_size = 0;
	ret = gnutls_x509_privkey_export_pkcs8(key_dat, GNUTLS_X509_FMT_PEM,
					       password,
					       flags,
	 				       NULL, /* Provide no buffer yet */
					       &out_size /* Put size here */);
	purple_debug_error("gnutls/x509key", "querying for size and export pkcs8 returned (%d) %s with size %zd\n",
			ret, gnutls_strerror(ret), out_size);
	g_return_val_if_fail(ret == GNUTLS_E_SHORT_MEMORY_BUFFER, FALSE);

	/* Now allocate a buffer and *really* export it */

	/* TODO: Again we seem to randomly get a "just not quite big enough" size above. */
	out_size += 100;

	out_buf = g_new0(gchar, out_size);
	ret = gnutls_x509_privkey_export_pkcs8(key_dat, GNUTLS_X509_FMT_PEM,
					       password,
					       flags,
					       out_buf, /* Export to our new buffer */
					       &out_size /* Put size here */);

	if (GNUTLS_E_SUCCESS != ret) {
		purple_debug_error("gnutls/x509key",
				   "Failed to export key to buffer:%s\n",
				   gnutls_strerror(ret));
		g_free(out_buf);
		return FALSE;
	}

	/* Write it out to an actual file */
	success = purple_util_write_data_to_file_absolute(filename,
							  out_buf, out_size);

	g_free(out_buf);
	return success;
}

static PurplePrivateKey *
x509_copy_key(PurplePrivateKey *key)
{
	x509_keydata_t *keydat;
	PurplePrivateKey *newkey;

	g_return_val_if_fail(key, NULL);
	g_return_val_if_fail(key->scheme == &x509_key_gnutls, NULL);

	keydat = (x509_keydata_t *) key->data;

	newkey = g_new0(PurplePrivateKey, 1);
	newkey->scheme = &x509_key_gnutls;
	newkey->data = x509_keydata_addref(keydat);

	return newkey;
}

static void 
x509_destroy_key(PurplePrivateKey * key)
{
	if (NULL == key) return;
	
	g_return_if_fail(key->data != NULL);
	g_return_if_fail(key->scheme != NULL);

	/* Check that the scheme is x509_key_gnutls */
	if ( key->scheme != &x509_key_gnutls ) {
		purple_debug_error("gnutls",
				   "destroy_key attempted on key of wrong scheme (scheme was %s, expected %s)\n",
				   key->scheme->name,
				   KEY_SCHEME_NAME);
		return;
	}

	purple_debug_info("gnutls", "Destroying PurplePrivateKey\n");
	/* Use the reference counting system to free (or not) the
	   underlying data */
	x509_keydata_delref((x509_keydata_t *)key->data);

	/* Kill the structure itself */
	g_free(key);
	return;
}

static gchar*
x509_get_unique_key_id(PurplePrivateKey *key)
{
	gnutls_x509_privkey_t key_dat; /* GnuTLS key struct */
	int ret;
	guchar * out_buf = NULL; /* Data to output */
	size_t out_size = 0; /* Output size */
	gchar* id;

	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(key->scheme == &x509_key_gnutls, FALSE);
	g_return_val_if_fail(key->data, FALSE);

	key_dat = X509_GET_GNUTLS_KEYDATA(key);

	/* Get output size */
	ret = gnutls_x509_privkey_get_key_id(key_dat, 0, NULL, &out_size);

	g_return_val_if_fail(ret == GNUTLS_E_SHORT_MEMORY_BUFFER, NULL);

	out_buf = g_new0(guchar, out_size);

	ret = gnutls_x509_privkey_get_key_id(key_dat, 0, out_buf, &out_size);
	if (GNUTLS_E_SUCCESS != ret) {
		purple_debug_error("gnutls/x509key",
				   "Failed to get key id: %s\n",
				   gnutls_strerror(ret));
		g_free(out_buf);
		return NULL;
	}

	id = hex_encode(out_buf, out_size);
	g_free(out_buf);
	return id;
}

static PurplePrivateKeyScheme x509_key_gnutls = {
	"x509",                           /* Scheme name */
	N_("X.509 Private Keys"),         /* User-visibile scheme name */
	x509_import_key,                  /* Key import */
	x509_export_key,                  /* Key export */
        x509_copy_key,                    /* Copy key */
	x509_destroy_key,                 /* Destroy key */
	x509_get_unique_key_id,           /* Get key id */

	NULL,
	NULL,
	NULL
};

/**********************************************************
 *  PKCS12 operations                                     *
 **********************************************************/

/**
 * Borrowed from gnutls_x509.c.  This is only exposed via:
 *  gnutls_certificate_set_x509_simple_pkcs12_mem
 *  gnutls_certificate_set_x509_simple_pkcs12_file
 * which operate on a gnutls_credentials object. However, purple
 * prefers to directly manage its own certificates and (now) keys.
 * PKCS12 is complex so we should use code that (probably) already
 * works.
 *
 * Adding a keystore abstraction would probably be better. Let each
 * SSL crypto backend supply its own keystore???
 */

static int
parse_pkcs12(gnutls_pkcs12_t p12,
	     const char *password,
	     GList **keys, /* gnutls_x509_privkey_t */
	     GList **crts, /* gnutls_x509_crt_t */
	     GList **crls) /* gnutlx_x509_crl_t */
{
	gnutls_pkcs12_bag_t bag = NULL;
	int idx = 0;
	int ret;
/*
	size_t cert_id_size = 0;
	size_t key_id_size = 0;
	unsigned char cert_id[20];
	unsigned char key_id[20];
*/
	int privkey_ok = 0;

	gnutls_x509_crt_t cert = NULL;
	gnutls_x509_privkey_t key = NULL;
	gnutls_x509_crl_t crl = NULL;

	g_return_val_if_fail(keys, -1);

	/* find the first private key */
	for (;;) {
		int elements_in_bag;
		int i;

		ret = gnutls_pkcs12_bag_init(&bag);
		if (ret < 0) {
			bag = NULL;
			purple_debug_error("gnutls/pkcs12",
				"Error initing pkcs12 bag\n");
			goto done;
		}

		ret = gnutls_pkcs12_get_bag(p12, idx, bag);
		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;
		if (ret < 0) {
			purple_debug_error("gnutls/pkcs12",
				"Error getting bag %d from pkcs12\n", idx);
			goto done;
		}

		ret = gnutls_pkcs12_bag_get_type(bag, 0);
		if (ret < 0) {
			purple_debug_error("gnutls/pkcs12",
				"Error getting type for bag %d\n", idx);
			goto done;
		}

		if (ret == GNUTLS_BAG_ENCRYPTED) {
			ret = gnutls_pkcs12_bag_decrypt(bag, password);
			if (ret < 0) {
				purple_debug_error("gnutls/pkcs12",
					"Error decrypting bag %d\n", idx);
				goto done;
			}
		}

		elements_in_bag = gnutls_pkcs12_bag_get_count(bag);
		if (elements_in_bag < 0) {
			purple_debug_error("gnutls/pkcs12",
				"Error getting count for bag %d\n", idx);
			goto done;
		}

		for (i = 0; i < elements_in_bag; i++) {
			int type;
			gnutls_datum_t data;

			type = gnutls_pkcs12_bag_get_type(bag, i);
			if (type < 0) {
				purple_debug_error("gnutls/pkcs12",
					"Error getting type for item %d in bag %d\n", i, idx);
				goto done;
			}

			ret = gnutls_pkcs12_bag_get_data(bag, i, &data);
			if (ret < 0) {
				purple_debug_error("gnutls/pkcs12",
					"Error getting item %d from bag %d\n", i, idx);
				goto done;
			}

			switch (type) {
			case GNUTLS_BAG_PKCS8_ENCRYPTED_KEY:
			case GNUTLS_BAG_PKCS8_KEY:
				if (privkey_ok == 1) { /* too simple to continue */
					purple_debug_error("gnutls/pkcs12",
						"Already found a key.\n");
					break;
				}

				ret = gnutls_x509_privkey_init(&key);
				if (ret < 0) {
					purple_debug_error("gnutls/pkcs12",
						"Failed to init x509_privkey.\n");
					goto done;
				}

				ret = gnutls_x509_privkey_import_pkcs8(
					key, &data, GNUTLS_X509_FMT_DER, password,
					type == GNUTLS_BAG_PKCS8_KEY ? GNUTLS_PKCS_PLAIN : 0);
				if (ret < 0) {
					purple_debug_error("gnutls/pkcs12",
						"Failed to import pkcs8 key from item %d in bag %d\n", i, idx);
					gnutls_x509_privkey_deinit(key);
					goto done;
				}

				purple_debug_info("gnutls/pkcs12",
					"Found key in item %d of bag %d\n", i, idx);
				*keys = g_list_append(*keys, key);
#if 0
				key_id_size = sizeof (key_id);
				ret = gnutls_x509_privkey_get_key_id(
					*key, 0, key_id, &key_id_size);
				if (ret < 0) {
					purple_debug_error("gnutls/pkcs12",
						"Failed to get key id from bag %d\n", idx);
					gnutls_x509_privkey_deinit (*key);
					goto done;
				}
#endif
				privkey_ok = 1;	/* break */
				break;
			default:
				break;
			}
		}

		idx++;
		gnutls_pkcs12_bag_deinit(bag);

		if (privkey_ok != 0)	/* private key was found */
			break;
	}

	if (privkey_ok == 0) {/* no private key */
		purple_debug_error("gnutls/pkcs12",
			"No private key found in pkcs12 file\n");
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	/* now find the corresponding certificate 
	*/
	idx = 0;
	bag = NULL;
	for (;;) {
		int elements_in_bag;
		int i;

		ret = gnutls_pkcs12_bag_init(&bag);
		if (ret < 0) {
			bag = NULL;
			purple_debug_error("gnutls/pkcs12",
				"pkcs12 bag init failed\n");
			goto done;
		}

		ret = gnutls_pkcs12_get_bag(p12, idx, bag);
		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;
		if (ret < 0) {
			purple_debug_error("gnutls/pkcs12",
				"Failed to to get bag %d\n", idx);
			goto done;
		}

		ret = gnutls_pkcs12_bag_get_type(bag, 0);
		if (ret < 0) {
			purple_debug_error("gnutls/pkcs12",
				"Failed getting type for bag %d\n", idx);
			goto done;
		}


		if (ret == GNUTLS_BAG_ENCRYPTED) {
			ret = gnutls_pkcs12_bag_decrypt(bag, password);
			if (ret < 0) {
				purple_debug_error("gnutls/pkcs12",
					"Failed to decrypt bag %d\n", idx);
				goto done;
			}
		}

		elements_in_bag = gnutls_pkcs12_bag_get_count(bag);
		if (elements_in_bag < 0) {
			purple_debug_error("gnutls/pkcs12",
				"Failed getting count for bag %d\n", idx);
			goto done;
		}

		for (i = 0; i < elements_in_bag; i++) {
			int type;
			gnutls_datum_t data;

			type = gnutls_pkcs12_bag_get_type(bag, i);
			if (type < 0) {
				purple_debug_error("gnutls/pkcs12",
					"Failed getting type for item %d in bag %d\n", i, idx);
				goto done;
			}

			ret = gnutls_pkcs12_bag_get_data(bag, i, &data);
			if (ret < 0) {
				purple_debug_error("gnutls/pkcs12",
					"Failed getting item %d from bag %d\n", i, idx);
				goto done;
			}

			switch (type) {
			case GNUTLS_BAG_CERTIFICATE:
#if 0
				if (*cert != NULL) {	/* no need to set it again */
					purple_debug_error("gnutls/pkcs12","");
					break;
				}
#endif
				/* Ignore certs if we didn't provide a list */
				if (crts == NULL)
					break;

				ret = gnutls_x509_crt_init(&cert);
	 			if (ret < 0) {
					purple_debug_error("gnutls/pkcs12",
						"Failed init x509_crt\n");
					goto done;
				}

				ret = gnutls_x509_crt_import(
					cert, &data, GNUTLS_X509_FMT_DER);
				if (ret < 0) {
					purple_debug_error("gnutls/pkcs12",
						"Failed importing cert from item %d in bag %d\n", i, idx);
					gnutls_x509_crt_deinit (cert);
					goto done;
				}

				purple_debug_info("gnutls/pkcs12",
					"Found cert in item %d of bag %d\n", i, idx);
				*crts = g_list_append(*crts, cert);
#if 0
				/* check if the key id match */
				cert_id_size = sizeof (cert_id);
				ret = gnutls_x509_crt_get_key_id(
					*cert, 0, cert_id, &cert_id_size);
				if (ret < 0) {
					purple_debug_error("gnutls/pkcs12","");();
					gnutls_x509_crt_deinit (*cert);
					goto done;
				}

				if (memcmp (cert_id, key_id, cert_id_size) != 0) {
					/* they don't match - skip the certificate */
					gnutls_x509_crt_deinit (*cert);
					*cert = NULL;
				}
#endif
				break;

			case GNUTLS_BAG_CRL:
#if 0
				if (crl != NULL) {
					purple_debug_error("gnutls/pkcs12","");();
					break;
				}
#endif
				/* Ignore crls if we didn't provide a list */
				if (crls == NULL)
					break;

				ret = gnutls_x509_crl_init(&crl);
				if (ret < 0) {
					purple_debug_error("gnutls/pkcs12",
						"Failed init x509_crl\n");
					goto done;
				}

				ret = gnutls_x509_crl_import(crl, &data, GNUTLS_X509_FMT_DER);
				if (ret < 0) {
					purple_debug_error("gnutls/pkcs12",
						"Failed importing crl from item %d in bag %d\n", i, idx);
					gnutls_x509_crl_deinit (crl);
					goto done;
				}

				purple_debug_info("gnutls/pkcs12",
					"Found crl in item %d of bag %d\n", i, idx);
				*crls = g_list_append(*crls, crl);
				break;

			case GNUTLS_BAG_ENCRYPTED:
				/* XXX Bother to recurse one level down?  Unlikely to
				   use the same password anyway. */
		 	case GNUTLS_BAG_EMPTY:
			default:
				break;
		 	}
		}

		idx++;
		gnutls_pkcs12_bag_deinit (bag);
	 }

	ret = 0;

done:
	if (bag)
		gnutls_pkcs12_bag_deinit (bag);

	return ret;
}

static gboolean
read_pkcs12_file(const gchar* filename, gnutls_datum_t *dt, gnutls_x509_crt_fmt_t * fmt)
{
	gchar *buf = NULL; /* Used to load the raw file data */
	gsize buf_sz;      /* Size of the above */

	purple_debug_info("gnutls",
			  "Attempting to load PKCS12 file from %s\n",
			  filename);

	/* Next, we'll simply yank the entire contents of the file
	   into memory */
	/* TODO: Should I worry about very large files here? */
	g_return_val_if_fail(
		g_file_get_contents(filename,
			    &buf,
			    &buf_sz,
			    NULL      /* No error checking for now */
		),
		FALSE);
	
	*fmt = GNUTLS_X509_FMT_DER;
	#define PEM_PKCS12_HDR "-----BEGIN PKCS12-----"
	if (0 == strncmp(buf, PEM_PKCS12_HDR, sizeof(PEM_PKCS12_HDR)-1)) 
		*fmt = GNUTLS_X509_FMT_PEM;

	dt->data = (unsigned char*) buf;
	dt->size = buf_sz;

	return TRUE;
}


static void
add_to_purple_crt_list(gpointer data, gpointer user_data)
{
	gnutls_x509_crt_t crt = (gnutls_x509_crt_t)data;
	GList **pcrts = (GList**)user_data;
	x509_crtdata_t *crtdat;
	PurpleCertificate *pcrt;

	g_return_if_fail(NULL != data);

	crtdat = g_new0(x509_crtdata_t, 1);
	crtdat->crt = crt;
	crtdat->refcount = 0;

	pcrt = g_new0(PurpleCertificate, 1);
	pcrt->scheme = &x509_gnutls;
	pcrt->data = x509_crtdata_addref(crtdat);

	*pcrts = g_list_append(*pcrts, pcrt);
}

static PurplePrivateKey*
create_purple_privatekey_from_privkey(gnutls_x509_privkey_t key)
{
	x509_keydata_t *keydat;
	PurplePrivateKey *pkey;

	g_return_val_if_fail(NULL != key, NULL);

	keydat = g_new0(x509_keydata_t, 1);
	keydat->key = key;
	keydat->refcount = 0;

	pkey = g_new0(PurplePrivateKey, 1);
	pkey->scheme = &x509_key_gnutls;
	pkey->data = x509_keydata_addref(keydat);

	return pkey;
}

/**
 * Derived from gnutls_certificate_set_x509_simple_pkcs12_mem in
 * gnutls_x509.c. Modified to return PurpleCertificate and PurplePrivateKey
 * objects.
 */
static gboolean
x509_import_pkcs12_from_file(const gchar* filename,
			     const gchar* password,
			     GList **pcrts, /* PurpleCertificate */
			     PurplePrivateKey **pkey)
{
	gnutls_pkcs12_t p12;
	gnutls_datum_t dt;
	gnutls_x509_crt_fmt_t fmt;
	GList *crts = NULL;
	GList *keys = NULL;
	gnutls_x509_privkey_t key;

	int rv;

	if (!read_pkcs12_file(filename, &dt, &fmt)) {
		purple_debug_error("gnutls",
			"Failed to load PKCS12 file from %s\n",
			filename);
		g_free(dt.data);
		return FALSE;
	}

	purple_debug_info("gnutls", "pkcs12 import: file:%s size:%d fmt:%d\n", filename, dt.size, fmt);
 
	rv = gnutls_pkcs12_init (&p12);
	if (GNUTLS_E_SUCCESS != rv) {
		purple_debug_error("gnutls/x509",
			"pkcs12_init error: %s\n", gnutls_strerror(rv));
		g_free(dt.data);
		return FALSE;
	}

	rv = gnutls_pkcs12_import(p12, &dt, fmt, 0);
	g_free(dt.data);
	if (GNUTLS_E_SUCCESS != rv) {
		purple_debug_error("gnutls/x509",
			"pkcs12_import error: %s\n", gnutls_strerror(rv));
 		gnutls_pkcs12_deinit (p12);
		return FALSE;
	}

	if (password) {
		rv = gnutls_pkcs12_verify_mac(p12, (const char*)password);
		if (GNUTLS_E_SUCCESS != rv) {
			purple_debug_error("gnutls/x509",
				"pkcs12_verify_mac error: %s\n", gnutls_strerror(rv));
			gnutls_pkcs12_deinit (p12);
			return FALSE;
		}
 	}
		
	rv = parse_pkcs12(p12, password, &keys, &crts, NULL);

	if (GNUTLS_E_SUCCESS != rv) {
		purple_debug_error("gnutls/x509",
			"parse_pkcs12 error: %s\n", gnutls_strerror(rv));
		return FALSE;
	}

	purple_debug_info("gnutls/x509",
		"Found %d keys and %d certs in pkcs12\n",
		g_list_length(keys), g_list_length(crts));

	if (g_list_length(keys) != 1) {
		purple_debug_error("gnutls/x509",
			"Only support one private key in pkcs12 file. Found %d\n",
			g_list_length(keys));
		g_list_free_full(keys, (GDestroyNotify)gnutls_x509_privkey_deinit);
		g_list_free_full(crts, (GDestroyNotify)gnutls_x509_crt_deinit);
		return FALSE;
	}

	key = (gnutls_x509_privkey_t)(g_list_first(keys)->data);
	*pkey = create_purple_privatekey_from_privkey(key);
	g_list_foreach(crts, add_to_purple_crt_list, pcrts);

	/* check if the key and certificate found match */
#if 0 /* TODO ljf */
	if (key && (ret = _gnutls_check_key_cert_match (res)) < 0) {
		gnutls_assert ();
		to done;
	}
#endif

	return TRUE;
}

/** Export PurpleCertificate and PurplePrivateKey to a PKCS12 file.
 */
/* Derived from generate_pkcs12() in certtool.c in the gnutls source. */
static gboolean
x509_export_pkcs12_to_filename(const gchar* filename, const gchar* password,
			       GList *pcrts, PurplePrivateKey *pkey)
{
	gnutls_pkcs12_t pkcs12 = NULL;
	gnutls_x509_crt_t crt = NULL;
	gnutls_x509_privkey_t key = NULL;
	int result;
	size_t size;
	gnutls_datum_t data;
	const char *name;
	unsigned int flags;
	gnutls_datum_t key_id;
	unsigned char _key_id[20];
	int indx;
	gboolean success = FALSE;
	gnutls_pkcs12_bag_t kbag = NULL;
	gnutls_pkcs12_bag_t bag = NULL;
	char *key_buf = NULL;
	char *out_buf = NULL;
	GList *item = NULL;

	result = gnutls_pkcs12_init (&pkcs12);
	if (result < 0) {
		purple_debug_error("gnutls/pkcs12",
			"export: pkcs12_init: %s\n", gnutls_strerror (result));
		goto done;
	}

	result = gnutls_pkcs12_bag_init (&bag);
	if (result < 0) {
		purple_debug_error("gnutls/pkcs12",
			"export: bag_init: %s\n", gnutls_strerror (result));
		goto done;
	}

	for (item = g_list_first(pcrts); NULL != item; item = g_list_next(item)) {
		PurpleCertificate *pcrt = (PurpleCertificate*)item->data;

		crt = X509_GET_GNUTLS_DATA(pcrt);

		name = x509_common_name(pcrt);
		if (NULL == name) {
			purple_debug_error("gnutls/pkcs12",
				"export: can't get common name for cert\n");
			goto done;
		}

		result = gnutls_pkcs12_bag_set_crt (bag, crt);
		if (result < 0) {
			purple_debug_error ("gnutls/pkcs12", "export: set_crt: %s\n",
				 gnutls_strerror (result));
			goto done;
		}

		indx = result;

		result = gnutls_pkcs12_bag_set_friendly_name (bag, indx, name);
		if (result < 0) {
			purple_debug_error ("gnutls/pkcs12", "bag_set_friendly_name: %s\n",
				gnutls_strerror (result));
			goto done;
		}

		size = sizeof (_key_id);
		result = gnutls_x509_crt_get_key_id (crt, KEYID_FLAG, _key_id, &size);
		if (result < 0) {
			purple_debug_error("gnutls/pkcs12", "key_id: %s\n", 
				 gnutls_strerror(result));
			goto done;
		}

		key_id.data = _key_id;
		key_id.size = size;

		result = gnutls_pkcs12_bag_set_key_id (bag, indx, &key_id);
		if (result < 0) {
			purple_debug_error("gnutls/pkcs12", "bag_set_key_id: %s\n",
				 gnutls_strerror(result));
			goto done;
		}
	}

#if 0
	flags = gnutls_get_default_crypt_flags();
	/* Should we be encrypting the certs?? Don't see why we should. */
	result = gnutls_pkcs12_bag_encrypt (bag, password, flags);
	if (result < 0) {
		purple_debug_error("gnutls/pkcs12", "bag_encrypt: %s\n", gnutls_strerror (result));
		goto done;
	}
#endif
	result = gnutls_pkcs12_set_bag (pkcs12, bag);
	if (result < 0) {
		purple_debug_error("gnutls/pkcs12", "set_bag: %s\n", gnutls_strerror (result));
		goto done;
	}

	gnutls_pkcs12_bag_deinit(bag);
	bag = NULL;

	/* XXX Assume one key */

	result = gnutls_pkcs12_bag_init (&kbag);
	if (result < 0) {
		purple_debug_error("gnutls/pkcs12", "bag_init: %s\n", gnutls_strerror (result));
		goto done;
	}

	key = X509_GET_GNUTLS_KEYDATA(pkey);

	flags = gnutls_get_default_crypt_flags();
	size = 0;
	result = gnutls_x509_privkey_export_pkcs8 (key, GNUTLS_X509_FMT_DER,
					password, flags, NULL, &size);

	if (result != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		purple_debug_error("gnutls/pkcs12", "Can't get pkcs8 memory size.\n");
		goto done;
	}

	purple_debug_info("gnutls/pkcs12", "Got pkcs8 export memory size = %zd\n", size);

	size = 2 * size;
	key_buf = g_new0(char, size);

	result = gnutls_x509_privkey_export_pkcs8 (key, GNUTLS_X509_FMT_DER,
					password, flags, key_buf, &size);
	if (result < 0) {
		purple_debug_error("gnutls/pkcs12", "key_export: size: %zd; error: %s\n",
			size, gnutls_strerror (result));
		goto done;
	}

	data.data = (unsigned char*)key_buf;
	data.size = size;
	result = gnutls_pkcs12_bag_set_data (kbag,
			GNUTLS_BAG_PKCS8_ENCRYPTED_KEY, &data);
	if (result < 0) {
		purple_debug_error("gnutls/pkcs12", "bag_set_data: %s\n", gnutls_strerror (result));
		goto done;
	}

	indx = result;

	name = x509_common_name((PurpleCertificate*)(g_list_first(pcrts)->data));
	if (NULL == name) {
		purple_debug_error("gnutls/pkcs12",
			"export: can't get common name for key's cert\n");
		goto done;
	}

	result = gnutls_pkcs12_bag_set_friendly_name (kbag, indx, name);
	if (result < 0) {
		purple_debug_error("gnutls/pkcs12", "bag_set_friendly_name: %s\n",
			 gnutls_strerror(result));
		goto done;
	}

	size = sizeof (_key_id);
	result = gnutls_x509_privkey_get_key_id (key, KEYID_FLAG, _key_id, &size);
	if (result < 0) {
		purple_debug_error("gnutls/pkcs12", "key_id: %s\n", gnutls_strerror (result));
		goto done;
	}

	key_id.data = _key_id;
	key_id.size = size;

	result = gnutls_pkcs12_bag_set_key_id (kbag, indx, &key_id);
	if (result < 0) {
		purple_debug_error("gnutls/pkcs12", "bag_set_key_id: %s\n",
			 gnutls_strerror(result));
		goto done;
	}

	result = gnutls_pkcs12_set_bag (pkcs12, kbag);
	if (result < 0) {
		purple_debug_error("gnutls/pkcs12", "set_bag: %s\n", gnutls_strerror (result));
		goto done;
	}

	result = gnutls_pkcs12_generate_mac (pkcs12, password);
	if (result < 0) {
		purple_debug_error("gnutls/pkcs12", "generate_mac: %s\n", gnutls_strerror (result));
		goto done;
	}

	size = 0;
	result = gnutls_pkcs12_export (pkcs12, GNUTLS_X509_FMT_PEM, NULL, &size);

	if (result != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		purple_debug_error("gnutls/pkcs12", "Can't get pkcs12 memory size.\n");
		goto done;
	}

	out_buf = g_new0(char, size);

	result = gnutls_pkcs12_export (pkcs12, GNUTLS_X509_FMT_PEM, out_buf, &size);
	if (result < 0) {
		purple_debug_error("gnutls/pkcs12", "pkcs12_export: %s\n", gnutls_strerror (result));
		goto done;
	}

	success = purple_util_write_data_to_file_absolute(filename,
							  out_buf, size);

done:
	g_free(key_buf);
	g_free(out_buf);
	gnutls_pkcs12_bag_deinit(bag);
	gnutls_pkcs12_bag_deinit(kbag);
	gnutls_pkcs12_deinit(pkcs12);

	return success;
}

static gboolean 
pkcs12_import(const gchar *filename, const gchar *password,
	      GList **crts, PurplePrivateKey **key)
{
	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(password, FALSE);
	g_return_val_if_fail(crts, FALSE);
	g_return_val_if_fail(key, FALSE);


	return x509_import_pkcs12_from_file(filename, password, crts, key);
}

static gboolean 
pkcs12_export(const gchar *filename, const gchar *password,
	      GList *crts, PurplePrivateKey *key)
{
	GList *i = NULL;

	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(password, FALSE);

	g_return_val_if_fail(NULL != crts, FALSE);
	g_return_val_if_fail(NULL != key, FALSE);
	g_return_val_if_fail(key->scheme == &x509_key_gnutls, FALSE);

	for (i = g_list_first(crts); NULL != i; i = g_list_next(i)) {
		PurpleCertificate *crt = (PurpleCertificate*)i->data;
		g_return_val_if_fail(crt->scheme == &x509_gnutls, FALSE);
	}

	return x509_export_pkcs12_to_filename(filename, password, crts, key);
}


static PurplePkcs12Scheme pkcs12_gnutls = {
	"pkcs12",                         /* Scheme name */
	N_("PKCS12"),                     /* User-visible scheme name */
	pkcs12_import,                    /* PKCS12 import */
	pkcs12_export,                    /* PKCS12 export */

	NULL,
	NULL,
	NULL
};

/**********************************************************************
 * Setting the Purple Certificate and Private Key for authentication  *
 **********************************************************************/

/**
 * This attempts to add all certs in pcrt's cert chain as the certs
 * are available. It will look in all our cert pools for issuers and
 * add them to the creds.
 */
static gboolean
ssl_gnutls_set_client_auth(gnutls_certificate_client_credentials cred,
		PurpleCertificate * pcrt, PurplePrivateKey * pkey)
{
	gnutls_x509_crt_t *cert_list;
	int rv;
	PurpleCertificatePool *user_pool = NULL;
	GList *crts = NULL;
	int numcrts = 0;
	GList *item = NULL;
	gchar *id = NULL;
	int idx = 0;

	g_return_val_if_fail(pcrt, FALSE);
	g_return_val_if_fail(pkey, FALSE);
	g_return_val_if_fail(pcrt->scheme == &x509_gnutls, FALSE);
	g_return_val_if_fail(pkey->scheme == &x509_key_gnutls, FALSE);

	user_pool = purple_certificate_find_pool("x509", "user");
	g_return_val_if_fail(user_pool, FALSE);

	if (NULL != xcred) {
#if 0
		/* Set global state for creds to return when server 
		 * requests a client certificate */
		client_auth_certs[0] = X509_GET_GNUTLS_DATA(pcrt);
		client_auth_key = X509_GET_GNUTLS_KEYDATA(pkey);
#endif

		id = purple_certificate_get_unique_id(pcrt);
		crts = purple_certificate_pool_retrieve_chain(user_pool, id, NULL);
		if (NULL == crts) {
			purple_debug_error("gnutls/ssl", "Failed to get cert chain %s for auth\n", id);
			return FALSE;
		}

		numcrts = g_list_length(crts);
		cert_list = g_new0(gnutls_x509_crt_t, numcrts);
		for (idx=0, item=g_list_first(crts); NULL != item; item = g_list_next(item),idx+=1) {
			cert_list[idx] = X509_GET_GNUTLS_DATA((PurpleCertificate*)(item->data));
		}

		purple_debug_info("gnutls/ssl", "Added %d crts and 1 key to creds\n", numcrts);

		rv = gnutls_certificate_set_x509_key(cred, cert_list, numcrts, X509_GET_GNUTLS_KEYDATA(pkey));
		if (GNUTLS_E_SUCCESS != rv) {
			purple_debug_error("gnutls/ssl",
					  "Failed to set add certs to credentials: %s\n",
					  gnutls_strerror(rv));
			g_free(cert_list);
			return FALSE;
		}
		g_free(cert_list);
		return TRUE;
	}

	return FALSE;
}

static PurpleSslOps ssl_ops =
{
	ssl_gnutls_init,
	ssl_gnutls_uninit,
	ssl_gnutls_connect,
	ssl_gnutls_close,
	ssl_gnutls_read,
	ssl_gnutls_write,
	ssl_gnutls_get_peer_certificates,

	/* padding */
	NULL,
	NULL,
	NULL
};

static gboolean
plugin_load(PurplePlugin *plugin)
{
	if(!purple_ssl_get_ops()) {
		purple_ssl_set_ops(&ssl_ops);
	}

	/* Init GNUTLS now so others can use it even if sslconn never does */
	ssl_gnutls_init_gnutls();

	/* Register that we're providing an X.509 CertScheme */
	purple_certificate_register_scheme( &x509_gnutls );
	purple_privatekey_register_scheme( &x509_key_gnutls );
	purple_pkcs12_register_scheme( &pkcs12_gnutls );

	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	if(purple_ssl_get_ops() == &ssl_ops) {
		purple_ssl_set_ops(NULL);
	}

	purple_certificate_unregister_scheme( &x509_gnutls );
	purple_privatekey_unregister_scheme( &x509_key_gnutls );
	purple_pkcs12_unregister_scheme( &pkcs12_gnutls );

	return TRUE;
}

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_STANDARD,                             /**< type           */
	NULL,                                             /**< ui_requirement */
	PURPLE_PLUGIN_FLAG_INVISIBLE,                       /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                            /**< priority       */

	SSL_GNUTLS_PLUGIN_ID,                             /**< id             */
	N_("GNUTLS"),                                     /**< name           */
	DISPLAY_VERSION,                                  /**< version        */
	                                                  /**  summary        */
	N_("Provides SSL support through GNUTLS."),
	                                                  /**  description    */
	N_("Provides SSL support through GNUTLS."),
	"Christian Hammond <chipx86@gnupdate.org>",
	PURPLE_WEBSITE,                                     /**< homepage       */

	plugin_load,                                      /**< load           */
	plugin_unload,                                    /**< unload         */
	NULL,                                             /**< destroy        */

	NULL,                                             /**< ui_info        */
	NULL,                                             /**< extra_info     */
	NULL,                                             /**< prefs_info     */
	NULL,                                             /**< actions        */

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin)
{
}

PURPLE_INIT_PLUGIN(ssl_gnutls, init_plugin, info)

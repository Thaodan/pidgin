/*
 * Gaim's oscar protocol plugin
 * This file is the legal property of its developers.
 * Please see the AUTHORS file distributed alongside this file.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 * Oscar File transfer (OFT) and Oscar Direct Connect (ODC).
 * (ODC is also referred to as DirectIM and IM Image.)
 *
 * There are a few static helper functions at the top, then
 * ODC stuff, then ft stuff.
 *
 * I feel like this is a good place to explain OFT, so I'm going to
 * do just that.  Each OFT packet has a header type.  I guess this
 * is pretty similar to the subtype of a SNAC packet.  The type
 * basically tells the other client the meaning of the OFT packet.
 * There are two distinct types of file transfer, which I usually
 * call "sendfile" and "getfile."  Sendfile is when you send a file
 * to another AIM user.  Getfile is when you share a group of files,
 * and other users request that you send them the files.
 *
 * A typical sendfile file transfer goes like this:
 *   1) Sender sends a channel 2 ICBM telling the other user that
 *      we want to send them a file.  At the same time, we open a
 *      listener socket (this should be done before sending the
 *      ICBM) on some port, and wait for them to connect to us.
 *      The ICBM we sent should contain our IP address and the port
 *      number that we're listening on.
 *   2) The receiver connects to the sender on the given IP address
 *      and port.  After the connection is established, the receiver
 *      sends an ICBM signifying that we are ready and waiting.
 *   3) The sender sends an OFT PROMPT message over the OFT
 *      connection.
 *   4) The receiver of the file sends back an exact copy of this
 *      OFT packet, except the cookie is filled in with the cookie
 *      from the ICBM.  I think this might be an attempt to verify
 *      that the user that is connected is actually the guy that
 *      we sent the ICBM to.  Oh, I've been calling this the ACK.
 *   5) The sender starts sending raw data across the connection
 *      until the entire file has been sent.
 *   6) The receiver knows the file is finished because the sender
 *      sent the file size in an earlier OFT packet.  So then the
 *      receiver sends the DONE thingy (after filling in the
 *      "received" checksum and size) and closes the connection.
 */

#ifdef HAVE_CONFIG_H
#include  <config.h>
#endif

#include "oscar.h"
#include "peer.h"

#ifndef _WIN32
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/utsname.h> /* for aim_odc_initiate */
#include <arpa/inet.h> /* for inet_ntoa */
#include <limits.h> /* for UINT_MAX */
#define G_DIR_SEPARATOR '/'
#endif

#ifdef _WIN32
#include "win32dep.h"
#endif

/*
 * I really want to switch all our networking code to using IPv6 only,
 * but that really isn't a good idea at all.  Evan S. of Adium says
 * OS X sets all connections as "AF_INET6/PF_INET6," even if there is
 * nothing inherently IPv6 about them.  And I feel like Linux kernel
 * 2.6.5 is doing the same thing.  So we REALLY should accept
 * connections if they're showing up as IPv6.  Old OSes (Solaris?)
 * that might not have full IPv6 support yet will fail if we try
 * to use PF_INET6 but it isn't defined.  --Mark Doliner
 */
#ifndef PF_INET6
#define PF_INET6 PF_INET
#endif

struct aim_odc_intdata {
	guint8 cookie[8];
	char sn[MAXSNLEN+1];
	char ip[22];
};

/**
 * Convert the directory separator from / (0x2f) to ^A (0x01)
 *
 * @param name The filename to convert.
 */
static void
aim_oft_dirconvert_tostupid(char *name)
{
	while (name[0]) {
		if (name[0] == 0x01)
			name[0] = G_DIR_SEPARATOR;
		name++;
	}
}

/**
 * Convert the directory separator from ^A (0x01) to / (0x2f)
 *
 * @param name The filename to convert.
 */
static void
aim_oft_dirconvert_fromstupid(char *name)
{
	while (name[0]) {
		if (name[0] == G_DIR_SEPARATOR)
			name[0] = 0x01;
		name++;
	}
}

/**
 * Calculate oft checksum of buffer
 *
 * Prevcheck should be 0xFFFF0000 when starting a checksum of a file.  The
 * checksum is kind of a rolling checksum thing, so each time you get bytes
 * of a file you just call this puppy and it updates the checksum.  You can
 * calculate the checksum of an entire file by calling this in a while or a
 * for loop, or something.
 *
 * Thanks to Graham Booker for providing this improved checksum routine,
 * which is simpler and should be more accurate than Josh Myer's original
 * code. -- wtm
 *
 * This algorithm works every time I have tried it.  The other fails
 * sometimes.  So, AOL who thought this up?  It has got to be the weirdest
 * checksum I have ever seen.
 *
 * @param buffer Buffer of data to checksum.  Man I'd like to buff her...
 * @param bufsize Size of buffer.
 * @param prevcheck Previous checksum.
 */
guint32
aim_oft_checksum_chunk(const guint8 *buffer, int bufferlen, guint32 prevcheck)
{
	guint32 check = (prevcheck >> 16) & 0xffff, oldcheck;
	int i;
	unsigned short val;

	for (i=0; i<bufferlen; i++) {
		oldcheck = check;
		if (i&1)
			val = buffer[i];
		else
			val = buffer[i] << 8;
		check -= val;
		/*
		 * The following appears to be necessary.... It happens
		 * every once in a while and the checksum doesn't fail.
		 */
		if (check > oldcheck)
			check--;
	}
	check = ((check & 0x0000ffff) + (check >> 16));
	check = ((check & 0x0000ffff) + (check >> 16));
	return check << 16;
}

guint32
aim_oft_checksum_file(char *filename)
{
	FILE *fd;
	guint32 checksum = 0xffff0000;

	if ((fd = fopen(filename, "rb"))) {
		int bytes;
		guint8 buffer[1024];

		while ((bytes = fread(buffer, 1, 1024, fd)))
			checksum = aim_oft_checksum_chunk(buffer, bytes, checksum);
		fclose(fd);
	}

	return checksum;
}

/**
 * After establishing a listening socket, this is called to accept a connection.  It
 * clones the conn used by the listener, and passes both of these to a signal handler.
 * The signal handler should close the listener conn and keep track of the new conn,
 * since this is what is used for file transfers and what not.
 *
 * @param sess The session.
 * @param cur The conn the incoming connection is on.
 * @return Return 0 if no errors, otherwise return the error number.
 */
int
aim_handlerendconnect(OscarSession *sess, OscarConnection *cur)
{
	int acceptfd = 0;
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	int ret = 0;
	OscarConnection *newconn;
	char ip[20];
	unsigned short port;

	if ((acceptfd = accept(cur->fd, &addr, &addrlen)) == -1)
		return 0; /* not an error */

	if ((addr.sa_family != PF_INET) && (addr.sa_family != PF_INET6)) {
		close(acceptfd);
		aim_conn_close(cur);
		return -1;
	}

	strncpy(ip, inet_ntoa(((struct sockaddr_in *)&addr)->sin_addr), sizeof(ip));
	port = ntohs(((struct sockaddr_in *)&addr)->sin_port);

	if (!(newconn = aim_cloneconn(sess, cur))) {
		close(acceptfd);
		aim_conn_close(cur);
		return -ENOMEM;
	}

	newconn->type = AIM_CONN_TYPE_RENDEZVOUS;
	newconn->fd = acceptfd;

	if (newconn->subtype == AIM_CONN_SUBTYPE_OFT_DIRECTIM) {
		aim_rxcallback_t userfunc;
		struct aim_odc_intdata *priv;

		priv = (struct aim_odc_intdata *)(newconn->internal = cur->internal);
		cur->internal = NULL;
		snprintf(priv->ip, sizeof(priv->ip), "%s:%hu", ip, port);

		if ((userfunc = aim_callhandler(sess, newconn, AIM_CB_FAM_OFT, PEER_TYPE_DIRECTIM_ESTABLISHED)))
			ret = userfunc(sess, NULL, newconn, cur);

	} else if (newconn->subtype == AIM_CONN_SUBTYPE_OFT_GETFILE) {
	} else if (newconn->subtype == AIM_CONN_SUBTYPE_OFT_SENDFILE) {
		aim_rxcallback_t userfunc;

		if ((userfunc = aim_callhandler(sess, newconn, AIM_CB_FAM_OFT, PEER_TYPE_ESTABLISHED)))
			ret = userfunc(sess, NULL, newconn, cur);

	} else {
		gaim_debug_warning("oscar", "Got a connection on a listener that's not rendezvous.  Closing connection.\n");
		aim_conn_close(newconn);
		ret = -1;
	}

	return ret;
}

/**
 * Send client-to-client typing notification over an established direct connection.
 *
 * @param sess The session.
 * @param conn The already-connected ODC connection.
 * @param typing If 0x0002, sends a "typing" message, 0x0001 sends "typed," and
 *        0x0000 sends "stopped."
 * @return Return 0 if no errors, otherwise return the error number.
 */
int
aim_odc_send_typing(OscarSession *sess, OscarConnection *conn, int typing)
{
	struct aim_odc_intdata *intdata = (struct aim_odc_intdata *)conn->internal;
	FlapFrame *fr;
	ByteStream *hdrbs;
	guint8 *hdr;
	int hdrlen = 0x44;

	if (!sess || !conn || (conn->type != AIM_CONN_TYPE_RENDEZVOUS))
		return -EINVAL;

	if (!(fr = aim_tx_new(sess, conn, AIM_FRAMETYPE_OFT, 0x0001, 0)))
		return -ENOMEM;
	memcpy(fr->hdr.rend.magic, "ODC2", 4);
	fr->hdr.rend.hdrlen = hdrlen + 8;

	if (!(hdr = calloc(1, hdrlen))) {
		aim_frame_destroy(fr);
		return -ENOMEM;
	}

	hdrbs = &(fr->data);
	aim_bstream_init(hdrbs, hdr, hdrlen);

	aimbs_put16(hdrbs, 0x0006);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_putraw(hdrbs, intdata->cookie, 8);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put32(hdrbs, 0x00000000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);

	if (typing == 0x0002)
		aimbs_put16(hdrbs, 0x0002 | 0x0008);
	else if (typing == 0x0001)
		aimbs_put16(hdrbs, 0x0002 | 0x0004);
	else
		aimbs_put16(hdrbs, 0x0002);

	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_putstr(hdrbs, sess->sn);

	aim_bstream_setpos(hdrbs, 52); /* bleeehh */

	aimbs_put8(hdrbs, 0x00);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put8(hdrbs, 0x00);

	/* end of hdr */

	aim_tx_enqueue(sess, fr);

	return 0;
}

/**
 * Send client-to-client IM over an established direct connection.
 * Call this just like you would aim_send_im, to send a directim.
 *
 * @param sess The session.
 * @param conn The already-connected ODC connection.
 * @param msg Null-terminated string to send.
 * @param len The length of the message to send, including binary data.
 * @param encoding See the AIM_CHARSET_* defines in oscar.h
 * @param isawaymsg 0 if this is not an auto-response, 1 if it is.
 * @return Return 0 if no errors, otherwise return the error number.
 */
int
aim_odc_send_im(OscarSession *sess, OscarConnection *conn, const char *msg, int len, int encoding, int isawaymsg)
{
	FlapFrame *fr;
	ByteStream *hdrbs;
	struct aim_odc_intdata *intdata = (struct aim_odc_intdata *)conn->internal;
	int hdrlen = 0x44;
	guint8 *hdr;

	if (!sess || !conn || (conn->type != AIM_CONN_TYPE_RENDEZVOUS) || !msg)
		return -EINVAL;

	if (!(fr = aim_tx_new(sess, conn, AIM_FRAMETYPE_OFT, 0x01, 0)))
		return -ENOMEM;

	memcpy(fr->hdr.rend.magic, "ODC2", 4);
	fr->hdr.rend.hdrlen = hdrlen + 8;

	if (!(hdr = calloc(1, hdrlen + len))) {
		aim_frame_destroy(fr);
		return -ENOMEM;
	}

	hdrbs = &(fr->data);
	aim_bstream_init(hdrbs, hdr, hdrlen + len);

	aimbs_put16(hdrbs, 0x0006);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_putraw(hdrbs, intdata->cookie, 8);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put32(hdrbs, len);
	aimbs_put16(hdrbs, encoding);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);

	/* flags - used for typing notification and to mark if this is an away message */
	aimbs_put16(hdrbs, 0x0000 | isawaymsg);

	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_putstr(hdrbs, sess->sn);

	aim_bstream_setpos(hdrbs, 52); /* bleeehh */

	aimbs_put8(hdrbs, 0x00);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put8(hdrbs, 0x00);

	/* end of hdr2 */

#if 0 /* XXX - this is how you send buddy icon info... */
	aimbs_put16(hdrbs, 0x0008);
	aimbs_put16(hdrbs, 0x000c);
	aimbs_put16(hdrbs, 0x0000);
	aimbs_put16(hdrbs, 0x1466);
	aimbs_put16(hdrbs, 0x0001);
	aimbs_put16(hdrbs, 0x2e0f);
	aimbs_put16(hdrbs, 0x393e);
	aimbs_put16(hdrbs, 0xcac8);
#endif
	aimbs_putraw(hdrbs, (guchar *)msg, len);

	aim_tx_enqueue(sess, fr);

	return 0;
}

/**
 * Get the screen name of the peer of a direct connection.
 *
 * @param conn The ODC connection.
 * @return The screen name of the dude, or NULL if there was an anomaly.
 */
const char *
aim_odc_getsn(OscarConnection *conn)
{
	struct aim_odc_intdata *intdata;

	if (!conn || !conn->internal)
		return NULL;

	if ((conn->type != AIM_CONN_TYPE_RENDEZVOUS) ||
			(conn->subtype != AIM_CONN_SUBTYPE_OFT_DIRECTIM))
		return NULL;

	intdata = (struct aim_odc_intdata *)conn->internal;

	return intdata->sn;
}

/**
 * Get the cookie of a direct connection.
 *
 * @param conn The ODC connection.
 * @return The cookie, an 8 byte unterminated string, or NULL if there was an anomaly.
 */
const guchar *
aim_odc_getcookie(OscarConnection *conn)
{
	struct aim_odc_intdata *intdata;

	if (!conn || !conn->internal)
		return NULL;

	intdata = (struct aim_odc_intdata *)conn->internal;

	return intdata->cookie;
}

/**
 * Find the conn of a direct connection with the given buddy.
 *
 * @param sess The session.
 * @param sn The screen name of the buddy whose direct connection you want to find.
 * @return The conn for the direct connection with the given buddy, or NULL if no
 *         connection was found.
 */
OscarConnection *
aim_odc_getconn(OscarSession *sess, const char *sn)
{
	OscarConnection *cur;
	struct aim_odc_intdata *intdata;

	if (!sess || !sn || !strlen(sn))
		return NULL;

	for (cur = sess->connlist; cur; cur = cur->next) {
		if ((cur->type == AIM_CONN_TYPE_RENDEZVOUS) && (cur->subtype == AIM_CONN_SUBTYPE_OFT_DIRECTIM)) {
			intdata = cur->internal;
			if (!aim_sncmp(intdata->sn, sn))
				return cur;
		}
	}

	return NULL;
}

/**
 * For those times when we want to open up the direct connection channel ourselves.
 *
 * You'll want to set up some kind of watcher on this socket.
 * When the state changes, call aim_handlerendconnection with
 * the connection returned by this.  aim_handlerendconnection
 * will accept the pending connection and stop listening.
 *
 * @param sess The session
 * @param sn The screen name to connect to.
 * @return The new connection.
 */
OscarConnection *
aim_odc_initiate(OscarSession *sess, const char *sn, int listenfd,
                 const guint8 *localip, guint16 port, const guint8 *mycookie)
{
	OscarConnection *newconn;
	IcbmCookie *cookie;
	struct aim_odc_intdata *priv;
	guint8 ck[8];

	if (!localip)
		return NULL;

	if (mycookie) {
		memcpy(ck, mycookie, 8);
		aim_im_sendch2_odcrequest(sess, ck, TRUE, sn, localip, port);
	} else
		aim_im_sendch2_odcrequest(sess, ck, FALSE, sn, localip, port);

	cookie = (IcbmCookie *)calloc(1, sizeof(IcbmCookie));
	memcpy(cookie->cookie, ck, 8);
	cookie->type = AIM_COOKIETYPE_OFTIM;

	/* this one is for the cookie */
	priv = (struct aim_odc_intdata *)calloc(1, sizeof(struct aim_odc_intdata));

	memcpy(priv->cookie, ck, 8);
	strncpy(priv->sn, sn, sizeof(priv->sn));
	cookie->data = priv;
	aim_cachecookie(sess, cookie);

	/* XXX - switch to aim_cloneconn()? */
	if (!(newconn = aim_newconn(sess, AIM_CONN_TYPE_LISTENER))) {
		close(listenfd);
		return NULL;
	}

	/* this one is for the conn */
	priv = (struct aim_odc_intdata *)calloc(1, sizeof(struct aim_odc_intdata));

	memcpy(priv->cookie, ck, 8);
	strncpy(priv->sn, sn, sizeof(priv->sn));

	newconn->fd = listenfd;
	newconn->subtype = AIM_CONN_SUBTYPE_OFT_DIRECTIM;
	newconn->internal = priv;
	newconn->lastactivity = time(NULL);

	return newconn;
}

/**
 * Connect directly to the given buddy for directim.
 *
 * This is a wrapper for aim_newconn.
 *
 * If addr is NULL, the socket is not created, but the connection is
 * allocated and setup to connect.
 *
 * @param sess The Godly session.
 * @param sn The screen name we're connecting to.  I hope it's a girl...
 * @param addr Address to connect to.
 * @return The new connection.
 */
OscarConnection *
aim_odc_connect(OscarSession *sess, const char *sn, const char *addr, const guint8 *cookie)
{
	OscarConnection *newconn;
	struct aim_odc_intdata *intdata;

	if (!sess || !sn)
		return NULL;

	if (!(intdata = calloc(1, sizeof(struct aim_odc_intdata))))
		return NULL;
	memcpy(intdata->cookie, cookie, 8);
	strncpy(intdata->sn, sn, sizeof(intdata->sn));
	if (addr)
		strncpy(intdata->ip, addr, sizeof(intdata->ip));

	/* XXX - verify that non-blocking connects actually work */
	if (!(newconn = aim_newconn(sess, AIM_CONN_TYPE_RENDEZVOUS))) {
		free(intdata);
		return NULL;
	}

	newconn->internal = intdata;
	newconn->subtype = AIM_CONN_SUBTYPE_OFT_DIRECTIM;

	return newconn;
}

/**
 * Sometimes you just don't know with these kinds of people.
 *
 * @param sess The session.
 * @param conn The ODC connection of the incoming data.
 * @param frr The frame allocated for the incoming data.
 * @param bs It stands for "bologna sandwich."
 * @return Return 0 if no errors, otherwise return the error number.
 */
static int
handlehdr_odc(OscarSession *sess, OscarConnection *conn, FlapFrame *frr, ByteStream *bs)
{
	FlapFrame fr;
	int ret = 0;
	aim_rxcallback_t userfunc;
	guint32 payloadlength;
	guint16 flags, encoding;
	char *snptr = NULL;

	fr.conn = conn;

	/* AAA - ugly */
	aim_bstream_setpos(bs, 20);
	payloadlength = aimbs_get32(bs);

	aim_bstream_setpos(bs, 24);
	encoding = aimbs_get16(bs);

	aim_bstream_setpos(bs, 30);
	flags = aimbs_get16(bs);

	aim_bstream_setpos(bs, 36);
	/* XXX - create an aimbs_getnullstr function? */
	snptr = aimbs_getstr(bs, 32); /* Next 32 bytes contain the sn, padded with null chars */

	gaim_debug_misc("oscar", "faim: OFT frame: handlehdr_odc: %04x / %04x / %s\n", payloadlength, flags, snptr);

	if (flags & 0x0008) {
		if ((userfunc = aim_callhandler(sess, conn, AIM_CB_FAM_OFT, PEER_TYPE_DIRECTIMTYPING)))
			ret = userfunc(sess, &fr, snptr, 2);
	} else if (flags & 0x0004) {
		if ((userfunc = aim_callhandler(sess, conn, AIM_CB_FAM_OFT, PEER_TYPE_DIRECTIMTYPING)))
			ret = userfunc(sess, &fr, snptr, 1);
	} else {
		if ((userfunc = aim_callhandler(sess, conn, AIM_CB_FAM_OFT, PEER_TYPE_DIRECTIMTYPING)))
			ret = userfunc(sess, &fr, snptr, 0);
	}

	if ((payloadlength != 0) && (payloadlength != UINT_MAX)) {
		char *msg;
		int recvd = 0;
		int i, isawaymsg;

		isawaymsg = flags & 0x0001;

		if (!(msg = calloc(1, payloadlength+1))) {
			free(snptr);
			return -ENOMEM;
		}

		while (payloadlength - recvd) {
			if (payloadlength - recvd >= 1024)
				i = aim_recv(conn->fd, &msg[recvd], 1024);
			else
				i = aim_recv(conn->fd, &msg[recvd], payloadlength - recvd);
			if (i <= 0) {
				free(msg);
				free(snptr);
				return -1;
			}
			recvd = recvd + i;
			if ((userfunc = aim_callhandler(sess, conn, AIM_CB_FAM_SPECIAL, AIM_CB_SPECIAL_IMAGETRANSFER)))
				ret = userfunc(sess, &fr, snptr, (double)recvd / payloadlength);
		}

		if ((userfunc = aim_callhandler(sess, conn, AIM_CB_FAM_OFT, PEER_TYPE_DIRECTIMINCOMING)))
			ret = userfunc(sess, &fr, snptr, msg, payloadlength, encoding, isawaymsg);

		free(msg);
	}

	free(snptr);

	return ret;
}

PeerInfo *
aim_oft_createinfo(OscarSession *sess, const guint8 *cookie, const char *sn, const char *ip, guint16 port, guint32 size, guint32 modtime, char *filename, int send_or_recv, int method, int stage)
{
	PeerInfo *new;

	if (!sess)
		return NULL;

	if (!(new = (PeerInfo *)calloc(1, sizeof(PeerInfo))))
		return NULL;

	new->sess = sess;
	if (cookie)
		memcpy(new->cookie, cookie, 8);
	else
		aim_icbm_makecookie(new->cookie);
	if (ip)
		new->clientip = strdup(ip);
	else
		new->clientip = NULL;
	if (sn)
		new->sn = strdup(sn);
	else
		new->sn = NULL;
	new->method = method;
	new->send_or_recv = send_or_recv;
	new->stage = stage;
	new->port = port;
	new->xfer_reffed = FALSE;
	new->success = FALSE;
	new->fh.totfiles = 1;
	new->fh.filesleft = 1;
	new->fh.totparts = 1;
	new->fh.partsleft = 1;
	new->fh.totsize = size;
	new->fh.size = size;
	new->fh.modtime = modtime;
	new->fh.checksum = 0xffff0000;
	new->fh.rfrcsum = 0xffff0000;
	new->fh.rfcsum = 0xffff0000;
	new->fh.recvcsum = 0xffff0000;
	strncpy(new->fh.idstring, "OFT_Windows ICBMFT V1.1 32", 31);
	if (filename) {
		strncpy(new->fh.name, filename, 63);
		new->fh.name[63] = '\0';
	}

	new->next = sess->oft_info;
	sess->oft_info = new;

	return new;
}

PeerProxyInfo *aim_rv_proxy_createinfo(OscarSession *sess, const guint8 *cookie,
	guint16 port)
{
	PeerProxyInfo *proxy_info;

	if (!(proxy_info = (PeerProxyInfo*)calloc(1, sizeof(PeerProxyInfo))))
		return NULL;

	proxy_info->sess = sess;
	proxy_info->port = port;
	proxy_info->packet_ver = AIM_RV_PROXY_PACKETVER_DFLT;
	proxy_info->unknownA = AIM_RV_PROXY_UNKNOWNA_DFLT;

	if (cookie)
		memcpy(proxy_info->cookie, cookie, 8);

	return proxy_info;
}

/**
 * Remove the given oft_info struct from the oft_info linked list, and
 * then free its memory.
 *
 * @param sess The session.
 * @param oft_info The PeerInfo that we're destroying.
 * @return Return 0 if no errors, otherwise return the error number.
 */
int
aim_oft_destroyinfo(PeerInfo *oft_info)
{
	OscarSession *sess;

	if (!oft_info || !(sess = oft_info->sess))
		return -EINVAL;

	if (sess->oft_info && (sess->oft_info == oft_info)) {
		sess->oft_info = sess->oft_info->next;
	} else {
		PeerInfo *cur;
		for (cur=sess->oft_info; (cur->next && (cur->next!=oft_info)); cur=cur->next);
		if (cur->next)
			cur->next = cur->next->next;
	}

	free(oft_info->sn);
	free(oft_info->proxyip);
	free(oft_info->clientip);
	free(oft_info->verifiedip);
	free(oft_info);

	return 0;
}

/**
 * Creates a listener socket so the other dude can connect to us.
 *
 * You'll want to set up some kind of watcher on this socket.
 * When the state changes, call aim_handlerendconnection with
 * the connection returned by this.  aim_handlerendconnection
 * will accept the pending connection and stop listening.
 *
 * @param sess The session.
 * @param oft_info File transfer information associated with this
 *        connection.
 * @return Return 0 if no errors, otherwise return the error number.
 */
int
aim_sendfile_listen(OscarSession *sess, PeerInfo *oft_info, int listenfd)
{
	if (!oft_info)
		return -EINVAL;

	if (!(oft_info->conn = aim_newconn(sess, AIM_CONN_TYPE_LISTENER))) {
		close(listenfd);
		return -ENOMEM;
	}

	oft_info->conn->fd = listenfd;
	oft_info->conn->subtype = AIM_CONN_SUBTYPE_OFT_SENDFILE;
	oft_info->conn->lastactivity = time(NULL);

	return 0;
}

/**
 * Extract an &aim_fileheader_t from the given buffer.
 *
 * @param bs The should be from an incoming rendezvous packet.
 * @return A pointer to new struct on success, or NULL on error.
 */
static PeerFrame *
aim_oft_getheader(ByteStream *bs)
{
	PeerFrame *fh;

	if (!(fh = calloc(1, sizeof(PeerFrame))))
		return NULL;

	/* The bstream should be positioned after the hdrtype. */
	aimbs_getrawbuf(bs, fh->bcookie, 8);
	fh->encrypt = aimbs_get16(bs);
	fh->compress = aimbs_get16(bs);
	fh->totfiles = aimbs_get16(bs);
	fh->filesleft = aimbs_get16(bs);
	fh->totparts = aimbs_get16(bs);
	fh->partsleft = aimbs_get16(bs);
	fh->totsize = aimbs_get32(bs);
	fh->size = aimbs_get32(bs);
	fh->modtime = aimbs_get32(bs);
	fh->checksum = aimbs_get32(bs);
	fh->rfrcsum = aimbs_get32(bs);
	fh->rfsize = aimbs_get32(bs);
	fh->cretime = aimbs_get32(bs);
	fh->rfcsum = aimbs_get32(bs);
	fh->nrecvd = aimbs_get32(bs);
	fh->recvcsum = aimbs_get32(bs);
	aimbs_getrawbuf(bs, (guchar *)fh->idstring, 32);
	fh->flags = aimbs_get8(bs);
	fh->lnameoffset = aimbs_get8(bs);
	fh->lsizeoffset = aimbs_get8(bs);
	aimbs_getrawbuf(bs, (guchar *)fh->dummy, 69);
	aimbs_getrawbuf(bs, (guchar *)fh->macfileinfo, 16);
	fh->nencode = aimbs_get16(bs);
	fh->nlanguage = aimbs_get16(bs);
	aimbs_getrawbuf(bs, (guchar *)fh->name, 64); /* XXX - filenames longer than 64B */
	fh->name[63] = '\0';

	return fh;
}

/**
 * Fills a buffer with network-order fh data
 *
 * @param bs A bstream to fill -- automatically initialized
 * @param fh A PeerFrame to get data from.
 * @return Return non-zero on error.
 */
static int
aim_oft_buildheader(ByteStream *bs, PeerFrame *fh)
{
	guint8 *hdr;

	if (!bs || !fh)
		return -EINVAL;

	if (!(hdr = (unsigned char *)calloc(1, 0x100 - 8)))
		return -ENOMEM;

	aim_bstream_init(bs, hdr, 0x100 - 8);
	aimbs_putraw(bs, fh->bcookie, 8);
	aimbs_put16(bs, fh->encrypt);
	aimbs_put16(bs, fh->compress);
	aimbs_put16(bs, fh->totfiles);
	aimbs_put16(bs, fh->filesleft);
	aimbs_put16(bs, fh->totparts);
	aimbs_put16(bs, fh->partsleft);
	aimbs_put32(bs, fh->totsize);
	aimbs_put32(bs, fh->size);
	aimbs_put32(bs, fh->modtime);
	aimbs_put32(bs, fh->checksum);
	aimbs_put32(bs, fh->rfrcsum);
	aimbs_put32(bs, fh->rfsize);
	aimbs_put32(bs, fh->cretime);
	aimbs_put32(bs, fh->rfcsum);
	aimbs_put32(bs, fh->nrecvd);
	aimbs_put32(bs, fh->recvcsum);
	aimbs_putraw(bs, (guchar *)fh->idstring, 32);
	aimbs_put8(bs, fh->flags);
	aimbs_put8(bs, fh->lnameoffset);
	aimbs_put8(bs, fh->lsizeoffset);
	aimbs_putraw(bs, (guchar *)fh->dummy, 69);
	aimbs_putraw(bs, (guchar *)fh->macfileinfo, 16);
	aimbs_put16(bs, fh->nencode);
	aimbs_put16(bs, fh->nlanguage);
	aimbs_putraw(bs, (guchar *)fh->name, 64); /* XXX - filenames longer than 64B */

	return 0;
}

/**
 * Create an OFT packet based on the given information, and send it on its merry way.
 *
 * @param sess The session.
 * @param type The subtype of the OFT packet we're sending.
 * @param oft_info The PeerInfo with the connection and OFT
 *        info we're sending.
 * @return Return 0 if no errors, otherwise return the error number.
 */
int aim_oft_sendheader(OscarSession *sess, guint16 type, PeerInfo *oft_info)
{
	FlapFrame *fr;

	if (!sess || !oft_info || !oft_info->conn || (oft_info->conn->type != AIM_CONN_TYPE_RENDEZVOUS))
		return -EINVAL;

#if 0
	/*
	 * If you are receiving a file, the cookie should be null, if you are sending a
	 * file, the cookie should be the same as the one used in the ICBM negotiation
	 * SNACs.
	 */
	fh->lnameoffset = 0x1a;
	fh->lsizeoffset = 0x10;

	/* These should be the same as charset and charsubset in ICBMs */
	fh->nencode = 0x0000;
	fh->nlanguage = 0x0000;
#endif

	aim_oft_dirconvert_tostupid(oft_info->fh.name);

	if (!(fr = aim_tx_new(sess, oft_info->conn, AIM_FRAMETYPE_OFT, type, 0)))
		return -ENOMEM;

	if (aim_oft_buildheader(&fr->data, &oft_info->fh) == -1) {
		aim_frame_destroy(fr);
		return -ENOMEM;
	}

	memcpy(fr->hdr.rend.magic, "OFT2", 4);
	fr->hdr.rend.hdrlen = aim_bstream_curpos(&fr->data) + 8;

	aim_tx_enqueue(sess, fr);

	return 0;
}

/**
 * Create a rendezvous "init recv" packet and send it on its merry way.
 * This is the first packet sent to the proxy server by the second client
 * involved in this rendezvous proxy session.
 *
 * @param sess The session.
 * @param proxy_info Changable pieces of data for this packet
 * @return Return 0 if no errors, otherwise return the error number.
 */
int
aim_rv_proxy_init_recv(PeerProxyInfo *proxy_info)
{
#if 0
	aim_tlvlist_t *tlvlist_sendfile;
#endif
	ByteStream bs;
	guint8 *bs_raw;
	guint16 packet_len;
	guint8 sn_len;
	int err;

	err = 0;

	if (!proxy_info)
		return -EINVAL;

	sn_len = strlen(proxy_info->sess->sn);
	packet_len = 2 + 2	/* packet_len, packet_ver */
		+ 2 + 4		/* cmd_type,  unknownA */
		+ 2		/* flags */
		+ 1 + sn_len	/* Length/value pair for screenname */
		+ 8		/* ICBM Cookie */
		+ 2		/* port */
		+ 2 + 2 + 16;	/* TLV for Filesend capability block */

	if (!(bs_raw = malloc(packet_len)))
		return -ENOMEM;

	aim_bstream_init(&bs, bs_raw, packet_len);
	aimbs_put16(&bs, packet_len - 2); /* Length includes only packets after length marker */
	aimbs_put16(&bs, proxy_info->packet_ver);
	aimbs_put16(&bs, AIM_RV_PROXY_INIT_RECV);
	aimbs_put32(&bs, proxy_info->unknownA);
	aimbs_put16(&bs, proxy_info->flags);
	aimbs_put8(&bs, sn_len);
	aimbs_putraw(&bs, (const guchar *)proxy_info->sess->sn, sn_len);
	aimbs_put16(&bs, proxy_info->port);
	aimbs_putraw(&bs, proxy_info->cookie, 8);

	aimbs_put16(&bs, 0x0001);		/* Type */
	aimbs_put16(&bs, 16);			/* Length */
	aimbs_putcaps(&bs, AIM_CAPS_SENDFILE);	/* Value */


#if 0
	/* TODO: Use built-in TLV */
	aim_tlvlist_add_caps(&tlvlist_sendfile, 0x0001, AIM_CAPS_SENDFILE);
	aim_tlvlist_write(&bs, &tlvlist_sendfile);
#endif

	aim_bstream_rewind(&bs);
	if (aim_bstream_send(&bs, proxy_info->conn, packet_len) != packet_len)
		err = errno;
	proxy_info->conn->lastactivity = time(NULL);

#if 0
	aim_tlvlist_free(tlvlist_sendfile);
#endif
	free(bs_raw);

	return err;
}


/**
 * Create a rendezvous "init send" packet and send it on its merry way.
 * This is the first packet sent to the proxy server by the client
 * first indicating that this will be a proxied connection
 *
 * @param sess The session.
 * @param proxy_info Changable pieces of data for this packet
 * @return Return 0 if no errors, otherwise return the error number.
 */
int
aim_rv_proxy_init_send(PeerProxyInfo *proxy_info)
{
#if 0
	aim_tlvlist_t *tlvlist_sendfile;
#endif
	ByteStream bs;
	guint8 *bs_raw;
	guint16 packet_len;
	guint8 sn_len;
	int err;

	err = 0;

	if (!proxy_info)
		return -EINVAL;

	sn_len = strlen(proxy_info->sess->sn);
	packet_len = 2 + 2	/* packet_len, packet_ver */
		+ 2 + 4		/* cmd_type,  unknownA */
		+ 2		/* flags */
		+ 1 + sn_len	/* Length/value pair for screenname */
		+ 8		/* ICBM Cookie */
		+ 2 + 2 + 16;	/* TLV for Filesend capability block */

	if (!(bs_raw = malloc(packet_len)))
		return -ENOMEM;

	aim_bstream_init(&bs, bs_raw, packet_len);
	aimbs_put16(&bs, packet_len - 2); /* Length includes only packets after length marker */
	aimbs_put16(&bs, proxy_info->packet_ver);
	aimbs_put16(&bs, AIM_RV_PROXY_INIT_SEND);
	aimbs_put32(&bs, proxy_info->unknownA);
	aimbs_put16(&bs, proxy_info->flags);
	aimbs_put8(&bs, sn_len);
	aimbs_putraw(&bs, (const guchar *)proxy_info->sess->sn, sn_len);
	aimbs_putraw(&bs, proxy_info->cookie, 8);

	aimbs_put16(&bs, 0x0001);		/* Type */
	aimbs_put16(&bs, 16);			/* Length */
	aimbs_putcaps(&bs, AIM_CAPS_SENDFILE);	/* Value */

	/* TODO: Use built-in TLV */
#if 0
	aim_tlvlist_add_caps(&tlvlist_sendfile, 0x0001, AIM_CAPS_SENDFILE);
	aim_tlvlist_write(&bs, &tlvlist_sendfile);
#endif

	aim_bstream_rewind(&bs);
	if (aim_bstream_send(&bs, proxy_info->conn, packet_len) != packet_len)
		err = errno;
	proxy_info->conn->lastactivity = time(NULL);

#if 0
	aim_tlvlist_free(tlvlist_sendfile);
#endif
	free(bs_raw);

	return err;
}

/**
 * Handle incoming data on a rendezvous connection.  This is analogous to the
 * consumesnac function in rxhandlers.c, and I really think this should probably
 * be in rxhandlers.c as well, but I haven't finished cleaning everything up yet.
 *
 * @param sess The session.
 * @param fr The frame allocated for the incoming data.
 * @return Return 0 if the packet was handled correctly, otherwise return the
 *         error number.
 */
int
aim_rxdispatch_rendezvous(OscarSession *sess, FlapFrame *fr)
{
	OscarConnection *conn = fr->conn;
	int ret = 1;

	if (conn->subtype == AIM_CONN_SUBTYPE_OFT_DIRECTIM) {
		if (fr->hdr.rend.type == 0x0001)
			ret = handlehdr_odc(sess, conn, fr, &fr->data);
		else
			gaim_debug_info("oscar", "ODC directim frame unknown, type is %04x\n", fr->hdr.rend.type);

	} else {
		aim_rxcallback_t userfunc;
		PeerFrame *header = aim_oft_getheader(&fr->data);
		aim_oft_dirconvert_fromstupid(header->name); /* XXX - This should be client-side */

		if ((userfunc = aim_callhandler(sess, conn, AIM_CB_FAM_OFT, fr->hdr.rend.type)))
			ret = userfunc(sess, fr, conn, header->bcookie, header);

		free(header);
	}

	if (ret == -1)
		aim_conn_close(conn);

	return ret;
}

/**
 * Handle incoming data on a rendezvous proxy connection.  This is similar to
 * aim_rxdispatch_rendezvous above and should probably be kept with that function.
 *
 * @param sess The session.
 * @param fr The frame allocated for the incoming data.
 * @return Return 0 if the packet was handled correctly, otherwise return the
 *         error number.
 */
PeerProxyInfo *
aim_rv_proxy_read(OscarSession *sess, OscarConnection *conn)
{
	ByteStream bs_hdr;
	guint8 hdr_buf[AIM_RV_PROXY_HDR_LEN];
	ByteStream bs_body; /* The body (everything but the header) of the packet */
	guint8 *body_buf = NULL;
	guint8 body_len;

	char str_ip[30] = {""};
	guint8 ip_temp[4];

	guint16 len;
	PeerProxyInfo *proxy_info;

	if(!(proxy_info = malloc(sizeof(PeerProxyInfo))))
		return NULL;

	aim_bstream_init(&bs_hdr, hdr_buf, AIM_RV_PROXY_HDR_LEN);
	if (aim_bstream_recv(&bs_hdr, conn->fd, AIM_RV_PROXY_HDR_LEN) == AIM_RV_PROXY_HDR_LEN) {
		aim_bstream_rewind(&bs_hdr);
		len = aimbs_get16(&bs_hdr);
		proxy_info->packet_ver = aimbs_get16(&bs_hdr);
		proxy_info->cmd_type = aimbs_get16(&bs_hdr);
		proxy_info->unknownA = aimbs_get32(&bs_hdr);
		proxy_info->flags = aimbs_get16(&bs_hdr);
		if(proxy_info->cmd_type == AIM_RV_PROXY_READY) {
			/* Do a little victory dance
			 * A ready packet contains no additional information */
		} else if(proxy_info->cmd_type == AIM_RV_PROXY_ERROR) {
			if(len == AIM_RV_PROXY_ERROR_LEN - 2) {
				body_len = AIM_RV_PROXY_ERROR_LEN - AIM_RV_PROXY_HDR_LEN;
				body_buf = malloc(body_len);
				aim_bstream_init(&bs_body, body_buf, body_len);
				if (aim_bstream_recv(&bs_body, conn->fd, body_len) == body_len) {
					aim_bstream_rewind(&bs_body);
					proxy_info->err_code = aimbs_get16(&bs_body);
				} else {
					gaim_debug_warning("oscar","error reading rv proxy error packet\n");
					aim_conn_close(conn);
					free(proxy_info);
					proxy_info = NULL;
				}
			} else {
				gaim_debug_warning("oscar","invalid length for proxy error packet\n");
				free(proxy_info);
				proxy_info = NULL;
			}
		} else if(proxy_info->cmd_type == AIM_RV_PROXY_ACK) {
			if(len == AIM_RV_PROXY_ACK_LEN - 2) {
				body_len = AIM_RV_PROXY_ACK_LEN - AIM_RV_PROXY_HDR_LEN;
				body_buf = malloc(body_len);
				aim_bstream_init(&bs_body, body_buf, body_len);
				if (aim_bstream_recv(&bs_body, conn->fd, body_len) == body_len) {
					int i;
					aim_bstream_rewind(&bs_body);
					proxy_info->port = aimbs_get16(&bs_body);
					for(i=0; i<4; i++)
						ip_temp[i] = aimbs_get8(&bs_body);
					snprintf(str_ip, sizeof(str_ip), "%hhu.%hhu.%hhu.%hhu",
						ip_temp[0], ip_temp[1],
						ip_temp[2], ip_temp[3]);
					proxy_info->ip = strdup(str_ip);
				} else {
					gaim_debug_warning("oscar","error reading rv proxy error packet\n");
					aim_conn_close(conn);
					free(proxy_info);
					proxy_info = NULL;
				}
			} else {
				gaim_debug_warning("oscar","invalid length for proxy error packet\n");
				free(proxy_info);
				proxy_info = NULL;
			}
		} else {
			gaim_debug_warning("oscar","unknown type for aim rendezvous proxy packet\n");
		}
	} else {
		gaim_debug_warning("oscar","error reading header of rv proxy packet\n");
		aim_conn_close(conn);
		free(proxy_info);
		proxy_info = NULL;
	}
	if(body_buf) {
		free(body_buf);
		body_buf = NULL;
	}
	return proxy_info;
}

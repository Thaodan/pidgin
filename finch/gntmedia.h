/* finch
 *
 * Finch is the legal property of its developers, whose names are too numerous
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

#ifndef FINCH_MEDIA_H
#define FINCH_MEDIA_H

/**
 * SECTION:gntmedia
 * @section_id: finch-gntmedia
 * @short_description: <filename>gntmedia.h</filename>
 * @title: Media API
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

G_BEGIN_DECLS

void finch_media_manager_init(void);
void finch_media_manager_uninit(void);

G_END_DECLS

#endif /* FINCH_MEDIA_H */


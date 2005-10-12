/*
 * gaim
 *
 * Gaim is the legal property of its developers, whose names are too numerous
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include "internal.h"

#include "blist.h"
#include "prefs.h"
#include "sound.h"

static GaimSoundUiOps *sound_ui_ops = NULL;

void
gaim_sound_play_file(const char *filename, const GaimAccount *account)
{
	GaimStatus *status;

	if ((account != NULL) && (!gaim_prefs_get_bool("/core/sounds/while_away")))
	{
		status = gaim_account_get_active_status(account);
		if (gaim_status_is_online(status) && !gaim_status_is_available(status))
			return;
	}

	if(sound_ui_ops && sound_ui_ops->play_file)
		sound_ui_ops->play_file(filename);
}

void
gaim_sound_play_event(GaimSoundEventID event, const GaimAccount *account)
{
	GaimStatus *status;

	if ((account != NULL) && (!gaim_prefs_get_bool("/core/sounds/while_away")))
	{
		status = gaim_account_get_active_status(account);
		if (gaim_status_is_online(status) && !gaim_status_is_available(status))
			return;
	}

	if(sound_ui_ops && sound_ui_ops->play_event)
		sound_ui_ops->play_event(event);
}

void
gaim_sound_set_ui_ops(GaimSoundUiOps *ops)
{
	if(sound_ui_ops && sound_ui_ops->uninit)
		sound_ui_ops->uninit();

	sound_ui_ops = ops;

	if(sound_ui_ops && sound_ui_ops->init)
		sound_ui_ops->init();
}

GaimSoundUiOps *
gaim_sound_get_ui_ops(void)
{
	return sound_ui_ops;
}

void
gaim_sound_init()
{
	gaim_prefs_add_none("/core/sound");
	gaim_prefs_add_bool("/core/sound/while_away", FALSE);

}

void
gaim_sound_uninit()
{
	if(sound_ui_ops && sound_ui_ops->uninit)
		sound_ui_ops->uninit();
}

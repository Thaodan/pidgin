/**
 * @file gaim-compat.h Gaim Compat macros
 * @ingroup core
 *
 * pidgin
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * @see @ref account-signals
 */
#ifndef _GAIM_COMPAT_H_
#define _GAIM_COMPAT_H_

/* from account.h */
#define GaimAccountUiOps PurpleAccountUiOps
#define GaimAccount PurpleAccount

#define GaimFilterAccountFunc PurpleFilterAccountFunc
#define GaimAccountRequestAuthorizationCb PurpleAccountRequestAuthorizationCb

#define gaim_account_new           purple_account_new
#define gaim_account_destroy       purple_account_destroy
#define gaim_account_connect       purple_account_connect
#define gaim_account_register      purple_account_register
#define gaim_account_disconnect    purple_account_disconnect
#define gaim_account_notify_added  purple_account_notify_added
#define gaim_account_request_add   purple_account_request_add

#define gaim_account_request_authorization     purple_account_request_authorization
#define gaim_account_request_change_password   purple_account_request_change_password
#define gaim_account_request_change_user_info  purple_account_request_change_user_info

#define gaim_account_set_username            purple_account_set_username
#define gaim_account_set_password            purple_account_set_password
#define gaim_account_set_alias               purple_account_set_alias
#define gaim_account_set_user_info           purple_account_set_user_info
#define gaim_account_set_buddy_icon          purple_account_set_buddy_icon
#define gaim_account_set_buddy_icon_path     purple_account_set_buddy_icon_path
#define gaim_account_set_protocol_id         purple_account_set_protocol_id
#define gaim_account_set_connection          purple_account_set_connection
#define gaim_account_set_remember_password   purple_account_set_remember_password
#define gaim_account_set_check_mail          purple_account_set_check_mail
#define gaim_account_set_enabled             purple_account_set_enabled
#define gaim_account_set_proxy_info          purple_account_set_proxy_info
#define gaim_account_set_status_types        purple_account_set_status_types
#define gaim_account_set_status              purple_account_set_status
#define gaim_account_set_status_list         purple_account_set_status_list

#define gaim_account_clear_settings   purple_account_clear_settings

#define gaim_account_set_int    purple_account_set_int
#define gaim_account_set_string purple_account_set_string
#define gaim_account_set_bool   purple_account_set_bool

#define gaim_account_set_ui_int     purple_account_set_ui_int
#define gaim_account_set_ui_string  purple_account_set_ui_string
#define gaim_account_set_ui_bool    purple_account_set_ui_bool

#define gaim_account_is_connected     purple_account_is_connected
#define gaim_account_is_connecting    purple_account_is_connecting
#define gaim_account_is_disconnected  purple_account_is_disconnected

#define gaim_account_get_username           purple_account_get_username
#define gaim_account_get_password           purple_account_get_password
#define gaim_account_get_alias              purple_account_get_alias
#define gaim_account_get_user_info          purple_account_get_user_info
#define gaim_account_get_buddy_icon         purple_account_get_buddy_icon
#define gaim_account_get_buddy_icon_path    purple_account_get_buddy_icon_path
#define gaim_account_get_protocol_id        purple_account_get_protocol_id
#define gaim_account_get_protocol_name      purple_account_get_protocol_name
#define gaim_account_get_connection         purple_account_get_connection
#define gaim_account_get_remember_password  purple_account_get_remember_password
#define gaim_account_get_check_mail         purple_account_get_check_mail
#define gaim_account_get_enabled            purple_account_get_enabled
#define gaim_account_get_proxy_info         purple_account_get_proxy_info
#define gaim_account_get_active_status      purple_account_get_active_status
#define gaim_account_get_status             purple_account_get_status
#define gaim_account_get_status_type        purple_account_get_status_type
#define gaim_account_get_status_type_with_primitive \
	purple_account_get_status_type_with_primitive

#define gaim_account_get_presence       purple_account_get_presence
#define gaim_account_is_status_active   purple_account_is_status_active
#define gaim_account_get_status_types   purple_account_get_status_types

#define gaim_account_get_int            purple_account_get_int
#define gaim_account_get_string         purple_account_get_string
#define gaim_account_get_bool           purple_account_get_bool

#define gaim_account_get_ui_int     purple_account_get_ui_int
#define gaim_account_get_ui_string  purple_account_get_ui_string
#define gaim_account_get_ui_bool    purple_account_get_ui_bool


#define gaim_account_get_log      purple_account_get_log
#define gaim_account_destroy_log  purple_account_destroy_log

#define gaim_account_add_buddy       purple_account_add_buddy
#define gaim_account_add_buddies     purple_account_add_buddies
#define gaim_account_remove_buddy    purple_account_remove_buddy
#define gaim_account_remove_buddies  purple_account_remove_buddies

#define gaim_account_remove_group  purple_account_remove_group

#define gaim_account_change_password  purple_account_change_password

#define gaim_account_supports_offline_message  purple_account_supports_offline_message

#define gaim_accounts_add      purple_accounts_add
#define gaim_accounts_remove   purple_accounts_remove
#define gaim_accounts_delete   purple_accounts_delete
#define gaim_accounts_reorder  purple_accounts_reorder

#define gaim_accounts_get_all         purple_accounts_get_all
#define gaim_accounts_get_all_active  purple_accounts_get_all_active

#define gaim_accounts_find   purple_accounts_find

#define gaim_accounts_restore_current_statuses  purple_accounts_restore_current_statuses

#define gaim_accounts_set_ui_ops  purple_accounts_set_ui_ops
#define gaim_accounts_get_ui_ops  purple_accounts_get_ui_ops

#define gaim_accounts_get_handle  purple_accounts_get_handle

#define gaim_accounts_init    purple_accounts_init
#define gaim_accounts_uninit  purple_accounts_uninit

/* from accountopt.h */

#define GaimAccountOption     PurpleAccountOption
#define GaimAccountUserSplit  PurpleAccountUserSplit

#define gaim_account_option_new         purple_account_option_new
#define gaim_account_option_bool_new    purple_account_option_bool_new
#define gaim_account_option_int_new     purple_account_option_int_new
#define gaim_account_option_string_new  purple_account_option_string_new
#define gaim_account_option_list_new    purple_account_option_list_new

#define gaim_account_option_destroy  purple_account_option_destroy

#define gaim_account_option_set_default_bool    purple_account_option_set_default_bool
#define gaim_account_option_set_default_int     purple_account_option_set_default_int
#define gaim_account_option_set_default_string  purple_account_option_set_default_string

#define gaim_account_option_set_masked  purple_account_option_set_masked

#define gaim_account_option_set_list  purple_account_option_set_list

#define gaim_account_option_add_list_item  purple_account_option_add_list_item

#define gaim_account_option_get_type     purple_account_option_get_type
#define gaim_account_option_get_text     purple_account_option_get_text
#define gaim_account_option_get_setting  purple_account_option_get_setting

#define gaim_account_option_get_default_bool        purple_account_option_get_default_bool
#define gaim_account_option_get_default_int         purple_account_option_get_default_int
#define gaim_account_option_get_default_string      purple_account_option_get_default_string
#define gaim_account_option_get_default_list_value  purple_account_option_get_default_list_value

#define gaim_account_option_get_masked  purple_account_option_get_masked
#define gaim_account_option_get_list    purple_account_option_get_list

#define gaim_account_user_split_new      purple_account_user_split_new
#define gaim_account_user_split_destroy  purple_account_user_split_destroy

#define gaim_account_user_split_get_text           purple_account_user_split_get_text
#define gaim_account_user_split_get_default_value  purple_account_user_split_get_default_value
#define gaim_account_user_split_get_separator      purple_account_user_split_get_separator

/* from blist.h */

#define GaimBuddyList    PurpleBuddyList
#define GaimBlistUiOps   PurpleBlistUiOps
#define GaimBlistNode    PurpleBlistNode

#define GaimChat     PurpleChat
#define GaimGroup    PurpleGroup
#define GaimContact  PurpleContact
#define GaimBuddy    PurpleBuddy

#define GAIM_BLIST_GROUP_NODE     PURPLE_BLIST_GROUP_NODE
#define GAIM_BLIST_CONTACT_NODE   PURPLE_BLIST_CONTACT_NODE
#define GAIM_BLIST_BUDDY_NODE     PURPLE_BLIST_BUDDY_NODE
#define GAIM_BLIST_CHAT_NODE      PURPLE_BLIST_CHAT_NODE
#define GAIM_BLIST_OTHER_NODE     PURPLE_BLIST_OTHER_NODE
#define GaimBlistNodeType         PurpleBlistNodeType

#define GAIM_BLIST_NODE_IS_CHAT       PURPLE_BLIST_NODE_IS_CHAT
#define GAIM_BLIST_NODE_IS_BUDDY      PURPLE_BLIST_NODE_IS_BUDDY
#define GAIM_BLIST_NODE_IS_CONTACT    PURPLE_BLIST_NODE_IS_CONTACT
#define GAIM_BLIST_NODE_IS_GROUP      PURPLE_BLIST_NODE_IS_GROUP

#define GAIM_BUDDY_IS_ONLINE PURPLE_BUDDY_IS_ONLINE

#define GAIM_BLIST_NODE_FLAG_NO_SAVE  PURPLE_BLIST_NODE_FLAG_NO_SAVE
#define GaimBlistNodeFlags            PurpleBlistNodeFlags

#define GAIM_BLIST_NODE_HAS_FLAG     PURPLE_BLIST_NODE_HAS_FLAG
#define GAIM_BLIST_NODE_SHOULD_SAVE  PURPLE_BLIST_NODE_SHOULD_SAVE

#define GAIM_BLIST_NODE_NAME   PURPLE_BLIST_NODE_NAME


#define gaim_blist_new  purple_blist_new
#define gaim_set_blist  purple_set_blist
#define gaim_get_blist  purple_get_blist

#define gaim_blist_get_root   purple_blist_get_root
#define gaim_blist_node_next  purple_blist_node_next

#define gaim_blist_show  purple_blist_show

#define gaim_blist_destroy  purple_blist_destroy

#define gaim_blist_set_visible  purple_blist_set_visible

#define gaim_blist_update_buddy_status  purple_blist_update_buddy_status
#define gaim_blist_update_buddy_icon    purple_blist_update_buddy_icon


#define gaim_blist_alias_contact       purple_blist_alias_contact
#define gaim_blist_alias_buddy         purple_blist_alias_buddy
#define gaim_blist_server_alias_buddy  purple_blist_server_alias_buddy
#define gaim_blist_alias_chat          purple_blist_alias_chat

#define gaim_blist_rename_buddy  purple_blist_rename_buddy
#define gaim_blist_rename_group  purple_blist_rename_group

#define gaim_chat_new        purple_chat_new
#define gaim_blist_add_chat  purple_blist_add_chat

#define gaim_buddy_new           purple_buddy_new
#define gaim_buddy_set_icon      purple_buddy_set_icon
#define gaim_buddy_get_account   purple_buddy_get_account
#define gaim_buddy_get_name      purple_buddy_get_name
#define gaim_buddy_get_icon      purple_buddy_get_icon
#define gaim_buddy_get_contact   purple_buddy_get_contact
#define gaim_buddy_get_presence  purple_buddy_get_presence

#define gaim_blist_add_buddy  purple_blist_add_buddy

#define gaim_group_new  purple_group_new

#define gaim_blist_add_group  purple_blist_add_group

#define gaim_contact_new  purple_contact_new

#define gaim_blist_add_contact    purple_blist_add_contact
#define gaim_blist_merge_contact  purple_blist_merge_contact

#define gaim_contact_get_priority_buddy  purple_contact_get_priority_buddy
#define gaim_contact_set_alias           purple_contact_set_alias
#define gaim_contact_get_alias           purple_contact_get_alias
#define gaim_contact_on_account          purple_contact_on_account

#define gaim_contact_invalidate_priority_buddy  purple_contact_invalidate_priority_buddy

#define gaim_blist_remove_buddy    purple_blist_remove_buddy
#define gaim_blist_remove_contact  purple_blist_remove_contact
#define gaim_blist_remove_chat     purple_blist_remove_chat
#define gaim_blist_remove_group    purple_blist_remove_group

#define gaim_buddy_get_alias_only     purple_buddy_get_alias_only
#define gaim_buddy_get_server_alias   purple_buddy_get_server_alias
#define gaim_buddy_get_contact_alias  purple_buddy_get_contact_alias
#define gaim_buddy_get_local_alias    purple_buddy_get_local_alias
#define gaim_buddy_get_alias          purple_buddy_get_alias

#define gaim_chat_get_name  purple_chat_get_name

#define gaim_find_buddy           purple_find_buddy
#define gaim_find_buddy_in_group  purple_find_buddy_in_group
#define gaim_find_buddies         purple_find_buddies

#define gaim_find_group  purple_find_group

#define gaim_blist_find_chat  purple_blist_find_chat

#define gaim_chat_get_group   purple_chat_get_group
#define gaim_buddy_get_group  purple_buddy_get_group

#define gaim_group_get_accounts  purple_group_get_accounts
#define gaim_group_on_account    purple_group_on_account

#define gaim_blist_add_account     purple_blist_add_account
#define gaim_blist_remove_account  purple_blist_remove_account

#define gaim_blist_get_group_size          purple_blist_get_group_size
#define gaim_blist_get_group_online_count  purple_blist_get_group_online_count

#define gaim_blist_load           purple_blist_load
#define gaim_blist_schedule_save  purple_blist_schedule_save

#define gaim_blist_request_add_buddy  purple_blist_request_add_buddy
#define gaim_blist_request_add_chat   purple_blist_request_add_chat
#define gaim_blist_request_add_group  purple_blist_request_add_group

#define gaim_blist_node_set_bool    purple_blist_node_set_bool
#define gaim_blist_node_get_bool    purple_blist_node_get_bool
#define gaim_blist_node_set_int     purple_blist_node_set_int
#define gaim_blist_node_get_int     purple_blist_node_get_int
#define gaim_blist_node_set_string  purple_blist_node_set_string
#define gaim_blist_node_get_string  purple_blist_node_get_string

#define gaim_blist_node_remove_setting  purple_blist_node_remove_setting

#define gaim_blist_node_set_flags  purple_blist_node_set_flags
#define gaim_blist_node_get_flags  purple_blist_node_get_flags

#define gaim_blist_node_get_extended_menu  purple_blist_node_get_extended_menu

#define gaim_blist_set_ui_ops  purple_blist_set_ui_ops
#define gaim_blist_get_ui_ops  purple_blist_get_ui_ops

#define gaim_blist_get_handle  purple_blist_get_handle

#define gaim_blist_init    purple_blist_init
#define gaim_blist_uninit  purple_blist_uninit


#define GaimBuddyIcon  PurpleBuddyIcon

#define gaim_buddy_icon_new      purple_buddy_icon_new
#define gaim_buddy_icon_destroy  purple_buddy_icon_destroy
#define gaim_buddy_icon_ref      purple_buddy_icon_ref
#define gaim_buddy_icon_unref    purple_buddy_icon_unref
#define gaim_buddy_icon_update   purple_buddy_icon_update
#define gaim_buddy_icon_cache    purple_buddy_icon_cache
#define gaim_buddy_icon_uncache  purple_buddy_icon_uncache

#define gaim_buddy_icon_set_account   purple_buddy_icon_set_account
#define gaim_buddy_icon_set_username  purple_buddy_icon_set_username
#define gaim_buddy_icon_set_data      purple_buddy_icon_set_data
#define gaim_buddy_icon_set_path      purple_buddy_icon_set_path

#define gaim_buddy_icon_get_account   purple_buddy_icon_get_account
#define gaim_buddy_icon_get_username  purple_buddy_icon_get_username
#define gaim_buddy_icon_get_data      purple_buddy_icon_get_data
#define gaim_buddy_icon_get_path      purple_buddy_icon_get_path
#define gaim_buddy_icon_get_type      purple_buddy_icon_get_type

#define gaim_buddy_icons_set_for_user   purple_buddy_icons_set_for_user
#define gaim_buddy_icons_find           purple_buddy_icons_find
#define gaim_buddy_icons_set_caching    purple_buddy_icons_set_caching
#define gaim_buddy_icons_is_caching     purple_buddy_icons_is_caching
#define gaim_buddy_icons_set_cache_dir  purple_buddy_icons_set_cache_dir
#define gaim_buddy_icons_get_cache_dir  purple_buddy_icons_get_cache_dir
#define gaim_buddy_icons_get_full_path  purple_buddy_icons_get_full_path
#define gaim_buddy_icons_get_handle     purple_buddy_icons_get_handle

#define gaim_buddy_icons_init    purple_buddy_icons_init
#define gaim_buddy_icons_uninit  purple_buddy_icons_uninit

#define gaim_buddy_icon_get_scale_size  purple_buddy_icon_get_scale_size

/* from cipher.h */

#define GAIM_CIPHER          PURPLE_CIPHER
#define GAIM_CIPHER_OPS      PURPLE_CIPHER_OPS
#define GAIM_CIPHER_CONTEXT  PURPLE_CIPHER_CONTEXT

#define GaimCipher         PurpleCipher
#define GaimCipherOps      PurpleCipherOps
#define GaimCipherContext  PurpleCipherContext

#define GAIM_CIPHER_CAPS_SET_OPT  PURPLE_CIPHER_CAPS_SET_OPT
#define GAIM_CIPHER_CAPS_GET_OPT  PURPLE_CIPHER_CAPS_GET_OPT
#define GAIM_CIPHER_CAPS_INIT     PURPLE_CIPHER_CAPS_INIT
#define GAIM_CIPHER_CAPS_RESET    PURPLE_CIPHER_CAPS_RESET
#define GAIM_CIPHER_CAPS_UNINIT   PURPLE_CIPHER_CAPS_UNINIT
#define GAIM_CIPHER_CAPS_SET_IV   PURPLE_CIPHER_CAPS_SET_IV
#define GAIM_CIPHER_CAPS_APPEND   PURPLE_CIPHER_CAPS_APPEND
#define GAIM_CIPHER_CAPS_DIGEST   PURPLE_CIPHER_CAPS_DIGEST
#define GAIM_CIPHER_CAPS_ENCRYPT  PURPLE_CIPHER_CAPS_ENCRYPT
#define GAIM_CIPHER_CAPS_DECRYPT  PURPLE_CIPHER_CAPS_DECRYPT
#define GAIM_CIPHER_CAPS_SET_SALT  PURPLE_CIPHER_CAPS_SET_SALT
#define GAIM_CIPHER_CAPS_GET_SALT_SIZE  PURPLE_CIPHER_CAPS_GET_SALT_SIZE
#define GAIM_CIPHER_CAPS_SET_KEY        PURPLE_CIPHER_CAPS_SET_KEY
#define GAIM_CIPHER_CAPS_GET_KEY_SIZE   PURPLE_CIPHER_CAPS_GET_KEY_SIZE
#define GAIM_CIPHER_CAPS_UNKNOWN        PURPLE_CIPHER_CAPS_UNKNOWN

#define gaim_cipher_get_name          purple_cipher_get_name
#define gaim_cipher_get_capabilities  purple_cipher_get_capabilities
#define gaim_cipher_digest_region     purple_cipher_digest_region

#define gaim_ciphers_find_cipher        purple_ciphers_find_cipher
#define gaim_ciphers_register_cipher    purple_ciphers_register_cipher
#define gaim_ciphers_unregister_cipher  purple_ciphers_unregister_cipher
#define gaim_ciphers_get_ciphers        purple_ciphers_get_ciphers

#define gaim_ciphers_get_handle  purple_ciphers_get_handle
#define gaim_ciphers_init        purple_ciphers_init
#define gaim_ciphers_uninit      purple_ciphers_uninit

#define gaim_cipher_context_set_option  purple_cipher_context_set_option
#define gaim_cipher_context_get_option  purple_cipher_context_get_option

#define gaim_cipher_context_new            purple_cipher_context_new
#define gaim_cipher_context_new_by_name    purple_cipher_context_new_by_name
#define gaim_cipher_context_reset          purple_cipher_context_reset
#define gaim_cipher_context_destroy        purple_cipher_context_destroy
#define gaim_cipher_context_set_iv         purple_cipher_context_set_iv
#define gaim_cipher_context_append         purple_cipher_context_append
#define gaim_cipher_context_digest         purple_cipher_context_digest
#define gaim_cipher_context_digest_to_str  purple_cipher_context_digest_to_str
#define gaim_cipher_context_encrypt        purple_cipher_context_encrypt
#define gaim_cipher_context_decrypt        purple_cipher_context_decrypt
#define gaim_cipher_context_set_salt       purple_cipher_context_set_salt
#define gaim_cipher_context_get_salt_size  purple_cipher_context_get_salt_size
#define gaim_cipher_context_set_key        purple_cipher_context_set_key
#define gaim_cipher_context_get_key_size   purple_cipher_context_get_key_size
#define gaim_cipher_context_set_data       purple_cipher_context_set_data
#define gaim_cipher_context_get_data       purple_cipher_context_get_data

#define gaim_cipher_http_digest_calculate_session_key \
	purple_cipher_http_digest_calculate_session_key

#define gaim_cipher_http_digest_calculate_response \
	purple_cipher_http_digest_calculate_response

/* from circbuffer.h */

#define GaimCircBuffer  PurpleCircBuffer

#define gaim_circ_buffer_new           purple_circ_buffer_new
#define gaim_circ_buffer_destroy       purple_circ_buffer_destroy
#define gaim_circ_buffer_append        purple_circ_buffer_append
#define gaim_circ_buffer_get_max_read  purple_circ_buffer_get_max_read
#define gaim_circ_buffer_mark_read     purple_circ_buffer_mark_read

/* from cmds.h */

#define GaimCmdPriority  PurpleCmdPriority
#define GaimCmdFlag      PurpleCmdFlag
#define GaimCmdStatus    PurpleCmdStatus
#define GaimCmdRet       PurpleCmdRet

#define GAIM_CMD_FUNC  PURPLE_CMD_FUNC

#define GaimCmdFunc  PurpleCmdFunc

#define GaimCmdId  PurpleCmdId

#define gaim_cmd_register    purple_cmd_register
#define gaim_cmd_unregister  purple_cmd_unregister
#define gaim_cmd_do_command  purple_cmd_do_command
#define gaim_cmd_list        purple_cmd_list
#define gaim_cmd_help        purple_cmd_help

/* from connection.h */

#define GaimConnection  PurpleConnection

#define GAIM_CONNECTION_HTML              PURPLE_CONNECTION_HTML
#define GAIM_CONNECTION_NO_BGCOLOR        PURPLE_CONNECTION_NO_BGCOLOR
#define GAIM_CONNECTION_AUTO_RESP         PURPLE_CONNECTION_AUTO_RESP
#define GAIM_CONNECTION_FORMATTING_WBFO   PURPLE_CONNECTION_FORMATTING_WBFO
#define GAIM_CONNECTION_NO_NEWLINES       PURPLE_CONNECTION_NO_NEWLINES
#define GAIM_CONNECTION_NO_FONTSIZE       PURPLE_CONNECTION_NO_FONTSIZE
#define GAIM_CONNECTION_NO_URLDESC        PURPLE_CONNECTION_NO_URLDESC
#define GAIM_CONNECTION_NO_IMAGES         PURPLE_CONNECTION_NO_IMAGES

#define GaimConnectionFlags  PurpleConnectionFlags

#define GAIM_DISCONNECTED  PURPLE_DISCONNECTED
#define GAIM_CONNECTED     PURPLE_CONNECTED
#define GAIM_CONNECTING    PURPLE_CONNECTING

#define GaimConnectionState  PurpleConnectionState

#define GaimConnectionUiOps  PurpleConnectionUiOps

#define gaim_connection_new      purple_connection_new
#define gaim_connection_destroy  purple_connection_destroy

#define gaim_connection_set_state         purple_connection_set_state
#define gaim_connection_set_account       purple_connection_set_account
#define gaim_connection_set_display_name  purple_connection_set_display_name
#define gaim_connection_get_state         purple_connection_get_state

#define GAIM_CONNECTION_IS_CONNECTED  PURPLE_CONNECTION_IS_CONNECTED

#define gaim_connection_get_account       purple_connection_get_account
#define gaim_connection_get_password      purple_connection_get_password
#define gaim_connection_get_display_name  purple_connection_get_display_name

#define gaim_connection_update_progress  purple_connection_update_progress

#define gaim_connection_notice  purple_connection_notice
#define gaim_connection_error   purple_connection_error

#define gaim_connections_disconnect_all  purple_connections_disconnect_all

#define gaim_connections_get_all         purple_connections_get_all
#define gaim_connections_get_connecting  purple_connections_get_connecting

#define GAIM_CONNECTION_IS_VALID  PURPLE_CONNECTION_IS_VALID

#define gaim_connections_set_ui_ops  purple_connections_set_ui_ops
#define gaim_connections_get_ui_ops  purple_connections_get_ui_ops

#define gaim_connections_init    purple_connections_init
#define gaim_connections_uninit  purple_connections_uninit
#define gaim_connections_get_handle  purple_connections_get_handle


/* from conversation.h */

#define GaimConversationUiOps  PurpleConversationUiOps
#define GaimConversation       PurpleConversation
#define GaimConvIm             PurpleConvIm
#define GaimConvChat           PurpleConvChat
#define GaimConvChatBuddy      PurpleConvChatBuddy

#define GAIM_CONV_TYPE_UNKNOWN  PURPLE_CONV_TYPE_UNKNOWN
#define GAIM_CONV_TYPE_IM       PURPLE_CONV_TYPE_IM
#define GAIM_CONV_TYPE_CHAT     PURPLE_CONV_TYPE_CHAT
#define GAIM_CONV_TYPE_MISC     PURPLE_CONV_TYPE_MISC
#define GAIM_CONV_TYPE_ANY      PURPLE_CONV_TYPE_ANY

#define GaimConversationType  PurpleConversationType

#define GAIM_CONV_UPDATE_ADD       PURPLE_CONV_UPDATE_ADD
#define GAIM_CONV_UPDATE_REMOVE    PURPLE_CONV_UPDATE_REMOVE
#define GAIM_CONV_UPDATE_ACCOUNT   PURPLE_CONV_UPDATE_ACCOUNT
#define GAIM_CONV_UPDATE_TYPING    PURPLE_CONV_UPDATE_TYPING
#define GAIM_CONV_UPDATE_UNSEEN    PURPLE_CONV_UPDATE_UNSEEN
#define GAIM_CONV_UPDATE_LOGGING   PURPLE_CONV_UPDATE_LOGGING
#define GAIM_CONV_UPDATE_TOPIC     PURPLE_CONV_UPDATE_TOPIC
#define GAIM_CONV_ACCOUNT_ONLINE   PURPLE_CONV_ACCOUNT_ONLINE
#define GAIM_CONV_ACCOUNT_OFFLINE  PURPLE_CONV_ACCOUNT_OFFLINE
#define GAIM_CONV_UPDATE_AWAY      PURPLE_CONV_UPDATE_AWAY
#define GAIM_CONV_UPDATE_ICON      PURPLE_CONV_UPDATE_ICON
#define GAIM_CONV_UPDATE_TITLE     PURPLE_CONV_UPDATE_TITLE
#define GAIM_CONV_UPDATE_CHATLEFT  PURPLE_CONV_UPDATE_CHATLEFT
#define GAIM_CONV_UPDATE_FEATURES  PURPLE_CONV_UPDATE_FEATURES

#define GaimConvUpdateType  PurpleConvUpdateType

#define GAIM_NOT_TYPING  PURPLE_NOT_TYPING
#define GAIM_TYPING      PURPLE_TYPING
#define GAIM_TYPED       PURPLE_TYPED

#define GaimTypingState  PurpleTypingState

#define GAIM_MESSAGE_SEND         PURPLE_MESSAGE_SEND
#define GAIM_MESSAGE_RECV         PURPLE_MESSAGE_RECV
#define GAIM_MESSAGE_SYSTEM       PURPLE_MESSAGE_SYSTEM
#define GAIM_MESSAGE_AUTO_RESP    PURPLE_MESSAGE_AUTO_RESP
#define GAIM_MESSAGE_ACTIVE_ONLY  PURPLE_MESSAGE_ACTIVE_ONLY
#define GAIM_MESSAGE_NICK         PURPLE_MESSAGE_NICK
#define GAIM_MESSAGE_NO_LOG       PURPLE_MESSAGE_NO_LOG
#define GAIM_MESSAGE_WHISPER      PURPLE_MESSAGE_WHISPER
#define GAIM_MESSAGE_ERROR        PURPLE_MESSAGE_ERROR
#define GAIM_MESSAGE_DELAYED      PURPLE_MESSAGE_DELAYED
#define GAIM_MESSAGE_RAW          PURPLE_MESSAGE_RAW
#define GAIM_MESSAGE_IMAGES       PURPLE_MESSAGE_IMAGES

#define GaimMessageFlags  PurpleMessageFlags

#define GAIM_CBFLAGS_NONE     PURPLE_CBFLAGS_NONE
#define GAIM_CBFLAGS_VOICE    PURPLE_CBFLAGS_VOICE
#define GAIM_CBFLAGS_HALFOP   PURPLE_CBFLAGS_HALFOP
#define GAIM_CBFLAGS_OP       PURPLE_CBFLAGS_OP
#define GAIM_CBFLAGS_FOUNDER  PURPLE_CBFLAGS_FOUNDER
#define GAIM_CBFLAGS_TYPING   PURPLE_CBFLAGS_TYPING

#define GaimConvChatBuddyFlags  PurpleConvChatBuddyFlags

#define gaim_conversations_set_ui_ops  purple_conversations_set_ui_ops

#define gaim_conversation_new          purple_conversation_new
#define gaim_conversation_destroy      purple_conversation_destroy
#define gaim_conversation_present      purple_conversation_present
#define gaim_conversation_get_type     purple_conversation_get_type
#define gaim_conversation_set_ui_ops   purple_conversation_set_ui_ops
#define gaim_conversation_get_ui_ops   purple_conversation_get_ui_ops
#define gaim_conversation_set_account  purple_conversation_set_account
#define gaim_conversation_get_account  purple_conversation_get_account
#define gaim_conversation_get_gc       purple_conversation_get_gc
#define gaim_conversation_set_title    purple_conversation_set_title
#define gaim_conversation_get_title    purple_conversation_get_title
#define gaim_conversation_autoset_title  purple_conversation_autoset_title
#define gaim_conversation_set_name       purple_conversation_set_name
#define gaim_conversation_get_name       purple_conversation_get_name
#define gaim_conversation_set_logging    purple_conversation_set_logging
#define gaim_conversation_is_logging     purple_conversation_is_logging
#define gaim_conversation_close_logs     purple_conversation_close_logs
#define gaim_conversation_get_im_data    purple_conversation_get_im_data

#define GAIM_CONV_IM    PURPLE_CONV_IM

#define gaim_conversation_get_chat_data  purple_conversation_get_chat_data

#define GAIM_CONV_CHAT  PURPLE_CONV_CHAT

#define gaim_conversation_set_data       purple_conversation_set_data
#define gaim_conversation_get_data       purple_conversation_get_data

#define gaim_get_conversations  purple_get_conversations
#define gaim_get_ims            purple_get_ims
#define gaim_get_chats          purple_get_chats

#define gaim_find_conversation_with_account \
	purple_find_conversation_with_account

#define gaim_conversation_write         purple_conversation_write
#define gaim_conversation_set_features  purple_conversation_set_features
#define gaim_conversation_get_features  purple_conversation_get_features
#define gaim_conversation_has_focus     purple_conversation_has_focus
#define gaim_conversation_update        purple_conversation_update
#define gaim_conversation_foreach       purple_conversation_foreach

#define gaim_conv_im_get_conversation  purple_conv_im_get_conversation
#define gaim_conv_im_set_icon          purple_conv_im_set_icon
#define gaim_conv_im_get_icon          purple_conv_im_get_icon
#define gaim_conv_im_set_typing_state  purple_conv_im_set_typing_state
#define gaim_conv_im_get_typing_state  purple_conv_im_get_typing_state

#define gaim_conv_im_start_typing_timeout  purple_conv_im_start_typing_timeout
#define gaim_conv_im_stop_typing_timeout   purple_conv_im_stop_typing_timeout
#define gaim_conv_im_get_typing_timeout    purple_conv_im_get_typing_timeout
#define gaim_conv_im_set_type_again        purple_conv_im_set_type_again
#define gaim_conv_im_get_type_again        purple_conv_im_get_type_again

#define gaim_conv_im_start_send_typed_timeout \
	purple_conv_im_start_send_typed_timeout

#define gaim_conv_im_stop_send_typed_timeout \
	purple_conv_im_stop_send_typed_timeout

#define gaim_conv_im_get_send_typed_timeout \
	purple_conv_im_get_send_typed_timeout

#define gaim_conv_present_error     purple_conv_present_error
#define gaim_conv_send_confirm      purple_conv_send_confirm

#define gaim_conv_im_update_typing    purple_conv_im_update_typing
#define gaim_conv_im_write            purple_conv_im_write
#define gaim_conv_im_send             purple_conv_im_send
#define gaim_conv_im_send_with_flags  purple_conv_im_send_with_flags

#define gaim_conv_custom_smiley_add    purple_conv_custom_smiley_add
#define gaim_conv_custom_smiley_write  purple_conv_custom_smiley_write
#define gaim_conv_custom_smiley_close  purple_conv_custom_smiley_close

#define gaim_conv_chat_get_conversation  purple_conv_chat_get_conversation
#define gaim_conv_chat_set_users         purple_conv_chat_set_users
#define gaim_conv_chat_get_users         purple_conv_chat_get_users
#define gaim_conv_chat_ignore            purple_conv_chat_ignore
#define gaim_conv_chat_unignore          purple_conv_chat_unignore
#define gaim_conv_chat_set_ignored       purple_conv_chat_set_ignored
#define gaim_conv_chat_get_ignored       purple_conv_chat_get_ignored
#define gaim_conv_chat_get_ignored_user  purple_conv_chat_get_ignored_user
#define gaim_conv_chat_is_user_ignored   purple_conv_chat_is_user_ignored
#define gaim_conv_chat_set_topic         purple_conv_chat_set_topic
#define gaim_conv_chat_get_topic         purple_conv_chat_get_topic
#define gaim_conv_chat_set_id            purple_conv_chat_set_id
#define gaim_conv_chat_get_id            purple_conv_chat_get_id
#define gaim_conv_chat_write             purple_conv_chat_write
#define gaim_conv_chat_send              purple_conv_chat_send
#define gaim_conv_chat_send_with_flags   purple_conv_chat_send_with_flags
#define gaim_conv_chat_add_user          purple_conv_chat_add_user
#define gaim_conv_chat_add_users         purple_conv_chat_add_users
#define gaim_conv_chat_rename_user       purple_conv_chat_rename_user
#define gaim_conv_chat_remove_user       purple_conv_chat_remove_user
#define gaim_conv_chat_remove_users      purple_conv_chat_remove_users
#define gaim_conv_chat_find_user         purple_conv_chat_find_user
#define gaim_conv_chat_user_set_flags    purple_conv_chat_user_set_flags
#define gaim_conv_chat_user_get_flags    purple_conv_chat_user_get_flags
#define gaim_conv_chat_clear_users       purple_conv_chat_clear_users
#define gaim_conv_chat_set_nick          purple_conv_chat_set_nick
#define gaim_conv_chat_get_nick          purple_conv_chat_get_nick
#define gaim_conv_chat_left              purple_conv_chat_left
#define gaim_conv_chat_has_left          purple_conv_chat_has_left

#define gaim_find_chat                   purple_find_chat

#define gaim_conv_chat_cb_new            purple_conv_chat_cb_new
#define gaim_conv_chat_cb_find           purple_conv_chat_cb_find
#define gaim_conv_chat_cb_get_name       purple_conv_chat_cb_get_name
#define gaim_conv_chat_cb_destroy        purple_conv_chat_cb_destroy

#define gaim_conversations_get_handle    purple_conversations_get_handle
#define gaim_conversations_init          purple_conversations_init
#define gaim_conversations_uninit        purple_conversations_uninit

/* from core.h */

#define GaimCore  PurpleCore

#define GaimCoreUiOps  PurpleCoreUiOps

#define gaim_core_init  purple_core_init
#define gaim_core_quit  purple_core_quit

#define gaim_core_quit_cb      purple_core_quit_cb
#define gaim_core_get_version  purple_core_get_version
#define gaim_core_get_ui       purple_core_get_ui
#define gaim_get_core          purple_get_core
#define gaim_core_set_ui_ops   purple_core_set_ui_ops
#define gaim_core_get_ui_ops   purple_core_get_ui_ops

/* from debug.h */

#define GAIM_DEBUG_ALL      PURPLE_DEBUG_ALL
#define GAIM_DEBUG_MISC     PURPLE_DEBUG_MISC
#define GAIM_DEBUG_INFO     PURPLE_DEBUG_INFO
#define GAIM_DEBUG_WARNING  PURPLE_DEBUG_WARNING
#define GAIM_DEBUG_ERROR    PURPLE_DEBUG_ERROR
#define GAIM_DEBUG_FATAL    PURPLE_DEBUG_FATAL

#define GaimDebugLevel  PurpleDebugLevel

#define GaimDebugUiOps  PurpleDebugUiOps


#define gaim_debug          purple_debug
#define gaim_debug_misc     purple_debug_misc
#define gaim_debug_info     purple_debug_info
#define gaim_debug_warning  purple_debug_warning
#define gaim_debug_error    purple_debug_error
#define gaim_debug_fatal    purple_debug_fatal

#define gaim_debug_set_enabled  purple_debug_set_enabled
#define gaim_debug_is_enabled   purple_debug_is_enabled

#define gaim_debug_set_ui_ops  purple_debug_set_ui_ops
#define gaim_debug_get_ui_ops  purple_debug_get_ui_ops

#define gaim_debug_init  purple_debug_init

/* from desktopitem.h */

#define GAIM_DESKTOP_ITEM_TYPE_NULL          PURPLE_DESKTOP_ITEM_TYPE_NULL
#define GAIM_DESKTOP_ITEM_TYPE_OTHER         PURPLE_DESKTOP_ITEM_TYPE_OTHER
#define GAIM_DESKTOP_ITEM_TYPE_APPLICATION   PURPLE_DESKTOP_ITEM_TYPE_APPLICATION
#define GAIM_DESKTOP_ITEM_TYPE_LINK          PURPLE_DESKTOP_ITEM_TYPE_LINK
#define GAIM_DESKTOP_ITEM_TYPE_FSDEVICE      PURPLE_DESKTOP_ITEM_TYPE_FSDEVICE
#define GAIM_DESKTOP_ITEM_TYPE_MIME_TYPE     PURPLE_DESKTOP_ITEM_TYPE_MIME_TYPE
#define GAIM_DESKTOP_ITEM_TYPE_DIRECTORY     PURPLE_DESKTOP_ITEM_TYPE_DIRECTORY
#define GAIM_DESKTOP_ITEM_TYPE_SERVICE       PURPLE_DESKTOP_ITEM_TYPE_SERVICE
#define GAIM_DESKTOP_ITEM_TYPE_SERVICE_TYPE  PURPLE_DESKTOP_ITEM_TYPE_SERVICE_TYPE

#define GaimDesktopItemType  PurpleDesktopItemType

#define GaimDesktopItem  PurpleDesktopItem

#define GAIM_TYPE_DESKTOP_ITEM         PURPLE_TYPE_DESKTOP_ITEM
#define gaim_desktop_item_get_type     purple_desktop_item_get_type

/* standard */
/* ugh, i'm just copying these as strings, rather than pidginifying them */
#define GAIM_DESKTOP_ITEM_ENCODING	"Encoding" /* string */
#define GAIM_DESKTOP_ITEM_VERSION	"Version"  /* numeric */
#define GAIM_DESKTOP_ITEM_NAME		"Name" /* localestring */
#define GAIM_DESKTOP_ITEM_GENERIC_NAME	"GenericName" /* localestring */
#define GAIM_DESKTOP_ITEM_TYPE		"Type" /* string */
#define GAIM_DESKTOP_ITEM_FILE_PATTERN "FilePattern" /* regexp(s) */
#define GAIM_DESKTOP_ITEM_TRY_EXEC	"TryExec" /* string */
#define GAIM_DESKTOP_ITEM_NO_DISPLAY	"NoDisplay" /* boolean */
#define GAIM_DESKTOP_ITEM_COMMENT	"Comment" /* localestring */
#define GAIM_DESKTOP_ITEM_EXEC		"Exec" /* string */
#define GAIM_DESKTOP_ITEM_ACTIONS	"Actions" /* strings */
#define GAIM_DESKTOP_ITEM_ICON		"Icon" /* string */
#define GAIM_DESKTOP_ITEM_MINI_ICON	"MiniIcon" /* string */
#define GAIM_DESKTOP_ITEM_HIDDEN	"Hidden" /* boolean */
#define GAIM_DESKTOP_ITEM_PATH		"Path" /* string */
#define GAIM_DESKTOP_ITEM_TERMINAL	"Terminal" /* boolean */
#define GAIM_DESKTOP_ITEM_TERMINAL_OPTIONS "TerminalOptions" /* string */
#define GAIM_DESKTOP_ITEM_SWALLOW_TITLE "SwallowTitle" /* string */
#define GAIM_DESKTOP_ITEM_SWALLOW_EXEC	"SwallowExec" /* string */
#define GAIM_DESKTOP_ITEM_MIME_TYPE	"MimeType" /* regexp(s) */
#define GAIM_DESKTOP_ITEM_PATTERNS	"Patterns" /* regexp(s) */
#define GAIM_DESKTOP_ITEM_DEFAULT_APP	"DefaultApp" /* string */
#define GAIM_DESKTOP_ITEM_DEV		"Dev" /* string */
#define GAIM_DESKTOP_ITEM_FS_TYPE	"FSType" /* string */
#define GAIM_DESKTOP_ITEM_MOUNT_POINT	"MountPoint" /* string */
#define GAIM_DESKTOP_ITEM_READ_ONLY	"ReadOnly" /* boolean */
#define GAIM_DESKTOP_ITEM_UNMOUNT_ICON "UnmountIcon" /* string */
#define GAIM_DESKTOP_ITEM_SORT_ORDER	"SortOrder" /* strings */
#define GAIM_DESKTOP_ITEM_URL		"URL" /* string */
#define GAIM_DESKTOP_ITEM_DOC_PATH	"X-GNOME-DocPath" /* string */

#define gaim_desktop_item_new_from_file   purple_desktop_item_new_from_file
#define gaim_desktop_item_get_entry_type  purple_desktop_item_get_entry_type
#define gaim_desktop_item_get_string      purple_desktop_item_get_string
#define gaim_desktop_item_copy            purple_desktop_item_copy
#define gaim_desktop_item_unref           purple_desktop_item_unref

/* from dnsquery.h */

#define GaimDnsQueryData  PurpleDnsQueryData
#define GaimDnsQueryConnectFunction  PurpleDnsQueryConnectFunction

#define gaim_dnsquery_a        purple_dnsquery_a
#define gaim_dnsquery_destroy  purple_dnsquery_destroy
#define gaim_dnsquery_init     purple_dnsquery_init
#define gaim_dnsquery_uninit   purple_dnsquery_uninit

/* from dnssrv.h */

#define GaimSrvResponse   PurpleSrvResponse
#define GaimSrvQueryData  PurpleSrvQueryData
#define GaimSrvCallback   PurpleSrvCallback

#define gaim_srv_resolve  purple_srv_resolve
#define gaim_srv_cancel   purple_srv_cancel

/* from eventloop.h */

#define GAIM_INPUT_READ   PURPLE_INPUT_READ
#define GAIM_INPUT_WRITE  PURPLE_INPUT_WRITE

#define GaimInputCondition  PurpleInputCondition
#define GaimInputFunction   PurpleInputFunction
#define GaimEventLoopUiOps  PurpleEventLoopUiOps

#define gaim_timeout_add     purple_timeout_add
#define gaim_timeout_remove  purple_timeout_remove
#define gaim_input_add       purple_input_add
#define gaim_input_remove    purple_input_remove

#define gaim_eventloop_set_ui_ops  purple_eventloop_set_ui_ops
#define gaim_eventloop_get_ui_ops  purple_eventloop_get_ui_ops

/* from ft.h */

#define GaimXfer  PurpleXfer

#define GAIM_XFER_UNKNOWN  PURPLE_XFER_UNKNOWN
#define GAIM_XFER_SEND     PURPLE_XFER_SEND
#define GAIM_XFER_RECEIVE  PURPLE_XFER_RECEIVE

#define GaimXferType  PurpleXferType

#define GAIM_XFER_STATUS_UNKNOWN        PURPLE_XFER_STATUS_UNKNOWN
#define GAIM_XFER_STATUS_NOT_STARTED    PURPLE_XFER_STATUS_NOT_STARTED
#define GAIM_XFER_STATUS_ACCEPTED       PURPLE_XFER_STATUS_ACCEPTED
#define GAIM_XFER_STATUS_STARTED        PURPLE_XFER_STATUS_STARTED
#define GAIM_XFER_STATUS_DONE           PURPLE_XFER_STATUS_DONE
#define GAIM_XFER_STATUS_CANCEL_LOCAL   PURPLE_XFER_STATUS_CANCEL_LOCAL
#define GAIM_XFER_STATUS_CANCEL_REMOTE  PURPLE_XFER_STATUS_CANCEL_REMOTE

#define GaimXferStatusType  PurpleXferStatusType

#define GaimXferUiOps  PurpleXferUiOps

#define gaim_xfer_new                  purple_xfer_new
#define gaim_xfer_ref                  purple_xfer_ref
#define gaim_xfer_unref                purple_xfer_unref
#define gaim_xfer_request              purple_xfer_request
#define gaim_xfer_request_accepted     purple_xfer_request_accepted
#define gaim_xfer_request_denied       purple_xfer_request_denied
#define gaim_xfer_get_type             purple_xfer_get_type
#define gaim_xfer_get_account          purple_xfer_get_account
#define gaim_xfer_get_status           purple_xfer_get_status
#define gaim_xfer_is_canceled          purple_xfer_is_canceled
#define gaim_xfer_is_completed         purple_xfer_is_completed
#define gaim_xfer_get_filename         purple_xfer_get_filename
#define gaim_xfer_get_local_filename   purple_xfer_get_local_filename
#define gaim_xfer_get_bytes_sent       purple_xfer_get_bytes_sent
#define gaim_xfer_get_bytes_remaining  purple_xfer_get_bytes_remaining
#define gaim_xfer_get_size             purple_xfer_get_size
#define gaim_xfer_get_progress         purple_xfer_get_progress
#define gaim_xfer_get_local_port       purple_xfer_get_local_port
#define gaim_xfer_get_remote_ip        purple_xfer_get_remote_ip
#define gaim_xfer_get_remote_port      purple_xfer_get_remote_port
#define gaim_xfer_set_completed        purple_xfer_set_completed
#define gaim_xfer_set_message          purple_xfer_set_message
#define gaim_xfer_set_filename         purple_xfer_set_filename
#define gaim_xfer_set_local_filename   purple_xfer_set_local_filename
#define gaim_xfer_set_size             purple_xfer_set_size
#define gaim_xfer_set_bytes_sent       purple_xfer_set_bytes_sent
#define gaim_xfer_get_ui_ops           purple_xfer_get_ui_ops
#define gaim_xfer_set_read_fnc         purple_xfer_set_read_fnc
#define gaim_xfer_set_write_fnc        purple_xfer_set_write_fnc
#define gaim_xfer_set_ack_fnc          purple_xfer_set_ack_fnc
#define gaim_xfer_set_request_denied_fnc  purple_xfer_set_request_denied_fnc
#define gaim_xfer_set_init_fnc         purple_xfer_set_init_fnc
#define gaim_xfer_set_start_fnc        purple_xfer_set_start_fnc
#define gaim_xfer_set_end_fnc          purple_xfer_set_end_fnc
#define gaim_xfer_set_cancel_send_fnc  purple_xfer_set_cancel_send_fnc
#define gaim_xfer_set_cancel_recv_fnc  purple_xfer_set_cancel_recv_fnc

#define gaim_xfer_read                purple_xfer_read
#define gaim_xfer_write               purple_xfer_write
#define gaim_xfer_start               purple_xfer_start
#define gaim_xfer_end                 purple_xfer_end
#define gaim_xfer_add                 purple_xfer_add
#define gaim_xfer_cancel_local        purple_xfer_cancel_local
#define gaim_xfer_cancel_remote       purple_xfer_cancel_remote
#define gaim_xfer_error               purple_xfer_error
#define gaim_xfer_update_progress     purple_xfer_update_progress
#define gaim_xfer_conversation_write  purple_xfer_conversation_write

#define gaim_xfers_get_handle  purple_xfers_get_handle
#define gaim_xfers_init        purple_xfers_init
#define gaim_xfers_uninit      purple_xfers_uninit
#define gaim_xfers_set_ui_ops  purple_xfers_set_ui_ops
#define gaim_xfers_get_ui_ops  purple_xfers_get_ui_ops

/* from gaim-client.h */

/* XXX: should this be purple_init, or pidgin_init */
#define gaim_init  purple_init

/* from idle.h */

#define GaimIdleUiOps  PurpleIdleUiOps

#define gaim_idle_touch       purple_idle_touch
#define gaim_idle_set         purple_idle_set
#define gaim_idle_set_ui_ops  purple_idle_set_ui_ops
#define gaim_idle_get_ui_ops  purple_idle_get_ui_ops
#define gaim_idle_init        purple_idle_init
#define gaim_idle_uninit      purple_idle_uninit

/* from imgstore.h */

#define GaimStoredImage  PurpleStoredImage

#define gaim_imgstore_add           purple_imgstore_add
#define gaim_imgstore_get           purple_imgstore_get
#define gaim_imgstore_get_data      purple_imgstore_get_data
#define gaim_imgstore_get_size      purple_imgstore_get_size
#define gaim_imgstore_get_filename  purple_imgstore_get_filename
#define gaim_imgstore_ref           purple_imgstore_ref
#define gaim_imgstore_unref         purple_imgstore_unref


/* from log.h */

#define GaimLog                  PurpleLog
#define GaimLogLogger            PurpleLogLogger
#define GaimLogCommonLoggerData  PurpleLogCommonLoggerData
#define GaimLogSet               PurpleLogSet

#define GAIM_LOG_IM      PURPLE_LOG_IM
#define GAIM_LOG_CHAT    PURPLE_LOG_CHAT
#define GAIM_LOG_SYSTEM  PURPLE_LOG_SYSTEM

#define GaimLogType  PurpleLogType

#define GAIM_LOG_READ_NO_NEWLINE  PURPLE_LOG_READ_NO_NEWLINE

#define GaimLogReadFlags  PurpleLogReadFlags

#define GaimLogSetCallback  PurpleLogSetCallback

#define gaim_log_new    purple_log_new
#define gaim_log_free   purple_log_free
#define gaim_log_write  purple_log_write
#define gaim_log_read   purple_log_read

#define gaim_log_get_logs         purple_log_get_logs
#define gaim_log_get_log_sets     purple_log_get_log_sets
#define gaim_log_get_system_logs  purple_log_get_system_logs
#define gaim_log_get_size         purple_log_get_size
#define gaim_log_get_total_size   purple_log_get_total_size
#define gaim_log_get_log_dir      purple_log_get_log_dir
#define gaim_log_compare          purple_log_compare
#define gaim_log_set_compare      purple_log_set_compare
#define gaim_log_set_free         purple_log_set_free

#define gaim_log_common_writer       purple_log_common_writer
#define gaim_log_common_lister       purple_log_common_lister
#define gaim_log_common_total_sizer  purple_log_common_total_sizer
#define gaim_log_common_sizer        purple_log_common_sizer

#define gaim_log_logger_new     purple_log_logger_new
#define gaim_log_logger_free    purple_log_logger_free
#define gaim_log_logger_add     purple_log_logger_add
#define gaim_log_logger_remove  purple_log_logger_remove
#define gaim_log_logger_set     purple_log_logger_set
#define gaim_log_logger_get     purple_log_logger_get

#define gaim_log_logger_get_options  purple_log_logger_get_options

#define gaim_log_init        purple_log_init
#define gaim_log_get_handle  purple_log_get_handle
#define gaim_log_uninit      purple_log_uninit

/* from mime.h */

#define GaimMimeDocument  PurpleMimeDocument
#define GaimMimePart      PurpleMimePart

#define gaim_mime_document_new         purple_mime_document_new
#define gaim_mime_document_free        purple_mime_document_free
#define gaim_mime_document_parse       purple_mime_document_parse
#define gaim_mime_document_parsen      purple_mime_document_parsen
#define gaim_mime_document_write       purple_mime_document_write
#define gaim_mime_document_get_fields  purple_mime_document_get_fields
#define gaim_mime_document_get_field   purple_mime_document_get_field
#define gaim_mime_document_set_field   purple_mime_document_set_field
#define gaim_mime_document_get_parts   purple_mime_document_get_parts

#define gaim_mime_part_new                purple_mime_part_new
#define gaim_mime_part_get_fields         purple_mime_part_get_fields
#define gaim_mime_part_get_field          purple_mime_part_get_field
#define gaim_mime_part_get_field_decoded  purple_mime_part_get_field_decoded
#define gaim_mime_part_set_field          purple_mime_part_set_field
#define gaim_mime_part_get_data           purple_mime_part_get_data
#define gaim_mime_part_get_data_decoded   purple_mime_part_get_data_decoded
#define gaim_mime_part_get_length         purple_mime_part_get_length
#define gaim_mime_part_set_data           purple_mime_part_set_data


/* from network.h */

#define GaimNetworkListenData  PurpleNetworkListenData

#define GaimNetworkListenCallback  PurpleNetworkListenCallback

#define gaim_network_ip_atoi              purple_network_ip_atoi
#define gaim_network_set_public_ip        purple_network_set_public_ip
#define gaim_network_get_public_ip        purple_network_get_public_ip
#define gaim_network_get_local_system_ip  purple_network_get_local_system_ip
#define gaim_network_get_my_ip            purple_network_get_my_ip

#define gaim_network_listen            purple_network_listen
#define gaim_network_listen_range      purple_network_listen_range
#define gaim_network_listen_cancel     purple_network_listen_cancel
#define gaim_network_get_port_from_fd  purple_network_get_port_from_fd

#define gaim_network_is_available  purple_network_is_available

#define gaim_network_init    purple_network_init
#define gaim_network_uninit  purple_network_uninit

/* from notify.h */


#define GaimNotifyUserInfoEntry  PurpleNotifyUserInfoEntry
#define GaimNotifyUserInfo       PurpleNotifyUserInfo

#define GaimNotifyCloseCallback  PurpleNotifyCloseCallback

#define GAIM_NOTIFY_MESSAGE        PURPLE_NOTIFY_MESSAGE
#define GAIM_NOTIFY_EMAIL          PURPLE_NOTIFY_EMAIL
#define GAIM_NOTIFY_EMAILS         PURPLE_NOTIFY_EMAILS
#define GAIM_NOTIFY_FORMATTED      PURPLE_NOTIFY_FORMATTED
#define GAIM_NOTIFY_SEARCHRESULTS  PURPLE_NOTIFY_SEARCHRESULTS
#define GAIM_NOTIFY_USERINFO       PURPLE_NOTIFY_USERINFO
#define GAIM_NOTIFY_URI            PURPLE_NOTIFY_URI

#define GaimNotifyType  PurpleNotifyType

#define GAIM_NOTIFY_MSG_ERROR    PURPLE_NOTIFY_MSG_ERROR
#define GAIM_NOTIFY_MSG_WARNING  PURPLE_NOTIFY_MSG_WARNING
#define GAIM_NOTIFY_MSG_INFO     PURPLE_NOTIFY_MSG_INFO

#define GaimNotifyMsgType  PurpleNotifyMsgType

#define GAIM_NOTIFY_BUTTON_LABELED   PURPLE_NOTIFY_BUTTON_LABELED
#define GAIM_NOTIFY_BUTTON_CONTINUE  PURPLE_NOTIFY_BUTTON_CONTINUE
#define GAIM_NOTIFY_BUTTON_ADD       PURPLE_NOTIFY_BUTTON_ADD
#define GAIM_NOTIFY_BUTTON_INFO      PURPLE_NOTIFY_BUTTON_INFO
#define GAIM_NOTIFY_BUTTON_IM        PURPLE_NOTIFY_BUTTON_IM
#define GAIM_NOTIFY_BUTTON_JOIN      PURPLE_NOTIFY_BUTTON_JOIN
#define GAIM_NOTIFY_BUTTON_INVITE    PURPLE_NOTIFY_BUTTON_INVITE

#define GaimNotifySearchButtonType  PurpleNotifySearchButtonType

#define GaimNotifySearchResults  PurpleNotifySearchResult

#define GAIM_NOTIFY_USER_INFO_ENTRY_PAIR            PURPLE_NOTIFY_USER_INFO_ENTRY_PAIR
#define GAIM_NOTIFY_USER_INFO_ENTRY_SECTION_BREAK   PURPLE_NOTIFY_USER_INFO_ENTRY_SECTION_BREAK
#define GAIM_NOTIFY_USER_INFO_ENTRY_SECTION_HEADER  PURPLE_NOTIFY_USER_INFO_ENTRY_SECTION_HEADER

#define GaimNotifyUserInfoEntryType  PurpleNotifyUserInfoEntryType

#define GaimNotifySearchColumn           PurpleNotifySearchColumn
#define GaimNotifySearchResultsCallback  PurpleNotifySearchResultsCallback
#define GaimNotifySearchButton           PurpleNotifySearchButton

#define GaimNotifyUiOps  PurpleNotifyUiOps

#define gaim_notify_searchresults                     purple_notify_searchresults
#define gaim_notify_searchresults_free                purple_notify_searchresults_free
#define gaim_notify_searchresults_new_rows            purple_notify_searchresults_new_rows
#define gaim_notify_searchresults_button_add          purple_notify_searchresults_button_add
#define gaim_notify_searchresults_button_add_labeled  purple_notify_searchresults_button_add_labeled
#define gaim_notify_searchresults_new                 purple_notify_searchresults_new
#define gaim_notify_searchresults_column_new          purple_notify_searchresults_column_new
#define gaim_notify_searchresults_column_add          purple_notify_searchresults_column_add
#define gaim_notify_searchresults_row_add             purple_notify_searchresults_row_add
#define gaim_notify_searchresults_get_rows_count      purple_notify_searchresults_get_rows_count
#define gaim_notify_searchresults_get_columns_count   purple_notify_searchresults_get_columns_count
#define gaim_notify_searchresults_row_get             purple_notify_searchresults_row_get
#define gaim_notify_searchresults_column_get_title    purple_notify_searchresults_column_get_title

#define gaim_notify_message    purple_notify_message
#define gaim_notify_email      purple_notify_email
#define gaim_notify_emails     purple_notify_emails
#define gaim_notify_formatted  purple_notify_formatted
#define gaim_notify_userinfo   purple_notify_userinfo

#define gaim_notify_user_info_new                    purple_notify_user_info_new
#define gaim_notify_user_info_destroy                purple_notify_user_info_destroy
#define gaim_notify_user_info_get_entries            purple_notify_user_info_get_entries
#define gaim_notify_user_info_get_text_with_newline  purple_notify_user_info_get_text_with_newline
#define gaim_notify_user_info_add_pair               purple_notify_user_info_add_pair
#define gaim_notify_user_info_prepend_pair           purple_notify_user_info_prepend_pair
#define gaim_notify_user_info_remove_entry           purple_notify_user_info_remove_entry
#define gaim_notify_user_info_entry_new              purple_notify_user_info_entry_new
#define gaim_notify_user_info_add_section_break      purple_notify_user_info_add_section_break
#define gaim_notify_user_info_add_section_header     purple_notify_user_info_add_section_header
#define gaim_notify_user_info_remove_last_item       purple_notify_user_info_remove_last_item
#define gaim_notify_user_info_entry_get_label        purple_notify_user_info_entry_get_label
#define gaim_notify_user_info_entry_set_label        purple_notify_user_info_entry_set_label
#define gaim_notify_user_info_entry_get_value        purple_notify_user_info_entry_get_value
#define gaim_notify_user_info_entry_set_value        purple_notify_user_info_entry_set_value
#define gaim_notify_user_info_entry_get_type         purple_notify_user_info_entry_get_type
#define gaim_notify_user_info_entry_set_type         purple_notify_user_info_entry_set_type

#define gaim_notify_uri                purple_notify_uri
#define gaim_notify_close              purple_notify_close
#define gaim_notify_close_with_handle  purple_notify_close_with_handle

#define gaim_notify_info     purple_notify_info
#define gaim_notify_warning  purple_notify_warning
#define gaim_notify_error    purple_notify_error

#define gaim_notify_set_ui_ops  purple_notify_set_ui_ops
#define gaim_notify_get_ui_ops  purple_notify_get_ui_ops

#define gaim_notify_get_handle  purple_notify_get_handle

#define gaim_notify_init    purple_notify_init
#define gaim_notify_uninit  purple_notify_uninit

#endif /* _GAIM_COMPAT_H_ */

/*
 *------------------------------------------------------------------
 * pppox_api.c - pppox api (stub for VPP v26)
 *
 * Copyright (c) 2017 RaydoNetworks.
 *------------------------------------------------------------------
 */

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>
#include <vlibapi/api_helper_macros.h>

#include <pppox/pppox.h>

#define vl_msg_id(n,h) n,
typedef enum
{
#include <pppox/pppox.api.h>
  /* We'll want to know how many messages IDs we need... */
  VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <pppox/pppox.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <pppox/pppox.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <pppox/pppox.api.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <pppox/pppox.api.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <pppox/pppox.api.h>
#undef vl_msg_name_crc_list

#define REPLY_MSG_ID_BASE pom->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
setup_message_id_table (pppox_main_t * pom, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + pom->msg_id_base);
  foreach_vl_msg_name_crc_pppox;
#undef _
}

#define foreach_pppox_plugin_api_msg                             \
_(PPPOX_SET_AUTH, pppox_set_auth)

static void vl_api_pppox_set_auth_t_handler
  (vl_api_pppox_set_auth_t * mp)
{
  vl_api_pppox_set_auth_reply_t *rmp;
  int rv = 0;
  pppox_main_t *pom = &pppox_main;
  u8 * username = 0, * password = 0;

  int username_len = strlen ((char *) mp->username); vec_resize (username, username_len);
  clib_memcpy (username, mp->username, username_len);
  vec_add1(username, 0);
  int password_len = strlen ((char *) mp->password); vec_resize (password, password_len);
  clib_memcpy (password, mp->password, password_len);
  vec_add1(password, 0);
  rv = pppox_set_auth (ntohl (mp->sw_if_index), username, password);
  vec_free (username);
  vec_free (password);

  REPLY_MACRO(VL_API_PPPOX_SET_AUTH_REPLY);
}

static clib_error_t *
pppox_api_hookup (vlib_main_t * vm)
{
  pppox_main_t *pom = &pppox_main;

  u8 *name = format (0, "pppox_%08x%c", api_version, 0);
  pom->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  /* API handlers stubbed out for VPP v26 compatibility */
  /* The pppox plugin works without API registration */

  setup_message_id_table (pom, &api_main);

  return 0;
}

VLIB_API_INIT_FUNCTION (pppox_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

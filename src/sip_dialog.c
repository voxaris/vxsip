/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "sip_msg.h"
#include "sip_hash.h"
#include "sip_dialog.h"
#include "sip_miscdefs.h"
#include "sip_parse_generic.h"

#define	SIP_DLG_XCHG_FROM	0
#define	SIP_DLG_XCHG_TO		1

/* Dialog state change callback function */
void (*sip_dlg_ulp_state_cb) (sip_dialog_t, sip_msg_t, int, int) = NULL;

boolean_t sip_incomplete_dialog (sip_dialog_t);

/* Exchange From/To header */
_sip_header_t *sip_dlg_xchg_from_to (sip_msg_t, int);

/* Complete dialog hash table */
sip_hash_t sip_dialog_hash[SIP_HASH_SZ];

/* Partial dialog hash table */
sip_hash_t sip_dialog_phash[SIP_HASH_SZ];

/* Route set structure */
typedef struct sip_dlg_route_set_s
{
   char *sip_dlg_route;
   sip_str_t sip_dlg_ruri;
   boolean_t sip_dlg_route_lr;
   struct sip_dlg_route_set_s *sip_dlg_route_next;
} sip_dlg_route_set_t;

sip_dialog_t sip_seed_dialog (sip_conn_object_t, _sip_msg_t *,
                              void (*func) (sip_dialog_t, sip_msg_t, void *), boolean_t, int);
sip_dialog_t sip_complete_dialog (_sip_msg_t *, _sip_dialog_t *, void (*func) (sip_dialog_t, sip_msg_t, void *));
sip_dialog_t sip_dialog_create (_sip_msg_t *, _sip_msg_t *, int);
int sip_dialog_process (_sip_msg_t *, sip_dialog_t *, void (*func) (sip_dialog_t, sip_msg_t, void *));
void sip_dialog_delete (_sip_dialog_t *);
void sip_dialog_init ();
sip_dialog_t sip_dialog_find (_sip_msg_t *);
boolean_t sip_dialog_match (void *, void *);
boolean_t sip_dialog_free (void *, void *, int *);
sip_dialog_t sip_update_dialog (sip_dialog_t, _sip_msg_t *, void (*func) (sip_dialog_t, sip_msg_t, void *));
char *sip_dialog_req_uri (sip_dialog_t);

static void sip_release_dialog_res (_sip_dialog_t *);
void sip_dlg_self_destruct (void *);
static int sip_dialog_get_route_set (_sip_dialog_t *, _sip_msg_t *, int);
static void sip_dialog_free_rset (sip_dlg_route_set_t *);

/* Timer object for partial dialogs */
typedef struct sip_dialog_timer_obj_s
{
   _sip_dialog_t *dialog;
   void (*func) (sip_dialog_t, sip_msg_t, void *);
} sip_dialog_timer_obj_t;

/* To avoid duplication all over the place */
static void sip_release_dialog_res (_sip_dialog_t * dialog)
{

   assert (dialog->sip_dlg_ref_cnt == 0);
   if (SIP_IS_TIMER_RUNNING (dialog->sip_dlg_timer))
      SIP_CANCEL_TIMER (dialog->sip_dlg_timer);
   if (dialog->sip_dlg_call_id != NULL)
      sip_free_header (dialog->sip_dlg_call_id);
   if (dialog->sip_dlg_local_uri_tag != NULL)
      sip_free_header (dialog->sip_dlg_local_uri_tag);
   if (dialog->sip_dlg_remote_uri_tag != NULL)
      sip_free_header (dialog->sip_dlg_remote_uri_tag);
   if (dialog->sip_dlg_remote_target != NULL)
      sip_free_header (dialog->sip_dlg_remote_target);
   if (dialog->sip_dlg_route_set != NULL)
      sip_free_header (dialog->sip_dlg_route_set);
   if (dialog->sip_dlg_event != NULL)
      sip_free_header (dialog->sip_dlg_event);
   if (dialog->sip_dlg_req_uri.sip_str_ptr != NULL)
   {
      free (dialog->sip_dlg_req_uri.sip_str_ptr);
      dialog->sip_dlg_req_uri.sip_str_ptr = NULL;
      dialog->sip_dlg_req_uri.sip_str_len = 0;
   }
   if (dialog->sip_dlg_rset.sip_str_ptr != NULL)
   {
      free (dialog->sip_dlg_rset.sip_str_ptr);
      dialog->sip_dlg_rset.sip_str_len = 0;
      dialog->sip_dlg_rset.sip_str_ptr = NULL;
   }
   (void) pthread_mutex_destroy (&dialog->sip_dlg_mutex);
   free (dialog);
}

/*
 * Get the route information from the 'value' and add it to the route
 * set.
 */
static sip_dlg_route_set_t *sip_add_route_to_set (sip_hdr_value_t * value)
{
   int vlen = 0;
   sip_dlg_route_set_t *rset;
   char *crlf;
   const sip_param_t *uri_param;
   int error;

   rset = calloc (1, sizeof (*rset));
   if (rset == NULL)
      return (NULL);
   rset->sip_dlg_route_next = NULL;
   vlen = value->sip_value_end - value->sip_value_start;

   /* check for CRLF */
   crlf = value->sip_value_end - strlen (SIP_CRLF);
   while (crlf != NULL && strncmp (crlf, SIP_CRLF, strlen (SIP_CRLF)) == 0)
   {
      vlen -= strlen (SIP_CRLF);
      crlf -= strlen (SIP_CRLF);
   }
   rset->sip_dlg_route = calloc (1, vlen + 1);
   if (rset->sip_dlg_route == NULL)
   {
      free (rset);
      return (NULL);
   }
   /* loose routing */
   rset->sip_dlg_route_lr = B_FALSE;
   (void) strncpy (rset->sip_dlg_route, value->sip_value_start, vlen);
   rset->sip_dlg_ruri.sip_str_ptr = rset->sip_dlg_route + (value->cftr_uri.sip_str_ptr - value->sip_value_start);
   rset->sip_dlg_ruri.sip_str_len = value->cftr_uri.sip_str_len;
   rset->sip_dlg_route[vlen] = '\0';

   assert (value->sip_value_parsed_uri != NULL);
   /*
    * Check if the 'lr' param is present for this route.
    */
   uri_param = sip_get_uri_params (value->sip_value_parsed_uri, &error);
   if (error != 0)
   {
      free (rset->sip_dlg_route);
      free (rset);
      return (NULL);
   }
   if (uri_param != NULL)
   {
      rset->sip_dlg_route_lr = sip_is_param_present (uri_param, "lr", strlen ("lr"));
   }
   return (rset);
}

/*
 * Depending on the route-set, determine the request URI.
 */
char *sip_dialog_req_uri (sip_dialog_t dialog)
{
   const sip_str_t *req_uri;
   char *uri;
   _sip_dialog_t *_dialog;

   _dialog = (_sip_dialog_t *) dialog;
   if (_dialog->sip_dlg_route_set == NULL || _dialog->sip_dlg_req_uri.sip_str_ptr == NULL)
   {
      const struct sip_value *val;

      val = sip_get_header_value (_dialog->sip_dlg_remote_target, NULL);
      req_uri = &((sip_hdr_value_t *) val)->cftr_uri;
   }
   else
   {
      req_uri = &_dialog->sip_dlg_req_uri;
   }
   uri = (char *) malloc (req_uri->sip_str_len + 1);
   if (uri == NULL)
      return (NULL);
   (void) strncpy (uri, req_uri->sip_str_ptr, req_uri->sip_str_len);
   uri[req_uri->sip_str_len] = '\0';

   return (uri);
}

/* Free the route set. */
void sip_dialog_free_rset (sip_dlg_route_set_t * rset)
{
   sip_dlg_route_set_t *next;

   while (rset != NULL)
   {
      next = rset->sip_dlg_route_next;
      rset->sip_dlg_route_next = NULL;
      free (rset->sip_dlg_route);
      free (rset);
      rset = next;
   }
}

/* Recompute route-set */
static int sip_dlg_recompute_rset (_sip_dialog_t * dialog, _sip_msg_t * sip_msg, int what)
{
   int ret;

   if (dialog->sip_dlg_route_set != NULL)
   {
      sip_free_header (dialog->sip_dlg_route_set);
      dialog->sip_dlg_route_set = NULL;
   }
   if (dialog->sip_dlg_req_uri.sip_str_ptr != NULL)
   {
      free (dialog->sip_dlg_req_uri.sip_str_ptr);
      dialog->sip_dlg_req_uri.sip_str_ptr = NULL;
      dialog->sip_dlg_req_uri.sip_str_len = 0;
   }
   if (dialog->sip_dlg_rset.sip_str_ptr != NULL)
   {
      free (dialog->sip_dlg_rset.sip_str_ptr);
      dialog->sip_dlg_rset.sip_str_ptr = NULL;
      dialog->sip_dlg_rset.sip_str_len = 0;
   }
   ret = sip_dialog_get_route_set (dialog, sip_msg, what);
   return (ret);
}

/*
 * If the route set is empty, the UAC MUST place the remote target URI
 * into the Request-URI.  The UAC MUST NOT add a Route header field to
 * the request.
 *
 * If the route set is not empty, and the first URI in the route set
 * contains the lr parameter (see Section 19.1.1), the UAC MUST place
 * the remote target URI into the Request-URI and MUST include a Route
 * header field containing the route set values in order, including all
 * parameters.
 *
 * If the route set is not empty, and its first URI does not contain the
 * lr parameter, the UAC MUST place the first URI from the route set
 * into the Request-URI, stripping any parameters that are not allowed
 * in a Request-URI.  The UAC MUST add a Route header field containing
 * the remainder of the route set values in order, including all
 * parameters.  The UAC MUST then place the remote target URI into the
 * Route header field as the last value.
 */
int sip_dialog_set_route_hdr (_sip_dialog_t * dialog, sip_dlg_route_set_t * rset_head, int rcnt, int rlen)
{
   size_t rset_len;
   _sip_header_t *rhdr;
   char *rset;
   char *rp;
   char *rsp;
   int count;
   sip_dlg_route_set_t *route;
   boolean_t first = B_TRUE;
   const sip_str_t *to_uri;
   char *uri = NULL;
   int rspl;
   int rpl;

   assert (rcnt > 0);

   dialog->sip_dlg_rset.sip_str_len = rlen + rcnt - 1;
   dialog->sip_dlg_rset.sip_str_ptr = malloc (rlen + rcnt);
   if (dialog->sip_dlg_rset.sip_str_ptr == NULL)
      return (ENOMEM);
   rsp = dialog->sip_dlg_rset.sip_str_ptr;
   rspl = rlen + rcnt;
   route = rset_head;
   rset_len = rlen;
   if (!route->sip_dlg_route_lr)
   {
      const struct sip_value *val;

      val = sip_get_header_value (dialog->sip_dlg_remote_target, NULL);
      to_uri = &((sip_hdr_value_t *) val)->cftr_uri;
      uri = (char *) malloc (to_uri->sip_str_len + 1);
      if (uri == NULL)
      {
         free (dialog->sip_dlg_rset.sip_str_ptr);
         dialog->sip_dlg_rset.sip_str_len = 0;
         dialog->sip_dlg_rset.sip_str_ptr = NULL;
         return (ENOMEM);
      }
      (void) strncpy (uri, to_uri->sip_str_ptr, to_uri->sip_str_len);
      uri[to_uri->sip_str_len] = '\0';
      rset_len = rlen - strlen (route->sip_dlg_route) + strlen (uri) +
         SIP_SPACE + sizeof (char) + SIP_SPACE + sizeof (char);
      count = snprintf (rsp, rspl, "%s", route->sip_dlg_route);
      dialog->sip_dlg_req_uri.sip_str_ptr = malloc (route->sip_dlg_ruri.sip_str_len + 1);
      if (dialog->sip_dlg_req_uri.sip_str_ptr == NULL)
      {
         free (uri);
         free (dialog->sip_dlg_rset.sip_str_ptr);
         dialog->sip_dlg_rset.sip_str_len = 0;
         dialog->sip_dlg_rset.sip_str_ptr = NULL;
         return (ENOMEM);
      }
      (void) strncpy (dialog->sip_dlg_req_uri.sip_str_ptr, rsp +
                      (route->sip_dlg_ruri.sip_str_ptr - route->sip_dlg_route), route->sip_dlg_ruri.sip_str_len);
      dialog->sip_dlg_req_uri.sip_str_ptr[route->sip_dlg_ruri.sip_str_len] = '\0';
      dialog->sip_dlg_req_uri.sip_str_len = route->sip_dlg_ruri.sip_str_len;

      rsp += count;
      rspl -= count;
      route = route->sip_dlg_route_next;
   }

   /* rcnt - 1 is for the number of COMMAs */
   rset_len += strlen (SIP_ROUTE) + SIP_SPACE + sizeof (char) + SIP_SPACE + rcnt - 1;
   rset = malloc (rset_len + 1);
   if (rset == NULL)
   {
      free (dialog->sip_dlg_rset.sip_str_ptr);
      dialog->sip_dlg_rset.sip_str_len = 0;
      dialog->sip_dlg_rset.sip_str_ptr = NULL;
      return (ENOMEM);
   }
   rhdr = sip_new_header (rset_len + strlen (SIP_CRLF));
   if (rhdr == NULL)
   {
      free (rset);
      free (dialog->sip_dlg_rset.sip_str_ptr);
      dialog->sip_dlg_rset.sip_str_len = 0;
      dialog->sip_dlg_rset.sip_str_ptr = NULL;
      return (ENOMEM);
   }

   rp = rset;
   rpl = rset_len + 1;
   count = snprintf (rp, rpl, "%s %c ", SIP_ROUTE, SIP_HCOLON);
   rp += count;
   rpl -= count;

   while (route != NULL)
   {
      if (first)
      {
         count = snprintf (rp, rpl, "%s", route->sip_dlg_route);
         rp += count;
         rpl -= count;
         first = B_FALSE;
         if (uri != NULL)
         {
            count = snprintf (rsp, rspl, "%c%s", SIP_COMMA, route->sip_dlg_route);
         }
         else
         {
            count = snprintf (rsp, rspl, "%s", route->sip_dlg_route);
         }
         rsp += count;
         rspl -= count;
      }
      else
      {
         count = snprintf (rp, rpl, "%c%s", SIP_COMMA, route->sip_dlg_route);
         rp += count;
         rpl -= count;
         count = snprintf (rsp, rspl, "%c%s", SIP_COMMA, route->sip_dlg_route);
         rsp += count;
         rspl -= count;
      }
      route = route->sip_dlg_route_next;
   }
   assert (rsp <= dialog->sip_dlg_rset.sip_str_ptr + dialog->sip_dlg_rset.sip_str_len);
   dialog->sip_dlg_rset.sip_str_ptr[dialog->sip_dlg_rset.sip_str_len] = '\0';
   if (uri != NULL)
   {
      if (first)
      {
         count = snprintf (rp, rpl, "%c %s %c", SIP_LAQUOT, uri, SIP_RAQUOT);
      }
      else
      {
         count = snprintf (rp, rpl, "%c%c %s %c", SIP_COMMA, SIP_LAQUOT, uri, SIP_RAQUOT);
      }
      rp += count;
      rpl -= count;
      free (uri);
   }
   assert (rp <= rset + rset_len);
   (void) snprintf (rhdr->sip_hdr_start, rset_len + strlen (SIP_CRLF) + 1, "%s%s", rset, SIP_CRLF);
   free (rset);
   dialog->sip_dlg_route_set = (sip_header_t) rhdr;
   sip_dialog_free_rset (rset_head);
   return (0);
}

/*
 * UAC Behavior
 * The route set MUST be set to the list of URIs in the Record-Route
 * header field from the response, taken in reverse order and preserving
 * all URI parameters.
 *
 * UAS behavior
 * The route set MUST be set to the list of URIs in the Record-Route
 * header field from the request, taken in order and preserving all URI
 * parameters.
 */
static int sip_dialog_get_route_set (_sip_dialog_t * dialog, _sip_msg_t * sip_msg, int what)
{
   sip_header_t rrhdr;
   sip_hdr_value_t *value;
   int error;
   sip_dlg_route_set_t *rset_head = NULL;
   sip_dlg_route_set_t *rset_tail = NULL;
   sip_dlg_route_set_t *rset;
   int rset_cnt = 0;
   int rset_len = 0;

   (void) pthread_mutex_lock (&sip_msg->sip_msg_mutex);
   rrhdr = sip_search_for_header (sip_msg, SIP_RECORD_ROUTE, NULL);
   while (rrhdr != NULL)
   {
      (void) pthread_mutex_unlock (&sip_msg->sip_msg_mutex);
      value = (sip_hdr_value_t *) sip_get_header_value (rrhdr, &error);
      while (value != NULL && error == 0)
      {
         char *crlf;

         if (value->sip_value_state == SIP_VALUE_BAD)
         {
            value = (sip_hdr_value_t *) sip_get_next_value ((sip_header_value_t) value, &error);
            continue;
         }
         rset = sip_add_route_to_set (value);
         if (rset == NULL)
            goto r_error;
         /* Add one for COMMA */
         rset_cnt++;
         rset_len += (value->sip_value_end - value->sip_value_start);
         /* Check for CRLF */
         crlf = value->sip_value_end - strlen (SIP_CRLF);
         while (crlf != NULL && strncmp (crlf, SIP_CRLF, strlen (SIP_CRLF)) == 0)
         {
            rset_len -= strlen (SIP_CRLF);
            crlf -= strlen (SIP_CRLF);
         }
         if (rset_head == NULL)
         {
            assert (rset_tail == NULL);
            rset_head = rset_tail = rset;
         }
         else if (what == SIP_UAS_DIALOG)
         {
            rset_tail->sip_dlg_route_next = rset;
            rset_tail = rset;
         }
         else if (what == SIP_UAC_DIALOG)
         {
            rset->sip_dlg_route_next = rset_head;
            rset_head = rset;
         }
         else
         {
            assert (0);
         }
         value = (sip_hdr_value_t *) sip_get_next_value ((sip_header_value_t) value, &error);
      }
      (void) pthread_mutex_lock (&sip_msg->sip_msg_mutex);
      rrhdr = sip_search_for_header (sip_msg, SIP_RECORD_ROUTE, rrhdr);
   }
   (void) pthread_mutex_unlock (&sip_msg->sip_msg_mutex);
   if (rset_cnt == 0)
      return (0);
   if (sip_dialog_set_route_hdr (dialog, rset_head, rset_cnt, rset_len) != 0)
   {
      goto r_error;
   }
   return (0);
 r_error:
   sip_dialog_free_rset (rset_head);
   return (ENOMEM);
}

/*
 * UAS behavior:
 * The remote sequence number MUST be set to the value of the sequence
 * number in the CSeq header field of the request.  The local sequence
 * number MUST be empty.  The call identifier component of the dialog ID
 * MUST be set to the value of the Call-ID in the request.  The local
 * tag component of the dialog ID MUST be set to the tag in the To field
 * in the response to the request (which always includes a tag), and the
 * remote tag component of the dialog ID MUST be set to the tag from the
 * From field in the request.  A UAS MUST be prepared to receive a
 * request without a tag in the From field, in which case the tag is
 * considered to have a value of null.
 * The remote URI MUST be set to the URI in the From field, and the
 * local URI MUST be set to the URI in the To field.
 * The remote target MUST be set to the URI from the Contact header field
 * of the request.
 *
 * UAC behavior:
 * The local sequence number MUST be set to the value of the sequence
 * number in the CSeq header field of the request.  The remote sequence
 * number MUST be empty (it is established when the remote UA sends a
 * request within the dialog).  The call identifier component of the
 * dialog ID MUST be set to the value of the Call-ID in the request.
 * The local tag component of the dialog ID MUST be set to the tag in
 * the From field in the request, and the remote tag component of the
 * dialog ID MUST be set to the tag in the To field of the response.  A
 * UAC MUST be prepared to receive a response without a tag in the To
 * field, in which case the tag is considered to have a value of null.
 * The remote URI MUST be set to the URI in the To field, and the local
 * URI MUST be set to the URI in the From field.
 * The remote target MUST be set to the URI from the Contact header field
 * of the response.
 */


/*
 * This is the routine that seeds a dialog.
 */
sip_dialog_t
sip_seed_dialog (sip_conn_object_t obj, _sip_msg_t * sip_msg,
                 void (*func) (sip_dialog_t, sip_msg_t, void *), boolean_t dlg_on_fork, int dlg_type)
{
   _sip_dialog_t *dialog;
   int cseq;
   sip_header_t fhdr = NULL;
   sip_header_t thdr = NULL;
   sip_header_t chdr;
   sip_header_t cihdr;
   sip_header_t evhdr = NULL;
   const struct sip_value *value;
   sip_dialog_timer_obj_t *tim_obj = NULL;
   const sip_str_t *callid;
   sip_method_t method;
   int timer1 = sip_timer_T1;
   int error;

   if (!sip_msg_is_request ((sip_msg_t) sip_msg, &error))
      return (NULL);
   method = sip_get_request_method ((sip_msg_t) sip_msg, &error);
   /* Only INVITE and SUBSCRIBE supported */
   if (error != 0 || (method != INVITE && method != SUBSCRIBE))
      return (NULL);

   if (dlg_type == SIP_UAS_DIALOG)
   {
      thdr = sip_dlg_xchg_from_to ((sip_msg_t) sip_msg, SIP_DLG_XCHG_FROM);
      (void) pthread_mutex_lock (&sip_msg->sip_msg_mutex);
   }
   else
   {
      (void) pthread_mutex_lock (&sip_msg->sip_msg_mutex);
      fhdr = sip_search_for_header (sip_msg, SIP_FROM, NULL);
   }
   cihdr = sip_search_for_header (sip_msg, SIP_CALL_ID, NULL);
   chdr = sip_search_for_header (sip_msg, SIP_CONTACT, NULL);
   if (method == SUBSCRIBE)
      evhdr = sip_search_for_header (sip_msg, SIP_EVENT, NULL);
   (void) pthread_mutex_unlock (&sip_msg->sip_msg_mutex);
   if ((fhdr == NULL && thdr == NULL) || cihdr == NULL || chdr == NULL || (method == SUBSCRIBE && evhdr == NULL))
   {
      return (NULL);
   }

   /* Sanity check since we just store the headers in the dialog */
   if (sip_get_from_tag ((sip_msg_t) sip_msg, NULL) == NULL ||
       sip_get_from_uri_str ((sip_msg_t) sip_msg, NULL) == NULL ||
       ((cseq = sip_get_callseq_num ((sip_msg_t) sip_msg, NULL)) == -1) ||
       (callid = sip_get_callid ((sip_msg_t) sip_msg, NULL)) == NULL ||
       sip_get_to_uri_str ((sip_msg_t) sip_msg, NULL) == NULL ||
       ((value = sip_get_header_value (chdr, NULL)) == NULL) ||
       sip_get_contact_uri_str ((sip_header_value_t) value, NULL) == NULL)
   {
      return (NULL);
   }

   tim_obj = malloc (sizeof (sip_dialog_timer_obj_t));
   if (tim_obj == NULL)
      return (NULL);
   dialog = calloc (1, sizeof (_sip_dialog_t));
   if (dialog == NULL)
      return (NULL);

   /*
    * We will take the TO header with the tag when we complete this
    * dialog
    */
   if (dlg_type == SIP_UAS_DIALOG)
   {
      dialog->sip_dlg_remote_uri_tag = thdr;
   }
   else
   {
      if ((dialog->sip_dlg_local_uri_tag = sip_dup_header (fhdr)) == NULL)
      {
         goto dia_err;
      }
   }
   if ((dialog->sip_dlg_remote_target = sip_dup_header (chdr)) == NULL ||
       (dialog->sip_dlg_call_id = sip_dup_header (cihdr)) == NULL)
   {
      goto dia_err;
   }
   if (method == SUBSCRIBE)
   {
      dialog->sip_dlg_event = sip_dup_header (evhdr);
      if (dialog->sip_dlg_event == NULL)
      {
         goto dia_err;
      }
   }
   dialog->sip_dlg_rset.sip_str_ptr = NULL;
   dialog->sip_dlg_rset.sip_str_len = 0;
   dialog->sip_dlg_req_uri.sip_str_ptr = NULL;
   dialog->sip_dlg_req_uri.sip_str_len = 0;
   /* Get the route set from the request, if present */
   if (sip_dialog_get_route_set (dialog, sip_msg, dlg_type) != 0)
   {
      goto dia_err;
   }
   if (dlg_type == SIP_UAC_DIALOG)
      dialog->sip_dlg_local_cseq = cseq;
   else
      dialog->sip_dlg_remote_cseq = cseq;
   dialog->sip_dlg_type = dlg_type;
   dialog->sip_dlg_on_fork = dlg_on_fork;
   dialog->sip_dlg_method = method;
   /* Set the partial dialog timer with the INVITE timeout val */
   if (sip_conn_timer1 != NULL)
      timer1 = sip_conn_timer1 (obj);
   SIP_INIT_TIMER (dialog->sip_dlg_timer, 64 * timer1);
   tim_obj->dialog = dialog;
   tim_obj->func = func;
   SIP_SCHED_TIMER (dialog->sip_dlg_timer, (void *) tim_obj, sip_dlg_self_destruct);
   if (!SIP_IS_TIMER_RUNNING (dialog->sip_dlg_timer))
      goto dia_err;
   (void) pthread_mutex_init (&dialog->sip_dlg_mutex, NULL);

   if (dlg_type == SIP_UAC_DIALOG)
   {
      const sip_str_t *local_tag;

      local_tag = sip_get_from_tag ((sip_msg_t) sip_msg, NULL);
      assert (local_tag != NULL);
      sip_md5_hash (local_tag->sip_str_ptr, local_tag->sip_str_len,
                    callid->sip_str_ptr, callid->sip_str_len,
                    NULL, 0, NULL, 0, NULL, 0, NULL, 0, (uchar_t *) dialog->sip_dlg_id);

      SIP_DLG_REFCNT_INCR (dialog);

      /* Add it to the partial hash table */
      if (sip_hash_add (sip_dialog_phash, (void *) dialog, SIP_DIGEST_TO_HASH (dialog->sip_dlg_id)) != 0)
      {
         goto dia_err;
      }
   }
   return ((sip_dialog_t) dialog);
 dia_err:
   sip_release_dialog_res (dialog);
   if (tim_obj != NULL)
      free (tim_obj);
   return (NULL);
}

/*
 * When creating a dialog from a NOTIFY request, we need to get the FROM
 * header for the dialog from the TO header of the NOTIFY.
 */
_sip_header_t *sip_dlg_xchg_from_to (sip_msg_t sip_msg, int what)
{
   int len;
   _sip_header_t *newhdr;
   int cnt;
   const struct sip_header *hdr;
   int hdrsize;
   int error;

   hdr = sip_get_header (sip_msg, what == SIP_DLG_XCHG_FROM ? SIP_FROM : SIP_TO, NULL, &error);
   if (error != 0 || hdr == NULL)
      return (NULL);
   if (sip_parse_goto_values ((_sip_header_t *) hdr) != 0)
      return (NULL);
   len = hdr->sip_hdr_end - hdr->sip_hdr_current;
   if (what == SIP_DLG_XCHG_FROM)
   {
      hdrsize = len + strlen (SIP_TO) + SIP_SPACE + sizeof (char) + SIP_SPACE;
   }
   else
   {
      hdrsize = len + strlen (SIP_FROM) + SIP_SPACE + sizeof (char) + SIP_SPACE;
   }
   newhdr = sip_new_header (hdrsize);
   if (newhdr == NULL)
      return (NULL);
   if (what == SIP_DLG_XCHG_FROM)
   {
      cnt = snprintf (newhdr->sip_hdr_current, hdrsize + 1, "%s %c ", SIP_TO, SIP_HCOLON);
   }
   else
   {
      cnt = snprintf (newhdr->sip_hdr_current, hdrsize + 1, "%s %c ", SIP_FROM, SIP_HCOLON);
   }
   newhdr->sip_hdr_current += cnt;
   (void) strncpy (newhdr->sip_hdr_current, hdr->sip_hdr_current, len);
   newhdr->sip_hdr_current += len;
   assert (newhdr->sip_hdr_current == newhdr->sip_hdr_end);
   assert (hdr->sip_header_functions != NULL);

   /* FROM and TO have common parsing functions */
   newhdr->sip_header_functions = hdr->sip_header_functions;
   newhdr->sip_hdr_current = newhdr->sip_hdr_start;

   return (newhdr);
}

/*
 * This is the response that completes the dialog that was created
 * in sip_seed_dialog().
 */
sip_dialog_t
sip_complete_dialog (_sip_msg_t * sip_msg, _sip_dialog_t * dialog, void (*func) (sip_dialog_t, sip_msg_t, void *))
{
   _sip_header_t *thdr;
   _sip_header_t *evhdr = NULL;
   _sip_header_t *substate = NULL;
   int resp_code;
   const sip_str_t *ttag;
   const sip_str_t *remtag;
   const sip_str_t *callid;
   const struct sip_value *val;
   sip_method_t method;
   int error = 0;
   int prev_state;

   if (sip_msg_is_request ((sip_msg_t) sip_msg, &error) && error == 0)
      method = sip_get_request_method ((sip_msg_t) sip_msg, &error);
   else
      method = sip_get_callseq_method ((sip_msg_t) sip_msg, &error);
   if (error != 0 || dialog == NULL ||
       (sip_msg_is_request ((sip_msg_t) sip_msg, &error) && (dialog->sip_dlg_method == INVITE || method != NOTIFY)))
   {
      return (NULL);
   }
   if ((dialog->sip_dlg_type == SIP_UAC_DIALOG && method != NOTIFY &&
        sip_get_callseq_num ((sip_msg_t) sip_msg, NULL) !=
        dialog->sip_dlg_local_cseq) ||
       (dialog->sip_dlg_type == SIP_UAS_DIALOG && method != NOTIFY &&
        sip_get_callseq_num ((sip_msg_t) sip_msg, NULL) != dialog->sip_dlg_remote_cseq))
   {
      return (NULL);
   }
   if (method == NOTIFY)
   {
      const sip_str_t *sstate;

      thdr = sip_dlg_xchg_from_to ((sip_msg_t) sip_msg, SIP_DLG_XCHG_FROM);
      (void) pthread_mutex_lock (&sip_msg->sip_msg_mutex);
      evhdr = sip_search_for_header (sip_msg, SIP_EVENT, NULL);
      if (evhdr == NULL)
      {
         (void) pthread_mutex_unlock (&sip_msg->sip_msg_mutex);
         return (NULL);
      }
      substate = sip_search_for_header (sip_msg, SIP_SUBSCRIPTION_STATE, NULL);
      if (substate == NULL)
      {
         (void) pthread_mutex_unlock (&sip_msg->sip_msg_mutex);
         return (NULL);
      }
      (void) pthread_mutex_unlock (&sip_msg->sip_msg_mutex);
      sstate = sip_get_substate ((sip_msg_t) sip_msg, &error);
      if (sstate == NULL || error != 0)
      {
         return (NULL);
      }
      if ((sstate->sip_str_len != strlen ("pending") &&
           sstate->sip_str_len != strlen ("active")) ||
          ((sstate->sip_str_len == strlen ("pending") &&
            strncasecmp (sstate->sip_str_ptr, "pending",
                         strlen ("pending")) != 0) ||
           (sstate->sip_str_len == strlen ("active") &&
            strncasecmp (sstate->sip_str_ptr, "active", strlen ("active")) != 0)))
      {
         return (NULL);
      }
      ttag = sip_get_from_tag ((sip_msg_t) sip_msg, NULL);
   }
   else
   {
      if (dialog->sip_dlg_type == SIP_UAS_DIALOG)
      {
         thdr = sip_dlg_xchg_from_to ((sip_msg_t) sip_msg, SIP_DLG_XCHG_TO);
      }
      else
      {
         (void) pthread_mutex_lock (&sip_msg->sip_msg_mutex);
         thdr = sip_search_for_header (sip_msg, SIP_TO, NULL);
         (void) pthread_mutex_unlock (&sip_msg->sip_msg_mutex);
      }
      if (thdr == NULL)
      {
         (void) pthread_mutex_unlock (&sip_msg->sip_msg_mutex);
         return (NULL);
      }
      ttag = sip_get_to_tag ((sip_msg_t) sip_msg, NULL);
   }
   if (ttag == NULL)
      return (NULL);
   prev_state = dialog->sip_dlg_state;

   if (method == NOTIFY)
   {
      int error;
      const sip_str_t *dlg_id_val = NULL;
      const sip_str_t *event;
      const sip_str_t *id_val = NULL;
      sip_header_value_t ev_val;
      sip_hdr_value_t *dlg_ev_val = NULL;

      event = sip_get_event ((sip_msg_t) sip_msg, &error);
      if (event == NULL || error != 0)
         return (NULL);
      ev_val = (sip_header_value_t) sip_get_header_value (evhdr, &error);
      if (ev_val != NULL)
         id_val = sip_get_param_value (ev_val, "id", &error);
      if (error == 0)
      {
         dlg_ev_val = (sip_hdr_value_t *) sip_get_header_value (dialog->sip_dlg_event, &error);
      }
      if (dlg_ev_val == NULL || error != 0)
         return (NULL);
      dlg_id_val = sip_get_param_value ((sip_header_value_t) dlg_ev_val, "id", &error);
      if (error != 0 ||
          dlg_ev_val->str_val_len != event->sip_str_len ||
          strncmp (dlg_ev_val->str_val_ptr, event->sip_str_ptr, event->sip_str_len != 0))
      {
         return (NULL);
      }
      if ((dlg_id_val == NULL && id_val != NULL) || (dlg_id_val != NULL && id_val == NULL))
      {
         return (NULL);
      }
      else if (dlg_id_val != NULL && id_val != NULL)
      {
         if (dlg_id_val->sip_str_len != id_val->sip_str_len ||
             strncasecmp (dlg_id_val->sip_str_ptr, id_val->sip_str_ptr, dlg_id_val->sip_str_len) != 0)
         {
            return (NULL);
         }
      }
      dialog->sip_dlg_state = SIP_DLG_CONFIRMED;
      if (dialog->sip_dlg_type == SIP_UAC_DIALOG)
         dialog->sip_dlg_remote_uri_tag = thdr;
      else
         dialog->sip_dlg_local_uri_tag = thdr;
   }
   else
   {
      resp_code = sip_get_response_code ((sip_msg_t) sip_msg, &error);
      (void) pthread_mutex_lock (&dialog->sip_dlg_mutex);
      assert (dialog->sip_dlg_state == SIP_DLG_NEW);
      if (SIP_PROVISIONAL_RESP (resp_code))
      {
         dialog->sip_dlg_state = SIP_DLG_EARLY;
      }
      else if (SIP_OK_RESP (resp_code))
      {
         dialog->sip_dlg_state = SIP_DLG_CONFIRMED;
      }
      else
      {
         dialog->sip_dlg_state = SIP_DLG_DESTROYED;
         (void) pthread_mutex_unlock (&dialog->sip_dlg_mutex);
         if (func != NULL)
            func (dialog, (sip_msg_t) sip_msg, NULL);
         sip_release_dialog_res (dialog);
         return (NULL);
      }
      if (dialog->sip_dlg_type == SIP_UAS_DIALOG)
      {
         dialog->sip_dlg_local_uri_tag = thdr;
      }
      else
      {
         if ((dialog->sip_dlg_remote_uri_tag = sip_dup_header (thdr)) == NULL)
         {
            (void) pthread_mutex_unlock (&dialog->sip_dlg_mutex);
            return (NULL);      /* XXXDestroy dialog? */
         }
      }
   }

   /* Cancel the partial dialog timer */
   if (SIP_IS_TIMER_RUNNING (dialog->sip_dlg_timer))
      SIP_CANCEL_TIMER (dialog->sip_dlg_timer);

   if (dialog->sip_dlg_type == SIP_UAC_DIALOG)
   {
      val = sip_get_header_value (dialog->sip_dlg_local_uri_tag, &error);
   }
   else
   {
      val = sip_get_header_value (dialog->sip_dlg_remote_uri_tag, &error);
   }
   assert (val != NULL && error == 0);
   remtag = sip_get_param_value ((sip_header_value_t) val, "tag", &error);

   val = sip_get_header_value (dialog->sip_dlg_call_id, &error);
   callid = &((sip_hdr_value_t *) val)->str_val;

   /* Get an ID for this dialog */
   if (dialog->sip_dlg_type == SIP_UAC_DIALOG)
   {
      sip_md5_hash (remtag->sip_str_ptr, remtag->sip_str_len,
                    ttag->sip_str_ptr, ttag->sip_str_len,
                    callid->sip_str_ptr, callid->sip_str_len,
                    NULL, 0, NULL, 0, NULL, 0, (uchar_t *) dialog->sip_dlg_id);
   }
   else
   {
      sip_md5_hash (ttag->sip_str_ptr, ttag->sip_str_len,
                    remtag->sip_str_ptr, remtag->sip_str_len,
                    callid->sip_str_ptr, callid->sip_str_len,
                    NULL, 0, NULL, 0, NULL, 0, (uchar_t *) dialog->sip_dlg_id);
   }

   SIP_DLG_REFCNT_INCR (dialog);
   (void) pthread_mutex_unlock (&dialog->sip_dlg_mutex);

   /* Add it to the hash table */
   if (sip_hash_add (sip_dialog_hash, (void *) dialog, SIP_DIGEST_TO_HASH (dialog->sip_dlg_id)) != 0)
   {
      sip_release_dialog_res (dialog);
      return (NULL);
   }
   if (sip_dlg_ulp_state_cb != NULL)
   {
      sip_dlg_ulp_state_cb ((sip_dialog_t) dialog, (sip_msg_t) sip_msg, prev_state, dialog->sip_dlg_state);
   }
   return ((sip_dialog_t) dialog);
}

/*
 * For a UAC just giving the RESPONSE/NOTIFY to the INVITE/SUBSCRIBE is enough,
 * we can get all the info. from it. However, on the UAS side we would need
 * the original request INVITE/SUBSCRIBE and the response RESPONSE/NOTIFY
 * since we don't have the remote target (CONTACT) info. in the response/notify.
 */
sip_dialog_t sip_dialog_create (_sip_msg_t * resp, _sip_msg_t * req, int what)
{
   _sip_dialog_t *dialog;
   _sip_header_t *fhdr;
   _sip_header_t *thdr;
   _sip_header_t *chdr;
   _sip_header_t *cihdr;
   const sip_str_t *ltag;
   const sip_str_t *ttag;
   const sip_str_t *callid;
   int cseq;
   const struct sip_value *value;
   int resp_code;
   int error = 0;
   int prev_state;
   sip_method_t method = 0;

   if (what == SIP_UAS_DIALOG)
   {
      if (req == NULL ||
          !sip_msg_is_request ((sip_msg_t) req, &error) || error != 0 ||
          (sip_get_request_method ((sip_msg_t) req, &error) != INVITE &&
           sip_get_request_method ((sip_msg_t) req, &error) != SUBSCRIBE))
      {
         return (NULL);
      }
   }
   if (sip_msg_is_request ((sip_msg_t) resp, &error))
   {
      /* Only NOTIFY request can create a dialog */
      method = sip_get_request_method ((sip_msg_t) resp, &error);
      if (method != NOTIFY)
         return (NULL);
   }
   else
   {
      /* Only response to an INVITE/SUBSCRIBE can create a dialog */
      resp_code = sip_get_response_code ((sip_msg_t) resp, &error);
      if (error == 0)
      {
         method = sip_get_callseq_method ((sip_msg_t) resp, &error);
      }
      if (error != 0 || (!SIP_PROVISIONAL_RESP (resp_code) &&
                         !SIP_OK_RESP (resp_code)) || (method != INVITE && method != SUBSCRIBE))
      {
         return (NULL);
      }
   }
   (void) pthread_mutex_lock (&resp->sip_msg_mutex);
   if (what == SIP_UAS_DIALOG)
   {
      if (method == NOTIFY)
      {
         fhdr = sip_search_for_header (resp, SIP_FROM, NULL);
         thdr = sip_search_for_header (resp, SIP_TO, NULL);
      }
      else
      {
         fhdr = sip_search_for_header (resp, SIP_TO, NULL);
         thdr = sip_search_for_header (resp, SIP_FROM, NULL);
      }
      (void) pthread_mutex_lock (&req->sip_msg_mutex);
      chdr = sip_search_for_header (req, SIP_CONTACT, NULL);
      (void) pthread_mutex_unlock (&req->sip_msg_mutex);
   }
   else
   {
      if (method == NOTIFY)
      {
         thdr = sip_search_for_header (resp, SIP_FROM, NULL);
         fhdr = sip_search_for_header (resp, SIP_TO, NULL);
      }
      else
      {
         fhdr = sip_search_for_header (resp, SIP_FROM, NULL);
         thdr = sip_search_for_header (resp, SIP_TO, NULL);
      }
      chdr = sip_search_for_header (resp, SIP_CONTACT, NULL);
   }
   cihdr = sip_search_for_header (resp, SIP_CALL_ID, NULL);
   (void) pthread_mutex_unlock (&resp->sip_msg_mutex);
   if (fhdr == NULL || thdr == NULL || cihdr == NULL)
      return (NULL);
   /* Sanity check since we just store the headers in the dialog */
   if (((ltag = sip_get_from_tag ((sip_msg_t) resp, NULL)) == NULL) ||
       sip_get_from_uri_str ((sip_msg_t) resp, NULL) == NULL ||
       ((ttag = sip_get_to_tag ((sip_msg_t) resp, NULL)) == NULL) ||
       sip_get_to_uri_str ((sip_msg_t) resp, NULL) == NULL ||
       ((cseq = sip_get_callseq_num ((sip_msg_t) resp, NULL)) == -1) ||
       ((callid = sip_get_callid ((sip_msg_t) resp, NULL)) == NULL) ||
       ((value = sip_get_header_value (chdr, NULL)) == NULL) ||
       sip_get_contact_uri_str ((sip_header_value_t) value, NULL) == NULL)
   {
      return (NULL);
   }

   dialog = calloc (1, sizeof (_sip_dialog_t));
   if (dialog == NULL)
      return (NULL);
   dialog->sip_dlg_local_cseq = cseq;
   dialog->sip_dlg_type = what;
   dialog->sip_dlg_method = method == NOTIFY ? SUBSCRIBE : method;

   /* this is just 0 */
   prev_state = dialog->sip_dlg_state;

   if ((dialog->sip_dlg_remote_uri_tag = sip_dup_header (thdr)) == NULL ||
       (dialog->sip_dlg_local_uri_tag = sip_dup_header (fhdr)) == NULL ||
       (dialog->sip_dlg_remote_target = sip_dup_header (chdr)) == NULL ||
       (dialog->sip_dlg_call_id = sip_dup_header (cihdr)) == NULL)
   {
      goto error;
   }
   dialog->sip_dlg_rset.sip_str_ptr = NULL;
   dialog->sip_dlg_rset.sip_str_len = 0;
   dialog->sip_dlg_req_uri.sip_str_ptr = NULL;
   dialog->sip_dlg_req_uri.sip_str_len = 0;
   if (sip_dialog_get_route_set (dialog, resp, what) != 0)
      goto error;
   /* Get an ID for this dialog */
   sip_md5_hash (ltag->sip_str_ptr, ltag->sip_str_len,
                 ttag->sip_str_ptr, ttag->sip_str_len,
                 callid->sip_str_ptr, callid->sip_str_len, NULL, 0, NULL, 0, NULL, 0, (uchar_t *) dialog->sip_dlg_id);

   SIP_DLG_REFCNT_INCR (dialog);
   (void) pthread_mutex_init (&dialog->sip_dlg_mutex, NULL);

   /* Add it to the hash table */
   if (sip_hash_add (sip_dialog_hash, (void *) dialog, SIP_DIGEST_TO_HASH (dialog->sip_dlg_id)) != 0)
   {
      sip_release_dialog_res (dialog);
      return (NULL);
   }
   if (sip_dlg_ulp_state_cb != NULL)
   {
      sip_dlg_ulp_state_cb ((sip_dialog_t) dialog, (sip_msg_t) resp, prev_state, dialog->sip_dlg_state);
   }
   return ((sip_dialog_t) dialog);
 error:
   sip_release_dialog_res (dialog);
   return (NULL);
}

/*
 * Check if this dialog is a match.
 */
boolean_t sip_dialog_match (void *obj, void *hindex)
{
   _sip_dialog_t *dialog = (_sip_dialog_t *) obj;

   (void) pthread_mutex_lock (&dialog->sip_dlg_mutex);
   if (dialog->sip_dlg_state == SIP_DLG_DESTROYED)
   {
      (void) pthread_mutex_unlock (&dialog->sip_dlg_mutex);
      return (B_FALSE);
   }
   if (bcmp (dialog->sip_dlg_id, hindex, sizeof (dialog->sip_dlg_id)) == 0)
   {
      SIP_DLG_REFCNT_INCR (dialog);
      (void) pthread_mutex_unlock (&dialog->sip_dlg_mutex);
      return (B_TRUE);
   }
   (void) pthread_mutex_unlock (&dialog->sip_dlg_mutex);
   return (B_FALSE);
}

/* Don't delete, just take it out of the hash */
boolean_t sip_dialog_dontfree (void *obj, void *hindex, int *found)
{
   _sip_dialog_t *dialog = (_sip_dialog_t *) obj;

   *found = 0;
   (void) pthread_mutex_lock (&dialog->sip_dlg_mutex);
   if (bcmp (dialog->sip_dlg_id, hindex, sizeof (dialog->sip_dlg_id)) == 0)
   {
      *found = 1;
      (void) pthread_mutex_unlock (&dialog->sip_dlg_mutex);
      return (B_TRUE);
   }
   (void) pthread_mutex_unlock (&dialog->sip_dlg_mutex);
   return (B_FALSE);
}

/*
 * Free resources associated with the dialog, the object will be removed
 * from the hash list by sip_hash_delete.
 */
boolean_t sip_dialog_free (void *obj, void *hindex, int *found)
{
   _sip_dialog_t *dialog = (_sip_dialog_t *) obj;

   *found = 0;
   (void) pthread_mutex_lock (&dialog->sip_dlg_mutex);
   if (bcmp (dialog->sip_dlg_id, hindex, sizeof (dialog->sip_dlg_id)) == 0)
   {
      *found = 1;
      assert (dialog->sip_dlg_state == SIP_DLG_DESTROYED);
      if (dialog->sip_dlg_ref_cnt != 0)
      {
         (void) pthread_mutex_unlock (&dialog->sip_dlg_mutex);
         return (B_FALSE);
      }
      (void) pthread_mutex_unlock (&dialog->sip_dlg_mutex);
      sip_release_dialog_res (dialog);
      return (B_TRUE);
   }
   (void) pthread_mutex_unlock (&dialog->sip_dlg_mutex);
   return (B_FALSE);
}

/*
 * The UAS will receive the request from the transaction layer.  If the
 * request has a tag in the To header field, the UAS core computes the
 * dialog identifier corresponding to the request and compares it with
 * existing dialogs.  If there is a match, this is a mid-dialog request.
 */
sip_dialog_t sip_dialog_find (_sip_msg_t * sip_msg)
{
   const sip_str_t *localtag;
   const sip_str_t *remtag;
   const sip_str_t *callid;
   uint16_t digest[8];
   _sip_dialog_t *dialog;
   boolean_t is_request;
   int error;

   is_request = sip_msg_is_request ((sip_msg_t) sip_msg, &error);
   if (error != 0)
      return (NULL);
   if (is_request)
   {
      localtag = sip_get_to_tag ((sip_msg_t) sip_msg, &error);
      if (error == 0)
         remtag = sip_get_from_tag ((sip_msg_t) sip_msg, &error);
   }
   else
   {
      remtag = sip_get_to_tag ((sip_msg_t) sip_msg, &error);
      if (error == 0)
         localtag = sip_get_from_tag ((sip_msg_t) sip_msg, &error);
   }
   if (error != 0)
      return (NULL);
   callid = sip_get_callid ((sip_msg_t) sip_msg, &error);
   if (error != 0 || remtag == NULL || localtag == NULL || callid == NULL)
   {
      return (NULL);
   }
   sip_md5_hash (localtag->sip_str_ptr, localtag->sip_str_len,
                 remtag->sip_str_ptr, remtag->sip_str_len,
                 callid->sip_str_ptr, callid->sip_str_len, NULL, 0, NULL, 0, NULL, 0, (uchar_t *) digest);

   dialog = (_sip_dialog_t *) sip_hash_find (sip_dialog_hash,
                                             (void *) digest, SIP_DIGEST_TO_HASH (digest), sip_dialog_match);
   if (dialog == NULL)
   {
      sip_md5_hash (localtag->sip_str_ptr, localtag->sip_str_len,
                    NULL, 0, callid->sip_str_ptr, callid->sip_str_len, NULL, 0, NULL, 0, NULL, 0, (uchar_t *) digest);
      dialog = (_sip_dialog_t *) sip_hash_find (sip_dialog_phash,
                                                (void *) digest, SIP_DIGEST_TO_HASH (digest), sip_dialog_match);
   }
   return ((sip_dialog_t) dialog);
}

/*
 * We keep this partial dialog for the duration of the INVITE
 * transaction timeout duration, i.e. Timer B.
 */
void sip_dlg_self_destruct (void *args)
{
   sip_dialog_timer_obj_t *tim_obj = (sip_dialog_timer_obj_t *) args;
   _sip_dialog_t *dialog = (_sip_dialog_t *) tim_obj->dialog;
   int index;

   if (dialog->sip_dlg_type == SIP_UAC_DIALOG)
      SIP_DLG_REFCNT_DECR (dialog);
   (void) pthread_mutex_lock (&dialog->sip_dlg_mutex);
   assert (dialog->sip_dlg_state == SIP_DLG_NEW);
   dialog->sip_dlg_state = SIP_DLG_DESTROYED;
   (void) pthread_mutex_unlock (&dialog->sip_dlg_mutex);
   if (dialog->sip_dlg_type == SIP_UAC_DIALOG)
   {
      index = SIP_DIGEST_TO_HASH (dialog->sip_dlg_id);
      sip_hash_delete (sip_dialog_phash, (void *) dialog->sip_dlg_id, index, sip_dialog_dontfree);
   }
   if (tim_obj->func != NULL)
      tim_obj->func (dialog, NULL, NULL);
   sip_release_dialog_res (dialog);
   free (tim_obj);
}

/* Terminate a dialog */
void sip_dialog_terminate (_sip_dialog_t * dialog, sip_msg_t sip_msg)
{
   int prev_state;

   (void) pthread_mutex_lock (&dialog->sip_dlg_mutex);
   prev_state = dialog->sip_dlg_state;
   dialog->sip_dlg_state = SIP_DLG_DESTROYED;
   (void) pthread_mutex_unlock (&dialog->sip_dlg_mutex);
   if (sip_dlg_ulp_state_cb != NULL)
   {
      sip_dlg_ulp_state_cb ((sip_dialog_t) dialog, sip_msg, prev_state, dialog->sip_dlg_state);
   }
   SIP_DLG_REFCNT_DECR (dialog);
}

/* Delete a dialog */
void sip_dialog_delete (_sip_dialog_t * dialog)
{
   int index;

   index = SIP_DIGEST_TO_HASH (dialog->sip_dlg_id);
   sip_hash_delete (sip_dialog_hash, (void *) dialog->sip_dlg_id, index, sip_dialog_free);
}

/* Process an incoming request/response */
/* ARGSUSED */
int sip_dialog_process (_sip_msg_t * sip_msg, sip_dialog_t * sip_dialog, void (*func) (sip_dialog_t, sip_msg_t, void *))
{
   boolean_t request;
   _sip_dialog_t *_dialog;
   int error;

   request = sip_msg_is_request ((sip_msg_t) sip_msg, &error);
   if (error != 0)
      return (EINVAL);
   _dialog = (_sip_dialog_t *) * sip_dialog;
   if (request)
   {
      uint32_t cseq;

      (void) pthread_mutex_lock (&_dialog->sip_dlg_mutex);
      cseq = sip_get_callseq_num (sip_msg, &error);
      if (error != 0 || ((_dialog->sip_dlg_remote_cseq != 0) && (SIP_CSEQ_LT (cseq, _dialog->sip_dlg_remote_cseq))))
      {
         (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
         /* Send CALL_NON_EXISTANT response?? */
         return (EPROTO);
      }
      _dialog->sip_dlg_remote_cseq = cseq;
      (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
   }
   else
   {
      int resp_code;
      sip_method_t method;
      int error;

      resp_code = sip_get_response_code ((sip_msg_t) sip_msg, &error);
      if (error == 0)
      {
         method = sip_get_callseq_method ((sip_msg_t) sip_msg, &error);
      }
      if (error != 0)
         return (error);

      (void) pthread_mutex_lock (&_dialog->sip_dlg_mutex);
      assert (_dialog->sip_dlg_state == SIP_DLG_EARLY || _dialog->sip_dlg_state == SIP_DLG_CONFIRMED);
      /*
       * Let the user delete the dialog if it is not a 1XX/2XX resp
       * for an early INVITE dialog.
       */
      if (SIP_OK_RESP (resp_code))
      {
         if (method == INVITE)
         {
            if (_dialog->sip_dlg_state == SIP_DLG_EARLY)
            {
               _dialog->sip_dlg_state = SIP_DLG_CONFIRMED;
               (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
               (void) sip_dlg_recompute_rset (_dialog, sip_msg, SIP_UAC_DIALOG);
               if (sip_dlg_ulp_state_cb != NULL)
               {
                  sip_dlg_ulp_state_cb ((sip_dialog_t) _dialog, sip_msg, SIP_DLG_EARLY, _dialog->sip_dlg_state);
               }
               return (0);
            }
         }
      }
      (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
   }
   return (0);
}

/* Copy partial dialog to create a complete dialog */
_sip_dialog_t *sip_copy_partial_dialog (_sip_dialog_t * dialog)
{
   _sip_dialog_t *new_dlg;

   new_dlg = calloc (1, sizeof (_sip_dialog_t));
   if (new_dlg == NULL)
      return (NULL);
   if (dialog->sip_dlg_req_uri.sip_str_ptr != NULL)
   {
      new_dlg->sip_dlg_req_uri.sip_str_ptr = malloc (dialog->sip_dlg_req_uri.sip_str_len + 1);
      if (new_dlg->sip_dlg_req_uri.sip_str_ptr == NULL)
      {
         free (new_dlg);
         return (NULL);
      }
      (void) strncpy (new_dlg->sip_dlg_req_uri.sip_str_ptr,
                      dialog->sip_dlg_req_uri.sip_str_ptr, dialog->sip_dlg_req_uri.sip_str_len);
      new_dlg->sip_dlg_req_uri.sip_str_ptr[dialog->sip_dlg_req_uri.sip_str_len] = '\0';
      new_dlg->sip_dlg_req_uri.sip_str_len = dialog->sip_dlg_req_uri.sip_str_len;
   }
   if (dialog->sip_dlg_route_set != NULL)
   {
      assert (dialog->sip_dlg_rset.sip_str_ptr != NULL);
      new_dlg->sip_dlg_rset.sip_str_ptr = malloc (dialog->sip_dlg_rset.sip_str_len + 1);
      if (new_dlg->sip_dlg_rset.sip_str_ptr == NULL)
      {
         if (new_dlg->sip_dlg_req_uri.sip_str_ptr != NULL)
            free (new_dlg->sip_dlg_req_uri.sip_str_ptr);
         free (new_dlg);
         return (NULL);
      }
      (void) strncpy (new_dlg->sip_dlg_rset.sip_str_ptr,
                      dialog->sip_dlg_rset.sip_str_ptr, dialog->sip_dlg_rset.sip_str_len);
      new_dlg->sip_dlg_rset.sip_str_ptr[dialog->sip_dlg_rset.sip_str_len] = '\0';
      new_dlg->sip_dlg_rset.sip_str_len = dialog->sip_dlg_rset.sip_str_len;

      new_dlg->sip_dlg_route_set = sip_dup_header (dialog->sip_dlg_route_set);
      if (new_dlg->sip_dlg_route_set == NULL)
      {
         free (new_dlg->sip_dlg_rset.sip_str_ptr);
         if (new_dlg->sip_dlg_req_uri.sip_str_ptr != NULL)
            free (new_dlg->sip_dlg_req_uri.sip_str_ptr);
         free (new_dlg);
         return (NULL);
      }
   }
   if ((new_dlg->sip_dlg_local_uri_tag =
        sip_dup_header (dialog->sip_dlg_local_uri_tag)) == NULL ||
       (new_dlg->sip_dlg_remote_target =
        sip_dup_header (dialog->sip_dlg_remote_target)) == NULL ||
       (new_dlg->sip_dlg_call_id = sip_dup_header (dialog->sip_dlg_call_id)) == NULL)
   {
      sip_release_dialog_res (new_dlg);
      return (NULL);
   }
   if (dialog->sip_dlg_event != NULL)
   {
      new_dlg->sip_dlg_event = sip_dup_header (dialog->sip_dlg_event);
      if (new_dlg->sip_dlg_event == NULL)
      {
         sip_release_dialog_res (new_dlg);
         return (NULL);
      }
   }
   new_dlg->sip_dlg_local_cseq = dialog->sip_dlg_local_cseq;
   new_dlg->sip_dlg_type = dialog->sip_dlg_type;
   new_dlg->sip_dlg_on_fork = B_FALSE;
   (void) pthread_mutex_init (&new_dlg->sip_dlg_mutex, NULL);

   return (new_dlg);
}

/*
 * Update the dialog using the response
 */
sip_dialog_t
sip_update_dialog (sip_dialog_t dialog, _sip_msg_t * sip_msg, void (*func) (sip_dialog_t, sip_msg_t, void *))
{
   _sip_dialog_t *_dialog;
   boolean_t isreq;
   sip_method_t method;
   int resp_code = 0;
   int prev_state;
   boolean_t decr_ref = B_FALSE;
   int error;

   isreq = sip_msg_is_request ((sip_msg_t) sip_msg, &error);
   if (error != 0)
      return (dialog);
   _dialog = (_sip_dialog_t *) dialog;
   (void) pthread_mutex_lock (&_dialog->sip_dlg_mutex);
   if (isreq)
   {
      method = sip_get_request_method ((sip_msg_t) sip_msg, &error);
      if (error != 0 || _dialog->sip_dlg_method != SUBSCRIBE || method != NOTIFY)
      {
         (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
         return (dialog);
      }
   }
   else
   {
      resp_code = sip_get_response_code ((sip_msg_t) sip_msg, &error);
      if (error != 0)
      {
         (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
         return (dialog);
      }
   }
   prev_state = _dialog->sip_dlg_state;
   if (_dialog->sip_dlg_state == SIP_DLG_CONFIRMED)
   {
      (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
   }
   else if (_dialog->sip_dlg_state == SIP_DLG_EARLY)
   {
      /*
       * Let the user delete the dialog if it is not a 1XX/2XX resp
       * for an early dialog.
       */
      assert (!isreq);
      if (SIP_OK_RESP (resp_code))
      {
         _dialog->sip_dlg_state = SIP_DLG_CONFIRMED;
         (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
         (void) sip_dlg_recompute_rset (_dialog, sip_msg, SIP_UAS_DIALOG);
         if (sip_dlg_ulp_state_cb != NULL)
         {
            sip_dlg_ulp_state_cb (dialog, (sip_msg_t) sip_msg, prev_state, dialog->sip_dlg_state);
         }
      }
      else
      {
         (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
      }
   }
   else if (_dialog->sip_dlg_state == SIP_DLG_NEW)
   {
      if (!isreq && _dialog->sip_dlg_method == SUBSCRIBE && SIP_PROVISIONAL_RESP (resp_code))
      {
         (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
         return (dialog);
      }
      if (_dialog->sip_dlg_type == SIP_UAC_DIALOG)
      {
         _sip_dialog_t *new_dlg;

         if (_dialog->sip_dlg_on_fork)
         {
            new_dlg = sip_copy_partial_dialog (_dialog);
            if (new_dlg == NULL)
            {
               (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
               return (dialog);
            }
            /*
             * This decr/incr dance is because the caller
             * has incremented the ref on the partial
             * dialog, we release it here and incr the
             * ref on the new dialog which will be
             * released by the caller.
             */
            (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
            SIP_DLG_REFCNT_DECR (_dialog);
            _dialog = new_dlg;
            (void) pthread_mutex_lock (&_dialog->sip_dlg_mutex);
            SIP_DLG_REFCNT_INCR (_dialog);
         }
         else
         {
            int index;

            /*
             * take it out of the list so that further
             * responses will not result in a dialog.
             * We will have an extra refcount when we
             * come back from sip_complete_dialog(), i.e.
             * one when the partial dialog was created -
             * in sip_seed_dialog(), one held by the caller
             * and one that will be added by
             * sip_complete_dialog(). We need to release
             * the one added by the sip_seed_dialog(),
             * since the one in sip_complete_dialog()
             * is for the same purpose.
             */
            /* Cancel the timer */
            if (SIP_IS_TIMER_RUNNING (_dialog->sip_dlg_timer))
            {
               SIP_CANCEL_TIMER (dialog->sip_dlg_timer);
            }
            index = SIP_DIGEST_TO_HASH (dialog->sip_dlg_id);
            (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
            sip_hash_delete (sip_dialog_phash, (void *) _dialog->sip_dlg_id, index, sip_dialog_dontfree);
            (void) pthread_mutex_lock (&_dialog->sip_dlg_mutex);
            decr_ref = B_TRUE;
         }
      }
      (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
      if ((dialog = sip_complete_dialog (sip_msg, _dialog, func)) == NULL)
      {
         return (NULL);
      }
      if (decr_ref)
         SIP_DLG_REFCNT_DECR (_dialog);
   }
   else
   {
      (void) pthread_mutex_unlock (&_dialog->sip_dlg_mutex);
   }
   return (dialog);
}

/* Initialize the hash table */
void sip_dialog_init (void (*ulp_state_cb) (sip_dialog_t, sip_msg_t, int, int))
{
   int cnt;

   for (cnt = 0; cnt < SIP_HASH_SZ; cnt++)
   {
      sip_dialog_hash[cnt].hash_count = 0;
      sip_dialog_hash[cnt].hash_head = NULL;
      sip_dialog_hash[cnt].hash_tail = NULL;
      (void) pthread_mutex_init (&sip_dialog_hash[cnt].sip_hash_mutex, NULL);
      sip_dialog_phash[cnt].hash_count = 0;
      sip_dialog_phash[cnt].hash_head = NULL;
      sip_dialog_phash[cnt].hash_tail = NULL;
      (void) pthread_mutex_init (&sip_dialog_phash[cnt].sip_hash_mutex, NULL);
   }
   if (ulp_state_cb != NULL)
      sip_dlg_ulp_state_cb = ulp_state_cb;
}

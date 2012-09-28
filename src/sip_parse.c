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
#include "sip_miscdefs.h"
#include "sip_parse_generic.h"

/* Parse SIP/2.0 string */
static int sip_get_protocol_version (_sip_header_t * sip_header, sip_proto_version_t * sip_proto_version)
{
   if (sip_skip_white_space (sip_header) != 0)
      return (1);
   if (!strncasecmp (sip_header->sip_hdr_current, SIP, strlen (SIP)))
   {
      sip_proto_version->name.sip_str_ptr = sip_header->sip_hdr_current;
      sip_proto_version->name.sip_str_len = strlen (SIP);

      if (sip_find_token (sip_header, SIP_SLASH) != 0)
         return (1);
      if (sip_skip_white_space (sip_header) != 0)
         return (1);

      sip_proto_version->version.sip_str_ptr = sip_header->sip_hdr_current;
      while (isdigit (*sip_header->sip_hdr_current))
      {
         sip_header->sip_hdr_current++;
         if (sip_header->sip_hdr_current >= sip_header->sip_hdr_end)
         {
            return (1);
         }
      }
      if (*sip_header->sip_hdr_current != SIP_PERIOD)
         return (1);
      sip_header->sip_hdr_current++;

      if (!isdigit (*sip_header->sip_hdr_current))
         return (1);
      while (isdigit (*sip_header->sip_hdr_current))
      {
         sip_header->sip_hdr_current++;
         if (sip_header->sip_hdr_current >= sip_header->sip_hdr_end)
         {
            return (1);
         }
      }

      sip_proto_version->version.sip_str_len = sip_header->sip_hdr_current - sip_proto_version->version.sip_str_ptr;
      return (0);
   }
   return (1);
}

/*
 * Warning = "Warning" HCOLON warning-value *(COMMA warning-value)
 * warning-value = warn-code SP warn-agent SP warn-text
 * warn-code = 3DIGIT
 * warn-agent = hostport | pseudonym ;
 *		 the name or pseudonym of the server adding;
 *		 the Warning header, for use in debugging
 * warn-text = quoted-string
 * pseudonym = token
 */
int sip_parse_warn_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   sip_parsed_header_t *parsed_header;
   int ret;
   sip_hdr_value_t *value = NULL;
   sip_hdr_value_t *last_value = NULL;

   if (sip_header == NULL || header == NULL)
      return (EINVAL);
   /* check if already parsed */
   if (sip_header->sip_hdr_parsed != NULL)
   {
      *header = sip_header->sip_hdr_parsed;
      return (0);
   }

   *header = NULL;

   assert (sip_header->sip_hdr_start == sip_header->sip_hdr_current);

   if (sip_parse_goto_values (sip_header) != 0)
      return (EPROTO);

   parsed_header = calloc (1, sizeof (sip_parsed_header_t));
   if (parsed_header == NULL)
      return (ENOMEM);
   parsed_header->sip_header = sip_header;

   while (sip_header->sip_hdr_current < sip_header->sip_hdr_end)
   {
      value = calloc (1, sizeof (sip_hdr_value_t));
      if (value == NULL)
      {
         sip_free_phdr (parsed_header);
         return (ENOMEM);
      }

      if (last_value != NULL)
         last_value->sip_next_value = value;
      else
         parsed_header->value = (sip_value_t *) value;

      value->sip_value_start = sip_header->sip_hdr_current;
      value->sip_value_header = parsed_header;

      ret = sip_atoi (sip_header, &value->warn_code);
      if (ret != 0 || value->warn_code < 100 || value->warn_code > 999)
      {
         value->sip_value_state = SIP_VALUE_BAD;
         goto get_next_val;
      }
      if (sip_skip_white_space (sip_header) != 0)
      {
         value->sip_value_state = SIP_VALUE_BAD;
         goto get_next_val;
      }
      value->warn_agt_ptr = sip_header->sip_hdr_current;

      if (sip_find_token (sip_header, SIP_QUOTE) == 0)
      {
         /* get warning agent */
         sip_header->sip_hdr_current--;
         (void) sip_reverse_skip_white_space (sip_header);
         value->warn_agt_len = sip_header->sip_hdr_current - value->warn_agt_ptr - 1;
         if (value->warn_agt_len <= 0)
         {
            value->warn_agt_ptr = NULL;
            value->sip_value_state = SIP_VALUE_BAD;
         }

         if (sip_find_token (sip_header, SIP_QUOTE) != 0)
         {
            value->sip_value_state = SIP_VALUE_BAD;
            goto get_next_val;
         }
         value->warn_text_ptr = sip_header->sip_hdr_current;
         if (sip_find_token (sip_header, SIP_QUOTE) == 0)
         {
            value->warn_text_len = sip_header->sip_hdr_current - value->warn_text_ptr - 1;
         }
         else
         {
            value->sip_value_state = SIP_VALUE_BAD;
            goto get_next_val;
         }
      }
      else
         /* warning text must present */
         value->sip_value_state = SIP_VALUE_BAD;

    get_next_val:
      if (sip_find_token (sip_header, SIP_COMMA) != 0)
         break;
      value->sip_value_end = sip_header->sip_hdr_current - 1;
      last_value = value;
      (void) sip_skip_white_space (sip_header);
   }

   *header = parsed_header;

   sip_header->sip_hdr_parsed = *header;
   return (0);
}

/*
 * Date = "Date" HCOLON SIPdate
 * SIPdate = wkday "," SP date1 SP time SP "GMT"
 * date1 = 2DIGIT SP mnth SP 4DIGIT; day month year
 * time = 2DIGIT ":" 2DIGIT ":" 2DIGIT
 * wkday = "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun"
 * month = "Jan" | "Feb" etc
 */
int sip_parse_date_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   sip_parsed_header_t *parsed_header;
   int r;
   sip_hdr_value_t *value = NULL;

   if (sip_header == NULL || header == NULL)
      return (EINVAL);
   /* check if already parsed */
   if (sip_header->sip_hdr_parsed != NULL)
   {
      *header = sip_header->sip_hdr_parsed;
      return (0);
   }

   *header = NULL;

   assert (sip_header->sip_hdr_start == sip_header->sip_hdr_current);

   if (sip_parse_goto_values (sip_header) != 0)
      return (EPROTO);

   parsed_header = calloc (1, sizeof (sip_parsed_header_t));
   if (parsed_header == NULL)
      return (ENOMEM);
   parsed_header->sip_header = sip_header;
   value = calloc (1, sizeof (sip_hdr_value_t));
   if (value == NULL)
   {
      sip_free_phdr (parsed_header);
      return (ENOMEM);
   }
   parsed_header->value = (sip_value_t *) value;

   value->sip_value_start = sip_header->sip_hdr_current;
   value->sip_value_header = parsed_header;
   value->date_wd_ptr = sip_header->sip_hdr_current;
   if (sip_find_token (sip_header, SIP_COMMA) == 0)
   {
      value->date_wd_len = sip_header->sip_hdr_current - value->date_wd_ptr - 1;
      sip_header->sip_hdr_current++;
      if (sip_skip_white_space (sip_header) != 0)
      {
         value->sip_value_state = SIP_VALUE_BAD;
         return (EPROTO);
      }
   }
   else
   {
      value->sip_value_state = SIP_VALUE_BAD;
      return (EPROTO);
   }

   if (sip_skip_white_space (sip_header) != 0)
   {
      value->sip_value_state = SIP_VALUE_BAD;
      return (EPROTO);
   }
   r = sip_atoi (sip_header, &value->date_d);
   if (r != 0)
   {
      value->sip_value_state = SIP_VALUE_BAD;
      return (EPROTO);
   }
   if (sip_skip_white_space (sip_header) != 0)
   {
      value->sip_value_state = SIP_VALUE_BAD;
      return (EPROTO);
   }
   value->date_m_ptr = sip_header->sip_hdr_current;
   if (sip_find_token (sip_header, SIP_SP) == 0)
   {
      value->date_m_len = sip_header->sip_hdr_current - value->date_m_ptr - 1;
   }
   else
   {
      value->sip_value_state = SIP_VALUE_BAD;
      return (EPROTO);
   }

   r = sip_atoi (sip_header, &value->date_y);
   if (r != 0)
   {
      value->sip_value_state = SIP_VALUE_BAD;
      return (EPROTO);
   }
   if (sip_skip_white_space (sip_header) != 0)
   {
      value->sip_value_state = SIP_VALUE_BAD;
      return (EPROTO);
   }
   value->date_t_ptr = sip_header->sip_hdr_current;
   if (sip_find_token (sip_header, SIP_SP) == 0)
   {
      value->date_t_len = sip_header->sip_hdr_current - value->date_t_ptr - 1;
   }
   else
   {
      value->sip_value_state = SIP_VALUE_BAD;
      return (EPROTO);
   }

   value->date_tz_ptr = sip_header->sip_hdr_current;
   /* minus 2 to get rid of the CRLF */
   value->date_tz_len = sip_header->sip_hdr_end - sip_header->sip_hdr_current - 2;

   *header = parsed_header;

   sip_header->sip_hdr_parsed = *header;
   return (0);
}

int sip_parse_allow_events_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

int sip_parse_event_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

int sip_parse_substate_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Accept = "Accept" HCOLON [ accept-range *(COMMA accept-range) ]
 * accept-range = media-range *(SEMI accept-param)
 * media-range = ("* / *" |  (m-type SLASH "*") | (m-type SLASH m-subtype))
 *		*(SEMI m-param)
 * accept-param = ("q" EQUAL qvalue) | generic-param
 * qvalue = ("0" ["." 0*3DIGIT]) | ("1" ["." 0*3DIGIT])
 * generic-param = token [ EQUAL gen-value]
 * gen-value = token | host | quoted-str
 *
 * EXAMPLE:
 * Accept: application/sdp; level = 1, application/x-private, text/html
 */

int sip_parse_acpt_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   if (!sip_is_empty_hdr (sip_header))
   {
      r = sip_parse_hdr_empty (sip_header, header);
      return (r);
   }

   r = sip_parse_hdr_parser1 (sip_header, header, SIP_SLASH);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * SYNTAX:
 * Accept-Encoding = "Accept-Encoding" ":" 1#(codings [ ";" "q" "=" qval])
 * codings = (content-coding | "*")
 * content-coding = token
 *
 * EXAMPLE:
 * Accept-Encoding: gzip; q = 1.0, identity; q = 0.5
 */
int sip_parse_acpt_encode_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * SYNTAX:
 * Accept-Language = "Accept-Language" ":" [ lang * (COMMA lang) ]
 * lang = lang-range *(SEMI accept-param)
 * lang-range = ((1*8ALPHA * ("-" 1*8ALPHA)) | "*"
 *
 * DEFAULT:
 * empty header field is eqivalent to "identity"
 *
 * EXAMPLE:
 * Accept-Language: da, en-gb; q = 0.8, en; q = 0.5
 *
 */
int sip_parse_acpt_lang_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   if (!sip_is_empty_hdr (sip_header))
   {
      r = sip_parse_hdr_empty (sip_header, header);
      return (r);
   }
   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * SYNTAX:
 * Alert-Info = "Alert-Info" ":" alert-param *(COMMA alert-param)
 * alert-param = LAQUOT absoluteURI RAQUOT * (SEMI generic-param)
 *
 * EXAMPLE:
 * Alert-Info: < http://www.example.com/sounds/moo.waw >
 *
 */
int sip_parse_alert_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser3 (sip_header, header, SIP_STR_VAL, B_TRUE);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * SYNTAX:
 * Allow = "Allow" ":" method-name1[, method-name2..]
 *
 * EXAMPLE:
 *  Allow: INVITE, ACK, CANCEL
 *
 */
int sip_parse_allow_header (_sip_header_t * hdr, sip_parsed_header_t ** phdr)
{
   sip_parsed_header_t *parsed_header;
   sip_hdr_value_t *value = NULL;
   sip_hdr_value_t *last_value = NULL;
   int len;
   int i;

   if (hdr == NULL || phdr == NULL)
      return (EINVAL);
   /* check if previously parsed */
   if (hdr->sip_hdr_parsed != NULL)
   {
      *phdr = hdr->sip_hdr_parsed;
      return (0);
   }

   *phdr = NULL;

   assert (hdr->sip_hdr_start == hdr->sip_hdr_current);

   if (sip_parse_goto_values (hdr) != 0)
      return (EPROTO);

   parsed_header = calloc (1, sizeof (sip_parsed_header_t));
   if (parsed_header == NULL)
      return (ENOMEM);
   parsed_header->sip_header = hdr;
   while (hdr->sip_hdr_current < hdr->sip_hdr_end)
   {
      value = calloc (1, sizeof (sip_hdr_value_t));
      if (value == NULL)
      {
         sip_free_phdr (parsed_header);
         return (ENOMEM);
      }
      if (last_value != NULL)
         last_value->sip_next_value = value;
      else
         parsed_header->value = (sip_value_t *) value;

      value->sip_value_start = hdr->sip_hdr_current;
      value->sip_value_header = parsed_header;

      if (sip_find_separator (hdr, SIP_COMMA, '\0', '\0') == 0)
      {
         len = hdr->sip_hdr_current - value->sip_value_start;
         for (i = 1; i < MAX_SIP_METHODS; i++)
         {
            if (strncmp (sip_methods[i].name, value->sip_value_start, len) == 0)
               break;
         }
         if (i >= MAX_SIP_METHODS)
         {
            value->int_val = 0;
            value->sip_value_state = SIP_VALUE_BAD;
            goto next_val;
         }
         value->int_val = i;
      }
      else
      {
         len = hdr->sip_hdr_current - value->sip_value_start;
         for (i = 1; i < MAX_SIP_METHODS; i++)
         {
            if (strncmp (sip_methods[i].name, value->sip_value_start, len) == 0)
               break;
         }
         if (i >= MAX_SIP_METHODS)
         {
            value->int_val = 0;
            value->sip_value_state = SIP_VALUE_BAD;
            goto next_val;
         }
         value->int_val = i;
         goto end;
      }
    next_val:
      if (sip_find_token (hdr, SIP_COMMA) != 0)
         break;
      value->sip_value_end = hdr->sip_hdr_current - 1;
      last_value = value;
      (void) sip_skip_white_space (hdr);
   }

 end:
   *phdr = parsed_header;
   return (0);
}


/*
 * Call-Info = "Call-Info" HCOLON info * (COMMA info)
 * info = LAQUOT absoluteURI RAQUOT * (SEMI info-param)
 * info-param = ("purpose" EQUAL ("icon" | "info" | "card" | token)) |
 *		 generic-param
 */
int sip_parse_callinfo_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser3 (sip_header, header, SIP_STR_VAL, B_TRUE);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Content-Disposition = "Content-Disposition" HCOLON disp-type *
 *			(SEMI disp-param)
 * disp-type = "render" | "session" | "icon" | "alert" | disp-ext-token
 * disp-param = handling-param | generic-param
 * handling-param = "handling" EQUAL("optional" | "required" | other-handling)
 * other-handling = token
 * disp-ext-token = token
 *
 */
int sip_parse_contentdis_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Content-Encoding = ("Content-Encoding" | "e") HCOLON content-coding *
 *			(COMMA content-coding)
 */
int sip_parse_contentencode_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Content-Language = ("Content-Language" | "l") HCOLON lang-tag *
 *		 (COMMA lang-tag)
 * lang-tag = primary-tag *("-" subtag)
 * prmary-tag = 1*8ALPHA
 * subtag = 1*8ALPHA
 */
int sip_parse_contentlang_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Error-Info = "Error-Info" HCOLON error-uri *(COMMA error-uri)
 * error-uri = LAQUOT absoluteURI RAQUOT *(SEMI generic-param)
 */
int sip_parse_errorinfo_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser3 (sip_header, header, SIP_STR_VAL, B_TRUE);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Expires = "Expires" HCOLON delta-seconds
 */
int sip_parse_expire_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser2 (sip_header, header, SIP_INT_VAL);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * In-Reply-To = "In-Reply-To" HCOLON callid *(COMMA callid)
 */
int sip_parse_inreplyto_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * RSeq          =  "RSeq" HCOLON response-num
 */
int sip_parse_rseq (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;
   sip_hdr_value_t *rseq_value;

   r = sip_parse_hdr_parser2 (sip_header, header, SIP_INT_VAL);
   sip_header->sip_hdr_parsed = *header;
   /* Additionally, a value of 0 is bad_value */
   if (sip_header->sip_hdr_parsed != NULL && sip_header->sip_hdr_parsed->value != NULL)
   {
      rseq_value = (sip_hdr_value_t *) sip_header->sip_hdr_parsed->value;
      if (rseq_value->int_val == 0)
         rseq_value->sip_value_state = SIP_VALUE_BAD;
   }
   return (r);
}

/* min-expires, same as expires */
int sip_parse_minexpire_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser2 (sip_header, header, SIP_INT_VAL);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * MIME-Version = "MIME-Version" HCOLON 1*DIGIT "." 1*DIGIT
 */
int sip_parse_mimeversion_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser4 (sip_header, header);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Organization = "Organization" HCOLON [TEXT-UTF8-TRIM]
 */
int sip_parse_org_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   if (!sip_is_empty_hdr (sip_header))
   {
      r = sip_parse_hdr_empty (sip_header, header);
      return (r);
   }
   r = sip_parse_hdr_parser4 (sip_header, header);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Priority = "Priority" HCOLON priority-val
 * priority-val = "emergency" | "urgent" | "normal" | "non-urgent" | other
 * other = token
 */
int sip_parse_priority_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

int sip_parse_ainfo_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;

   return (r);
}


int sip_parse_preq_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}


int sip_parse_author_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser5 (sip_header, header, B_TRUE);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}


int sip_parse_pauthor_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;
   r = sip_parse_hdr_parser5 (sip_header, header, B_TRUE);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

int sip_parse_pauthen_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;
   r = sip_parse_hdr_parser5 (sip_header, header, B_TRUE);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

int sip_parse_wauthen_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;
   r = sip_parse_hdr_parser5 (sip_header, header, B_TRUE);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Reply-To = "Reply-To" HCOLON rplyto-spec
 * rplyto-spec = (name-addr | addr-spec) *(SEMI rplyto-param)
 * rplyto-param = generic-param
 * name-addr = [ display-name ] LAQUOT addr-spec RAQUOT
 * addr-spec = SIP-URI | SIPS-URI | absolute URI
 */
int sip_parse_replyto_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser3 (sip_header, header, SIP_STRS_VAL, B_TRUE);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * PAssertedID = "P-Asserted-Identity" HCOLON PAssertedID-value
 *               *(COMMA PAssertedID-value)
 * PAssertedID-value = name-addr / addr-spec
 */
int sip_parse_passertedid (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser3 (sip_header, header, SIP_STRS_VAL, B_TRUE);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * PPreferredID = "P-Preferred-Identity" HCOLON PPreferredID-value
 *               *(COMMA PAssertedID-value)
 * PPreferredID-value = name-addr / addr-spec
 */
int sip_parse_ppreferredid (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser3 (sip_header, header, SIP_STRS_VAL, B_TRUE);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}


/*
 * PRIVACY = "Privacy" HCOLON priv-value *(COMMA priv-value)
 * priv-value   =   "header" / "session" / "user" / "none" / "critical"
 *                  / token / id
 */
int sip_parse_privacy_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Require = "Require" HCOLON option-tag * (COMMA option-tag)
 */
int sip_parse_require_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Retry-After = "Retry-After" HCOLON delta-seconds [ comment ] *
 *		(SEMI retry-param)
 * retry-param = "duration" EQUAL delta-seconds
 */
int sip_parse_retryaft_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   sip_parsed_header_t *parsed_header;
   sip_hdr_value_t *value = NULL;
   int ret;

   if (sip_header == NULL || header == NULL)
      return (EINVAL);
   /* check if already parsed */
   if (sip_header->sip_hdr_parsed != NULL)
   {
      *header = sip_header->sip_hdr_parsed;
      return (0);
   }

   *header = NULL;

   assert (sip_header->sip_hdr_start == sip_header->sip_hdr_current);

   if (sip_parse_goto_values (sip_header))
      return (EPROTO);
   parsed_header = calloc (1, sizeof (sip_parsed_header_t));
   if (parsed_header == NULL)
      return (ENOMEM);
   parsed_header->sip_header = sip_header;

   value = calloc (1, sizeof (sip_hdr_value_t));
   if (value == NULL)
   {
      sip_free_phdr (parsed_header);
      return (ENOMEM);
   }

   parsed_header->value = (sip_value_t *) value;
   value->sip_value_start = sip_header->sip_hdr_current;
   value->sip_value_header = parsed_header;

   ret = sip_atoi (sip_header, &(value->intstr_int));
   if (ret != 0)
      value->sip_value_state = SIP_VALUE_BAD;
   if (sip_find_token (sip_header, SIP_LPAR) == 0)
   {
      value->intstr_str_ptr = sip_header->sip_hdr_current;
      if (sip_find_token (sip_header, SIP_RPAR) == 0)
      {
         value->intstr_str_len = sip_header->sip_hdr_current - value->intstr_str_ptr - 1;
         if (sip_find_token (sip_header, SIP_SEMI) == 0)
         {
            sip_header->sip_hdr_current--;
            (void) sip_parse_params (sip_header, &(value->sip_param_list));
         }
      }
      else
      {
         value->sip_value_state = SIP_VALUE_BAD;
         return (EPROTO);
      }
   }
   else
   {
      value->intstr_str_ptr = NULL;
      value->intstr_str_len = 0;

      /* from value start, search if parameter list */
      sip_header->sip_hdr_current = value->sip_value_start;
      if (sip_find_token (sip_header, SIP_SEMI) == 0)
      {
         sip_header->sip_hdr_current--;
         (void) sip_parse_params (sip_header, &(value->sip_param_list));
      }
   }

   *header = parsed_header;
   sip_header->sip_hdr_parsed = *header;
   return (0);
}

/*
 * Server = "Server" HCOLON servel-val *(LWS server-val)
 * servel-val = product|comment
 * product = token [SLASH version]
 * version = token
 * Treated as one single string
 */
int sip_parse_server_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser4 (sip_header, header);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Subject = ("Subject" | "s")HCOLON [TEXT-UTF8-TRIM]
 */
int sip_parse_subject_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   if (!sip_is_empty_hdr (sip_header))
   {
      r = sip_parse_hdr_empty (sip_header, header);
      return (r);
   }
   r = sip_parse_hdr_parser4 (sip_header, header);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * XXXXX supported, same as require
 * Supported = ("Supported" | "k") HCOLON [option-tag * (COMMA option-tag) ]
 */
int sip_parse_support_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   if (!sip_is_empty_hdr (sip_header))
   {
      r = sip_parse_hdr_empty (sip_header, header);
      return (r);
   }
   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Timestamp = "Timestamp" HCOLON 1*DIGIT ["." *(DIGIT)] [LWS delay]
 */
int sip_parse_timestamp_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   sip_parsed_header_t *parsed_header;
   sip_hdr_value_t *value = NULL;

   if (sip_header == NULL || header == NULL)
      return (EINVAL);
   /* check if already parsed */
   if (sip_header->sip_hdr_parsed != NULL)
   {
      *header = sip_header->sip_hdr_parsed;
      return (0);
   }

   *header = NULL;

   assert (sip_header->sip_hdr_start == sip_header->sip_hdr_current);

   if (sip_parse_goto_values (sip_header))
      return (EPROTO);

   parsed_header = calloc (1, sizeof (sip_parsed_header_t));
   if (parsed_header == NULL)
      return (ENOMEM);
   parsed_header->sip_header = sip_header;

   value = calloc (1, sizeof (sip_hdr_value_t));
   if (value == NULL)
   {
      sip_free_phdr (parsed_header);
      return (ENOMEM);
   }
   parsed_header->value = (sip_value_t *) value;

   value->sip_value_start = sip_header->sip_hdr_current;
   value->sip_value_header = parsed_header;

   if (sip_skip_white_space (sip_header) != 0)
   {
      value->sip_value_state = SIP_VALUE_BAD;
      return (EPROTO);
   }
   value->strs1_val_ptr = sip_header->sip_hdr_current;

   if (sip_find_white_space (sip_header) == 0)
   {
      /* timestamp and delay, timestamp in str1, delay in str2 */
      value->strs1_val_len = sip_header->sip_hdr_current - value->strs1_val_ptr;
      (void) sip_skip_white_space (sip_header);

      value->strs2_val_ptr = sip_header->sip_hdr_current;
      if (sip_find_cr (sip_header) != 0)
      {
         value->sip_value_state = SIP_VALUE_BAD;
         return (EPROTO);
      }
      if (sip_header->sip_hdr_current < value->strs2_val_ptr)
      {
         value->strs2_val_ptr = NULL;
         value->strs2_val_len = 0;
      }
      else
      {
         value->strs2_val_len = sip_header->sip_hdr_current - value->strs2_val_ptr;
      }
   }
   else
   {
      /* no delay information */
      value->strs1_val_len = sip_header->sip_hdr_current - value->strs1_val_ptr;
      value->strs2_val_ptr = NULL;
      value->strs2_val_len = 0;
   }

   *header = parsed_header;
   sip_header->sip_hdr_parsed = *header;

   return (0);
}

/*
 * Unsupported = "Unsupported" HCOLON option-tag * (COMMA option-tag)
 */
int sip_parse_usupport_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, '\0');
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * User-Agent = "User-Agent" HCOLON server-val * (LWS server-val)
 * servel-val = product |comment
 * product = token [SLASH version]
 * version = token
 */
int sip_parse_useragt_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser4 (sip_header, header);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Via =  ( "Via" / "v" ) HCOLON via-parm *(COMMA via-parm)
 * via-parm          =  sent-protocol LWS sent-by *( SEMI via-params )
 * via-params        =  via-ttl / via-maddr
 *                      / via-received / via-branch
 *                      / via-extension
 * via-ttl           =  "ttl" EQUAL ttl
 * via-maddr         =  "maddr" EQUAL host
 * via-received      =  "received" EQUAL (IPv4address / IPv6address)
 * via-branch        =  "branch" EQUAL token
 * via-extension     =  generic-param
 * sent-protocol     =  protocol-name SLASH protocol-version
 *                      SLASH transport
 * protocol-name     =  "SIP" / token
 * protocol-version  =  token
 * transport         =  "UDP" / "TCP" / "TLS" / "SCTP"
 *                      / other-transport
 * sent-by           =  host [ COLON port ]
 * ttl               =  1*3DIGIT ; 0 to 255
 *
 * There can be multiple via headers we always append the header.
 */
int sip_parse_via_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   sip_parsed_header_t *parsed_header;
   int ret;
   sip_hdr_value_t *value = NULL;
   sip_hdr_value_t *last_value = NULL;

   if (sip_header == NULL || header == NULL)
      return (EINVAL);
   /* check if already parsed */
   if (sip_header->sip_hdr_parsed != NULL)
   {
      *header = sip_header->sip_hdr_parsed;
      return (0);
   }

   *header = NULL;

   assert (sip_header->sip_hdr_start == sip_header->sip_hdr_current);

   if (sip_parse_goto_values (sip_header) != 0)
      return (EPROTO);

   parsed_header = calloc (1, sizeof (sip_parsed_header_t));
   if (parsed_header == NULL)
      return (ENOMEM);
   parsed_header->sip_parsed_header_version = SIP_PARSED_HEADER_VERSION_1;
   parsed_header->sip_header = sip_header;
   while (sip_header->sip_hdr_current < sip_header->sip_hdr_end)
   {

      value = calloc (1, sizeof (sip_hdr_value_t));
      if (value == NULL)
      {
         sip_free_phdr (parsed_header);
         return (ENOMEM);
      }
      if (last_value != NULL)
         last_value->sip_next_value = value;
      else
         parsed_header->value = (sip_value_t *) value;

      value->sip_value_version = SIP_VALUE_VERSION_1;
      value->sip_value_start = sip_header->sip_hdr_current;
      value->sip_value_header = parsed_header;
      value->via_protocol_name.sip_str_ptr = sip_header->sip_hdr_current;

      /*
       * Check to see if there is a version number
       */
      if (sip_get_protocol_version (sip_header, &value->via_protocol) != 0)
      {
         if (sip_goto_next_value (sip_header) != 0)
         {
            sip_free_phdr (parsed_header);
            return (EPROTO);
         }
         value->sip_value_state = SIP_VALUE_BAD;
         goto get_next_via_value;
      }

      if (sip_find_token (sip_header, SIP_SLASH) != 0)
      {
         if (sip_goto_next_value (sip_header) != 0)
         {
            sip_free_phdr (parsed_header);
            return (EPROTO);
         }
         value->sip_value_state = SIP_VALUE_BAD;
         goto get_next_via_value;
      }

      if (sip_skip_white_space (sip_header) != 0)
      {
         if (sip_goto_next_value (sip_header) != 0)
         {
            sip_free_phdr (parsed_header);
            return (EPROTO);
         }
         value->sip_value_state = SIP_VALUE_BAD;
         goto get_next_via_value;
      }

      value->via_protocol_transport.sip_str_ptr = sip_header->sip_hdr_current;
      if (sip_find_white_space (sip_header) != 0)
      {
         if (sip_goto_next_value (sip_header) != 0)
         {
            sip_free_phdr (parsed_header);
            return (EPROTO);
         }
         value->sip_value_state = SIP_VALUE_BAD;
         goto get_next_via_value;
      }

      value->via_protocol_transport.sip_str_len =
         sip_header->sip_hdr_current - value->via_protocol_transport.sip_str_ptr;

      if (sip_skip_white_space (sip_header) != 0)
      {
         if (sip_goto_next_value (sip_header) != 0)
         {
            sip_free_phdr (parsed_header);
            return (EPROTO);
         }
         value->sip_value_state = SIP_VALUE_BAD;
         goto get_next_via_value;
      }

      value->via_sent_by_host.sip_str_ptr = sip_header->sip_hdr_current;
      if (*sip_header->sip_hdr_current == '[')
      {
         if (sip_find_token (sip_header, ']'))
         {
            if (sip_goto_next_value (sip_header) != 0)
            {
               sip_free_phdr (parsed_header);
               return (EPROTO);
            }
            value->sip_value_state = SIP_VALUE_BAD;
            goto get_next_via_value;
         }
      }
      else if (sip_find_separator (sip_header, SIP_SEMI, SIP_COMMA, SIP_HCOLON))
      {
         if (sip_goto_next_value (sip_header) != 0)
         {
            sip_free_phdr (parsed_header);
            return (EPROTO);
         }
         value->sip_value_state = SIP_VALUE_BAD;
         goto get_next_via_value;
      }
      value->via_sent_by_host.sip_str_len = sip_header->sip_hdr_current - value->via_sent_by_host.sip_str_ptr;

      if (sip_skip_white_space (sip_header) != 0)
      {
         if (sip_goto_next_value (sip_header) != 0)
         {
            sip_free_phdr (parsed_header);
            return (EPROTO);
         }
         value->sip_value_state = SIP_VALUE_BAD;
         goto get_next_via_value;
      }

      if (*sip_header->sip_hdr_current == SIP_HCOLON)
      {
         sip_header->sip_hdr_current++;
         /*
          * We have a port number
          */
         if (sip_atoi (sip_header, &value->via_sent_by_port) != 0)
         {
            if (sip_goto_next_value (sip_header) != 0)
            {
               sip_free_phdr (parsed_header);
               return (EPROTO);
            }
            value->sip_value_state = SIP_VALUE_BAD;
            goto get_next_via_value;
         }

      }

      /*
       * Do some sanity checking.
       * This should be replaced by a v4/v6 address check.
       */
      if (value->via_sent_by_host.sip_str_len == 0 ||
          (!isalnum (*value->via_sent_by_host.sip_str_ptr) && *value->via_sent_by_host.sip_str_ptr != '['))
      {
         if (sip_goto_next_value (sip_header) != 0)
         {
            sip_free_phdr (parsed_header);
            return (EPROTO);
         }
         value->sip_value_state = SIP_VALUE_BAD;
         goto get_next_via_value;
      }

      ret = sip_parse_params (sip_header, &value->sip_param_list);
      if (ret == EPROTO)
      {
         value->sip_value_state = SIP_VALUE_BAD;
      }
      else if (ret != 0)
      {
         sip_free_phdr (parsed_header);
         return (ret);
      }
    get_next_via_value:
      value->sip_value_end = sip_header->sip_hdr_current;

      if (sip_find_token (sip_header, SIP_COMMA) != 0)
         break;
      last_value = value;
      (void) sip_skip_white_space (sip_header);
   }

   sip_header->sip_hdr_parsed = parsed_header;

   *header = parsed_header;
   return (0);
}

/* Generic parser for Contact, From, To, Route and Record-Route  headers */
int sip_parse_cftr_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   sip_parsed_header_t *parsed_header;
   char *tmp_ptr;
   char *tmp_ptr_2;
   int ret;
   sip_hdr_value_t *value = NULL;
   sip_hdr_value_t *last_value = NULL;

   if (sip_header == NULL || header == NULL)
      return (EINVAL);
   /* check if already parsed */
   if (sip_header->sip_hdr_parsed != NULL)
   {
      *header = sip_header->sip_hdr_parsed;
      return (0);
   }

   *header = NULL;

   assert (sip_header->sip_hdr_start == sip_header->sip_hdr_current);

   if (sip_parse_goto_values (sip_header) != 0)
      return (EPROTO);
   parsed_header = calloc (1, sizeof (sip_parsed_header_t));
   if (parsed_header == NULL)
      return (ENOMEM);
   parsed_header->sip_parsed_header_version = SIP_PARSED_HEADER_VERSION_1;
   parsed_header->sip_header = sip_header;
   while (sip_header->sip_hdr_current < sip_header->sip_hdr_end)
   {
      boolean_t quoted_name = B_FALSE;

      value = calloc (1, sizeof (sip_hdr_value_t));
      if (value == NULL)
      {
         sip_free_cftr_header (parsed_header);
         return (ENOMEM);
      }
      if (last_value != NULL)
         last_value->sip_next_value = value;
      else
         parsed_header->value = (sip_value_t *) value;
      if (*sip_header->sip_hdr_current == SIP_QUOTE)
      {
         sip_header->sip_hdr_current++;
         quoted_name = B_TRUE;
      }
      value->sip_value_version = SIP_VALUE_VERSION_1;
      value->sip_value_start = sip_header->sip_hdr_current;
      value->sip_value_header = parsed_header;
      /*
       * lets see if there is a display name
       */
      if (*sip_header->sip_hdr_current != '<')
      {

         tmp_ptr = sip_header->sip_hdr_current;
         /*
          * According to 20.10 '<' may not have a leading
          * space.
          */
         if (quoted_name && sip_find_token (sip_header, SIP_QUOTE))
         {
            if (sip_goto_next_value (sip_header) != 0)
            {
               sip_free_cftr_header (parsed_header);
               return (EPROTO);
            }
            value->sip_value_state = SIP_VALUE_BAD;
            goto get_next_cftr_value;
         }
         else if (sip_find_separator (sip_header, SIP_SEMI, SIP_LAQUOT, SIP_COMMA))
         {

            /*
             * only a uri.
             */
            value->cftr_uri.sip_str_ptr = tmp_ptr;
            value->cftr_uri.sip_str_len = sip_header->sip_hdr_current - tmp_ptr;
            /*
             * It's an error not to have a uri.
             */
            if (value->cftr_uri.sip_str_len == 0)
            {
               if (sip_goto_next_value (sip_header) != 0)
               {
                  sip_free_cftr_header (parsed_header);
                  return (EPROTO);
               }
               value->sip_value_state = SIP_VALUE_BAD;
               goto get_next_cftr_value;
            }
            continue;
         }

         tmp_ptr_2 = sip_header->sip_hdr_current;
         if (*sip_header->sip_hdr_current == SIP_SP)
         {
            if (sip_skip_white_space (sip_header) != 0)
            {
               /*
                * only a uri.
                */
               value->cftr_uri.sip_str_ptr = tmp_ptr;
               value->cftr_uri.sip_str_len = tmp_ptr_2 - tmp_ptr;
               /*
                * It's an error not to have a uri.
                */
               if (value->cftr_uri.sip_str_len == 0)
               {
                  if (sip_goto_next_value (sip_header) != 0)
                  {
                     sip_free_cftr_header (parsed_header);
                     return (EPROTO);
                  }
                  value->sip_value_state = SIP_VALUE_BAD;
                  goto get_next_cftr_value;
               }
               continue;
            }
         }

         if (*sip_header->sip_hdr_current != SIP_LAQUOT)
         {
            /*
             * No display name here.
             */
            value->cftr_uri.sip_str_ptr = tmp_ptr;
            value->cftr_uri.sip_str_len = tmp_ptr_2 - tmp_ptr;
            /*
             * It's an error not to have a uri.
             */
            if (value->cftr_uri.sip_str_len == 0)
            {
               if (sip_goto_next_value (sip_header) != 0)
               {
                  sip_free_cftr_header (parsed_header);
                  return (EPROTO);
               }
               value->sip_value_state = SIP_VALUE_BAD;
               goto get_next_cftr_value;
            }
            goto get_params;
         }

         value->cftr_name = malloc (sizeof (sip_str_t));
         if (value->cftr_name == NULL)
         {
            sip_free_cftr_header (parsed_header);
            return (ENOMEM);
         }
         value->cftr_name->sip_str_ptr = tmp_ptr;
         value->cftr_name->sip_str_len = tmp_ptr_2 - tmp_ptr;
         if (quoted_name)
            value->cftr_name->sip_str_len--;
      }

      if (sip_find_token (sip_header, SIP_LAQUOT) != 0)
      {
         if (sip_goto_next_value (sip_header) != 0)
         {
            sip_free_cftr_header (parsed_header);
            return (EPROTO);
         }
         value->sip_value_state = SIP_VALUE_BAD;
         goto get_next_cftr_value;
      }

      if (*sip_header->sip_hdr_current == SIP_SP)
      {
         if (sip_skip_white_space (sip_header) != 0)
         {
            if (sip_goto_next_value (sip_header) != 0)
            {
               sip_free_cftr_header (parsed_header);
               return (EPROTO);
            }
            value->sip_value_state = SIP_VALUE_BAD;
            goto get_next_cftr_value;
         }
      }

      tmp_ptr = sip_header->sip_hdr_current;

      if (sip_find_separator (sip_header, SIP_RAQUOT, '\0', '\0'))
      {
         if (sip_goto_next_value (sip_header) != 0)
         {
            sip_free_cftr_header (parsed_header);
            return (EPROTO);
         }
         value->sip_value_state = SIP_VALUE_BAD;
         goto get_next_cftr_value;
      }

      value->cftr_uri.sip_str_ptr = tmp_ptr;
      value->cftr_uri.sip_str_len = sip_header->sip_hdr_current - tmp_ptr;

      if (sip_find_token (sip_header, '>') != 0)
      {
         if (sip_goto_next_value (sip_header) != 0)
         {
            sip_free_cftr_header (parsed_header);
            return (EINVAL);
         }
         value->sip_value_state = SIP_VALUE_BAD;
         goto get_next_cftr_value;
      }

      if (value->cftr_uri.sip_str_len <= strlen ("<>"))
      {
         if (sip_goto_next_value (sip_header) != 0)
         {
            sip_free_cftr_header (parsed_header);
            return (EPROTO);
         }
         value->sip_value_state = SIP_VALUE_BAD;
         goto get_next_cftr_value;
      }

    get_params:
      ret = sip_parse_params (sip_header, &value->sip_param_list);
      if (ret == EPROTO)
      {
         value->sip_value_state = SIP_VALUE_BAD;
      }
      else if (ret != 0)
      {
         sip_free_cftr_header (parsed_header);
         return (ret);
      }
    get_next_cftr_value:
      value->sip_value_end = sip_header->sip_hdr_current;

      /*
       * Parse uri
       */
      if (value->cftr_uri.sip_str_len > 0)
      {
         int error;

         value->sip_value_parsed_uri = sip_parse_uri (&value->cftr_uri, &error);
         if (value->sip_value_parsed_uri == NULL)
         {
            sip_free_cftr_header (parsed_header);
            return (ENOMEM);
         }
         if (error != 0 || ((_sip_uri_t *) value->sip_value_parsed_uri)->sip_uri_errflags != 0)
         {
            value->sip_value_state = SIP_VALUE_BAD;
         }
      }

      (void) sip_find_token (sip_header, SIP_COMMA);
      last_value = value;
      (void) sip_skip_white_space (sip_header);
   }

   sip_header->sip_hdr_parsed = parsed_header;

   *header = parsed_header;
   return (0);
}

/*
 * Parse RAck header
 * "RAck" HCOLON response-num LWS CSeq-num LWS Method
 * response-num  =  1*DIGIT
 * CSeq-num      =  1*DIGIT
 */
int sip_parse_rack (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   sip_parsed_header_t *parsed_header;
   sip_hdr_value_t *rack_value;
   int len;
   char *tmp_ptr;
   int i;

   if (sip_header == NULL || header == NULL)
      return (EINVAL);
   /* check if previously parsed */
   if (sip_header->sip_hdr_parsed != NULL)
   {
      *header = sip_header->sip_hdr_parsed;
      return (0);
   }

   *header = NULL;
   parsed_header = calloc (1, sizeof (sip_parsed_header_t));
   if (parsed_header == NULL)
      return (ENOMEM);
   parsed_header->sip_parsed_header_version = SIP_PARSED_HEADER_VERSION_1;

   if (sip_parse_goto_values (sip_header) != 0)
   {
      free (parsed_header);
      return (EPROTO);
   }

   parsed_header->value = calloc (1, sizeof (sip_hdr_value_t));
   if (parsed_header->value == NULL)
   {
      free (parsed_header);
      return (ENOMEM);
   }

   parsed_header->sip_header = sip_header;
   rack_value = (sip_hdr_value_t *) parsed_header->value;
   rack_value->sip_value_version = SIP_VALUE_VERSION_1;
   rack_value->sip_value_start = sip_header->sip_hdr_current;
   rack_value->sip_value_header = parsed_header;
   if (sip_atoi (sip_header, &rack_value->rack_resp) || rack_value->rack_resp == 0)
   {
      rack_value->sip_value_state = SIP_VALUE_BAD;
      rack_value->sip_value_end = sip_header->sip_hdr_end - 2;
      goto rack_parse_done;
   }
   rack_value->sip_value_header = parsed_header;
   /*
    * Get cseq.
    */
   if (sip_skip_white_space (sip_header) != 0)
   {
      rack_value->sip_value_state = SIP_VALUE_BAD;
      rack_value->sip_value_end = sip_header->sip_hdr_end - 2;
      goto rack_parse_done;
   }
   if (sip_atoi (sip_header, &rack_value->rack_cseq))
   {
      rack_value->sip_value_state = SIP_VALUE_BAD;
      rack_value->sip_value_end = sip_header->sip_hdr_end - 2;
      goto rack_parse_done;
   }
   /*
    * Get method.
    */
   if (sip_skip_white_space (sip_header) != 0)
   {
      rack_value->sip_value_state = SIP_VALUE_BAD;
      rack_value->sip_value_end = sip_header->sip_hdr_end - 2;
      goto rack_parse_done;
   }

   tmp_ptr = sip_header->sip_hdr_current;
   if (sip_find_white_space (sip_header))
   {
      rack_value->sip_value_state = SIP_VALUE_BAD;
      rack_value->sip_value_end = sip_header->sip_hdr_end - 2;
      goto rack_parse_done;
   }

   len = sip_header->sip_hdr_current - tmp_ptr;

   for (i = 1; i < MAX_SIP_METHODS; i++)
   {
      if (strncmp (sip_methods[i].name, tmp_ptr, len) == 0)
         break;
   }

   if (i >= MAX_SIP_METHODS)
   {
      rack_value->sip_value_state = SIP_VALUE_BAD;
      rack_value->sip_value_end = sip_header->sip_hdr_end - 2;
      goto rack_parse_done;
   }

   rack_value->rack_method = i;
   rack_value->sip_value_end = sip_header->sip_hdr_current;

 rack_parse_done:
   sip_header->sip_hdr_parsed = parsed_header;

   *header = parsed_header;
   return (0);
}

/* Parse CSeq header */
int sip_parse_cseq_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   sip_parsed_header_t *parsed_header;
   sip_hdr_value_t *cseq_value;
   int len;
   char *tmp_ptr;
   int i;

   if (sip_header == NULL || header == NULL)
      return (EINVAL);
   /* check if previously parsed */
   if (sip_header->sip_hdr_parsed != NULL)
   {
      *header = sip_header->sip_hdr_parsed;
      return (0);
   }

   *header = NULL;
   parsed_header = calloc (1, sizeof (sip_parsed_header_t));
   if (parsed_header == NULL)
      return (ENOMEM);
   parsed_header->sip_parsed_header_version = SIP_PARSED_HEADER_VERSION_1;

   if (sip_parse_goto_values (sip_header) != 0)
   {
      free (parsed_header);
      return (EPROTO);
   }

   parsed_header->value = calloc (1, sizeof (sip_hdr_value_t));
   if (parsed_header->value == NULL)
   {
      free (parsed_header);
      return (ENOMEM);
   }

   parsed_header->sip_header = sip_header;
   cseq_value = (sip_hdr_value_t *) parsed_header->value;
   cseq_value->sip_value_version = SIP_VALUE_VERSION_1;
   cseq_value->sip_value_start = sip_header->sip_hdr_current;
   if (sip_atoi (sip_header, &cseq_value->cseq_num))
   {
      cseq_value->sip_value_state = SIP_VALUE_BAD;
      cseq_value->sip_value_end = sip_header->sip_hdr_end - 2;
      goto cseq_parse_done;
   }
   cseq_value->sip_value_header = parsed_header;
   /*
    * Get method.
    */
   if (sip_skip_white_space (sip_header) != 0)
   {
      cseq_value->sip_value_state = SIP_VALUE_BAD;
      cseq_value->sip_value_end = sip_header->sip_hdr_end - 2;
      goto cseq_parse_done;
   }

   tmp_ptr = sip_header->sip_hdr_current;

   if (sip_find_white_space (sip_header))
   {
      cseq_value->sip_value_state = SIP_VALUE_BAD;
      cseq_value->sip_value_end = sip_header->sip_hdr_current;
      goto cseq_parse_done;
   }

   len = sip_header->sip_hdr_current - tmp_ptr;

   for (i = 1; i < MAX_SIP_METHODS; i++)
   {
      if (strncmp (sip_methods[i].name, tmp_ptr, len) == 0)
         break;
   }

   if (i >= MAX_SIP_METHODS)
   {
      cseq_value->sip_value_state = SIP_VALUE_BAD;
      cseq_value->sip_value_end = sip_header->sip_hdr_current;
      goto cseq_parse_done;
   }

   cseq_value->cseq_method = i;
   cseq_value->sip_value_end = sip_header->sip_hdr_current;
 cseq_parse_done:

   sip_header->sip_hdr_parsed = parsed_header;

   *header = parsed_header;
   return (0);
}

/* Parse Call-Id header */
int sip_parse_cid_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser4 (sip_header, header);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/* Parse Content-Length header */
int sip_parse_clen_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser2 (sip_header, header, SIP_INT_VAL);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Max-Forwards  =  "Max-Forwards" HCOLON 1*DIGIT
 */
int sip_parse_maxf_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser2 (sip_header, header, SIP_INT_VAL);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/*
 * Content-Type     =  ( "Content-Type" / "c" ) HCOLON media-type
 * media-type       =  m-type SLASH m-subtype *(SEMI m-parameter)
 * m-type           =  discrete-type / composite-type
 * discrete-type    =  "text" / "image" / "audio" / "video"
 *                     / "application" / extension-token
 * composite-type   =  "message" / "multipart" / extension-token
 * extension-token  =  ietf-token / x-token
 * ietf-token       =  token
 * x-token          =  "x-" token
 * m-subtype        =  extension-token / iana-token
 * iana-token       =  token
 * m-parameter      =  m-attribute EQUAL m-value
 * m-attribute      =  token
 * m-value          =  token / quoted-string
 */
int sip_parse_ctype_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   int r;

   r = sip_parse_hdr_parser1 (sip_header, header, SIP_SLASH);
   sip_header->sip_hdr_parsed = *header;
   return (r);
}

/* Return the URI in the request startline */
static int _sip_get_request_uri (_sip_header_t * sip_header, sip_message_type_t * msg_info)
{
   int size = 0;
   char *start_ptr;

   if (sip_skip_white_space (sip_header))
      return (1);
   start_ptr = sip_header->sip_hdr_current;

   while (!isspace (*sip_header->sip_hdr_current))
   {
      if (sip_header->sip_hdr_current >= sip_header->sip_hdr_end)
         return (1);
      sip_header->sip_hdr_current++;
   }

   size = sip_header->sip_hdr_current - start_ptr;

   msg_info->U.sip_request.sip_request_uri.sip_str_ptr = start_ptr;
   msg_info->U.sip_request.sip_request_uri.sip_str_len = size;
   if (size > 0)
   {                            /* Parse uri */
      int error;

      msg_info->U.sip_request.sip_parse_uri = sip_parse_uri (&msg_info->U.sip_request.sip_request_uri, &error);
      if (msg_info->U.sip_request.sip_parse_uri == NULL)
         return (1);
   }
   return (0);
}

/* Parse the start line into request/response */
int sip_parse_first_line (_sip_header_t * sip_header, sip_message_type_t ** msg_info)
{
   sip_message_type_t *sip_msg_info;
   boolean_t sip_is_request = B_TRUE;
   int ret;

   if (sip_header == NULL || msg_info == NULL)
      return (EINVAL);

   if (sip_skip_white_space (sip_header) != 0)
      return (EPROTO);

   /* There is nothing, return */
   if (sip_header->sip_hdr_current + strlen (SIP_VERSION) >= sip_header->sip_hdr_end)
   {
      return (EPROTO);
   }
#ifdef	__solaris__
   assert (mutex_held (&sip_header->sip_hdr_sipmsg->sip_msg_mutex));
#endif
   sip_msg_info = malloc (sizeof (sip_message_type_t));
   if (sip_msg_info == NULL)
      return (ENOMEM);

   /*
    * lets see if its a request or a response
    */
   ret = sip_get_protocol_version (sip_header, &sip_msg_info->sip_proto_version);
   if (ret == 0)
   {
      sip_is_request = B_FALSE;
   }
   else if (ret == 2)
   {
      free (sip_msg_info);
      return (EPROTO);
   }

   if (sip_skip_white_space (sip_header) != 0)
   {
      free (sip_msg_info);
      return (EPROTO);
   }

   if (!sip_is_request)
   {
      /*
       * check for status code.
       */
      if (sip_skip_white_space (sip_header) != 0)
      {
         free (sip_msg_info);
         return (EPROTO);
      }
      if (sip_header->sip_hdr_current + SIP_SIZE_OF_STATUS_CODE >= sip_header->sip_hdr_end)
      {
         free (sip_msg_info);
         return (EPROTO);
      }

      if (sip_atoi (sip_header, &sip_msg_info->U.sip_response.sip_response_code))
      {
         free (sip_msg_info);
         return (EPROTO);
      }

      if (sip_msg_info->U.sip_response.sip_response_code < 100 || sip_msg_info->U.sip_response.sip_response_code > 700)
      {
         free (sip_msg_info);
         return (EPROTO);
      }

      /*
       * get reason phrase.
       */
      if (sip_skip_white_space (sip_header) != 0)
      {
         sip_msg_info->sip_resp_phrase_len = 0;
         sip_msg_info->sip_resp_phrase_ptr = NULL;
      }
      else
      {
         sip_msg_info->sip_resp_phrase_ptr = sip_header->sip_hdr_current;
         if (sip_find_cr (sip_header) != 0)
         {
            free (sip_msg_info);
            return (EPROTO);
         }
         sip_msg_info->sip_resp_phrase_len = sip_header->sip_hdr_current - sip_msg_info->sip_resp_phrase_ptr;
      }
      sip_msg_info->is_request = B_FALSE;
   }
   else
   {
      int i;
      /*
       * It's a request.
       */
      sip_msg_info->is_request = B_TRUE;
      for (i = 1; i < MAX_SIP_METHODS; i++)
      {
         if (strncmp (sip_methods[i].name, sip_header->sip_hdr_current, sip_methods[i].len) == 0)
         {
            sip_msg_info->sip_req_method = i;
            sip_header->sip_hdr_current += sip_methods[i].len;
            if (!isspace (*sip_header->sip_hdr_current++) || !isalpha (*sip_header->sip_hdr_current))
            {
               free (sip_msg_info);
               return (EPROTO);
            }

            if (_sip_get_request_uri (sip_header, sip_msg_info))
            {
               free (sip_msg_info);
               return (EPROTO);
            }

            /*
             * Get SIP version
             */
            ret = sip_get_protocol_version (sip_header, &sip_msg_info->sip_proto_version);
            if (ret != 0)
            {
               free (sip_msg_info);
               return (EPROTO);
            }
            goto done;
         }
      }
      free (sip_msg_info);
      return (EPROTO);
   }
 done:
   sip_msg_info->sip_next = *msg_info;
   *msg_info = sip_msg_info;
   return (0);
}

/* We don't do anything for a header we don't understand */
/* ARGSUSED */
int sip_parse_unknown_header (_sip_header_t * sip_header, sip_parsed_header_t ** header)
{
   return (EINVAL);
}

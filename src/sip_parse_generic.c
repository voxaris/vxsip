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

/* atoi function from a header */
int sip_atoi (_sip_header_t * sip_header, int *num)
{
   boolean_t num_found = B_FALSE;

   *num = 0;
   while (sip_header->sip_hdr_current < sip_header->sip_hdr_end)
   {
      if (isspace (*sip_header->sip_hdr_current))
      {
         sip_header->sip_hdr_current++;
         if (num_found)
            break;
      }
      else if (isdigit (*sip_header->sip_hdr_current))
      {
         *num = (*num * 10) + (*sip_header->sip_hdr_current - '0');
         num_found = B_TRUE;
         sip_header->sip_hdr_current++;
      }
      else
      {
         break;
      }
   }
   if (!num_found)
      return (EINVAL);
   return (0);
}

/* Find the 'token' */
int sip_find_token (_sip_header_t * sip_header, char token)
{
   while (sip_header->sip_hdr_current < sip_header->sip_hdr_end)
   {
      if (token != SIP_COMMA && *sip_header->sip_hdr_current == SIP_COMMA)
      {
         sip_header->sip_hdr_current--;
         return (1);
      }
      if (*sip_header->sip_hdr_current++ == token)
      {
         /*
          * sip_hdr_current points to the char
          * after the token
          */
         return (0);
      }
   }
   return (1);
}

/* Find a carriage-return */
int sip_find_cr (_sip_header_t * sip_header)
{
   sip_header->sip_hdr_current = sip_header->sip_hdr_end;
   while (*sip_header->sip_hdr_current-- != '\n')
   {
      if (sip_header->sip_hdr_current == sip_header->sip_hdr_start)
         return (EINVAL);
   }
   return (0);
}

/*
 * Find one of the separator provided, i.e. separator_1st or separator_2nd or
 * separator_3rd.
 */
int sip_find_separator (_sip_header_t * sip_header, char separator_1st, char separator_2nd, char separator_3rd)
{
   assert (separator_1st != '\0' || separator_2nd != '\0');
   while (sip_header->sip_hdr_current < sip_header->sip_hdr_end)
   {
      if (isspace (*sip_header->sip_hdr_current) ||
          (separator_1st != '\0' &&
           (*sip_header->sip_hdr_current == separator_1st)) ||
          (separator_2nd != '\0' &&
           (*sip_header->sip_hdr_current == separator_2nd)) ||
          (separator_3rd != '\0' && (*sip_header->sip_hdr_current == separator_3rd)))
      {
         return (0);
      }
      /*
       * If we have escape character, go to the next char
       */
      if (*sip_header->sip_hdr_current == '\\')
         sip_header->sip_hdr_current++;
      sip_header->sip_hdr_current++;
   }
   return (1);
}

/* Return when we hit a white space */
int sip_find_white_space (_sip_header_t * sip_header)
{
   while (sip_header->sip_hdr_current < sip_header->sip_hdr_end)
   {
      if (isspace (*sip_header->sip_hdr_current))
         return (0);
      sip_header->sip_hdr_current++;
   }
   return (1);
}

/* Skip to the next non-whitespace */
int sip_skip_white_space (_sip_header_t * sip_header)
{
   while (sip_header->sip_hdr_current < sip_header->sip_hdr_end)
   {
      if (!isspace (*sip_header->sip_hdr_current))
         return (0);
      sip_header->sip_hdr_current++;
   }
   return (1);
}


/* Skip to the non-white space in the reverse direction */
int sip_reverse_skip_white_space (_sip_header_t * sip_header)
{
   while (sip_header->sip_hdr_current >= sip_header->sip_hdr_start)
   {
      if (!isspace (*sip_header->sip_hdr_current))
         return (0);
      sip_header->sip_hdr_current--;
   }
   return (1);
}

/* get to the first non space after ':' */
int sip_parse_goto_values (_sip_header_t * sip_header)
{

   if (sip_find_token (sip_header, SIP_HCOLON) != 0)
      return (1);
   if (sip_skip_white_space (sip_header))
      return (1);

   return (0);
}

/* Skip the current value. */
int sip_goto_next_value (_sip_header_t * sip_header)
{
   boolean_t quoted = B_FALSE;

   while (sip_header->sip_hdr_current < sip_header->sip_hdr_end)
   {
      if (*sip_header->sip_hdr_current == SIP_QUOTE)
      {
         if (quoted)
            quoted = B_FALSE;
         else
            quoted = B_TRUE;
      }
      else if (!quoted && *sip_header->sip_hdr_current == SIP_COMMA)
      {
         /* value ends before the COMMA */
         sip_header->sip_hdr_current--;
         return (0);
      }
      sip_header->sip_hdr_current++;
   }
   if (quoted)
      return (1);
   return (0);
}

/* Parse the header into parameter list. Parameters start with a ';'  */
int sip_parse_params (_sip_header_t * sip_header, sip_param_t ** parsed_list)
{
   sip_param_t *param = NULL;
   sip_param_t *new_param;
   char *tmp_ptr;

   *parsed_list = NULL;
   for (;;)
   {
      boolean_t quoted_name = B_FALSE;

      /* First check if there are any parama */
      if (sip_skip_white_space (sip_header) != 0)
         return (0);
      if (*sip_header->sip_hdr_current != SIP_SEMI)
         return (0);

      sip_header->sip_hdr_current++;

      new_param = calloc (1, sizeof (sip_param_t));
      if (new_param == NULL)
         return (ENOMEM);

      if (param != NULL)
         param->param_next = new_param;
      else
         *parsed_list = new_param;

      param = new_param;

      /* Let's get to the start of the param name */
      if (sip_skip_white_space (sip_header) != 0)
         return (EPROTO);
      /*
       * start of param name
       */
      tmp_ptr = sip_header->sip_hdr_current;
      param->param_name.sip_str_ptr = tmp_ptr;

      if (sip_find_separator (sip_header, SIP_EQUAL, SIP_SEMI, SIP_COMMA) != 0)
      {
         param->param_name.sip_str_len = sip_header->sip_hdr_current - tmp_ptr;
         param->param_value.sip_str_ptr = NULL;
         param->param_value.sip_str_len = 0;
         return (0);
      }

      /*
       * End of param name
       */
      param->param_name.sip_str_len = sip_header->sip_hdr_current - tmp_ptr;

      if (sip_skip_white_space (sip_header) != 0 || *sip_header->sip_hdr_current == SIP_COMMA)
      {
         param->param_value.sip_str_ptr = NULL;
         param->param_value.sip_str_len = 0;
         return (0);
      }
      if (*sip_header->sip_hdr_current == SIP_SEMI)
      {
         param->param_value.sip_str_ptr = NULL;
         param->param_value.sip_str_len = 0;
         continue;
      }
      assert (*sip_header->sip_hdr_current == SIP_EQUAL);

      /* We are at EQUAL, lets go beyond that */
      sip_header->sip_hdr_current++;

      if (sip_skip_white_space (sip_header) != 0)
         return (EPROTO);

      if (*sip_header->sip_hdr_current == SIP_QUOTE)
      {
         sip_header->sip_hdr_current++;
         quoted_name = B_TRUE;
      }

      /* start of param value */
      param->param_value.sip_str_ptr = sip_header->sip_hdr_current;
      tmp_ptr = sip_header->sip_hdr_current;

      if (quoted_name && sip_find_token (sip_header, SIP_QUOTE) != 0)
      {
         return (EPROTO);
      }
      else if (sip_find_separator (sip_header, SIP_SEMI, SIP_COMMA, '\0') != 0)
      {
         return (EPROTO);
      }
      param->param_value.sip_str_len = sip_header->sip_hdr_current - tmp_ptr;
      if (quoted_name)
         param->param_value.sip_str_len--;
   }
}

/*
 * a header only has "header_name : " is an empty header
 * ":" must exist
 * sip_hdr_current resets to sip_hdr_start before exit
 */
boolean_t sip_is_empty_hdr (_sip_header_t * sip_header)
{
   if (sip_find_token (sip_header, SIP_HCOLON) != 0)
   {
      sip_header->sip_hdr_current = sip_header->sip_hdr_start;
      return (B_TRUE);
   }

   if (sip_skip_white_space (sip_header) == 0)
   {
      sip_header->sip_hdr_current = sip_header->sip_hdr_start;
      return (B_TRUE);
   }

   sip_header->sip_hdr_current = sip_header->sip_hdr_start;
   return (B_FALSE);
}

/* Parsing an empty header, i.e. only has a ":" */
int sip_parse_hdr_empty (_sip_header_t * hdr, sip_parsed_header_t ** phdr)
{
   sip_parsed_header_t *parsed_header;

   if (hdr == NULL || phdr == NULL)
      return (EINVAL);
   /* check if already parsed */
   if (hdr->sip_hdr_parsed != NULL)
   {
      *phdr = hdr->sip_hdr_parsed;
      return (0);
   }

   *phdr = NULL;

   parsed_header = calloc (1, sizeof (sip_parsed_header_t));
   if (parsed_header == NULL)
      return (ENOMEM);
   parsed_header->sip_header = hdr;

   parsed_header->value = NULL;

   *phdr = parsed_header;
   return (0);
}

/* validate uri str and parse uri using uri_parse() */
void sip_parse_uri_str (sip_str_t * sip_str, sip_parsed_header_t * hdr, sip_hdr_value_t * value)
{
   int error;

   /* Parse uri */
   if (sip_str->sip_str_len > 0)
   {
      value->sip_value_parsed_uri = sip_parse_uri (sip_str, &error);
      if (value->sip_value_parsed_uri == NULL)
      {
         sip_free_phdr (hdr);
         return;
      }
      if (error != 0 || value->sip_value_parsed_uri->sip_uri_errflags != 0)
      {
         value->sip_value_state = SIP_VALUE_BAD;
      }
   }
}

/*
 * parser1 parses hdr format
 *	header_name: val1[; par1=pval1;par2=pval2 ..][, val2[;parlist..] ]
 *	val can be str1/str2 or str
 * headers: Accept, Accept-Encode, Accept-lang, Allow, Content-disp,
 *	    Content-Encode, Content-Lang, In-reply-to,
 *	    Priority, Require, Supported, Unsupported
 *	    Allow-Events, Event, Subscription-State
 */
int sip_parse_hdr_parser1 (_sip_header_t * hdr, sip_parsed_header_t ** phdr, char sep)
{
   sip_parsed_header_t *parsed_header;
   int ret;
   sip_hdr_value_t *value = NULL;
   sip_hdr_value_t *last_value = NULL;

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

      if (sip_find_separator (hdr, sep, SIP_COMMA, SIP_SEMI) == 0)
      {
         char c = *(hdr->sip_hdr_current);

         if (isspace (c) && sep == '\0')
         {
            value->str_val_ptr = value->sip_value_start;
            value->str_val_len = hdr->sip_hdr_current - value->sip_value_start;
            /* nothing at the end except SP */
            if (sip_skip_white_space (hdr) != 0)
               goto end;
            /* white space skipped */
            c = *(hdr->sip_hdr_current);
         }

         /* only one string until COMMA, use sip_str_t */
         if (c == SIP_COMMA)
         {
            char *t = hdr->sip_hdr_current;

            hdr->sip_hdr_current--;
            (void) sip_reverse_skip_white_space (hdr);
            value->str_val_ptr = value->sip_value_start;
            value->str_val_len = hdr->sip_hdr_current - value->sip_value_start + 1;
            hdr->sip_hdr_current = t;
            goto get_next_val;
         }

         /* two strings, use sip_2strs_t */
         if ((sep != '\0') && (c == sep))
         {
            value->strs1_val_ptr = value->sip_value_start;
            value->strs1_val_len = hdr->sip_hdr_current - value->sip_value_start;

            value->strs2_val_ptr = (++hdr->sip_hdr_current);
            if (sip_find_separator (hdr, SIP_SEMI, SIP_COMMA, '\0') == 0)
            {
               char t = *(hdr->sip_hdr_current);
               value->strs2_val_len = hdr->sip_hdr_current - value->strs2_val_ptr;
               /*
                * if COMMA, no param list, get next val
                * if SEMI, need to set params list
                */
               if (t == SIP_COMMA)
                  goto get_next_val;
            }
            else
            {                   /* the last part */
               value->strs2_val_len = hdr->sip_hdr_current - value->strs2_val_ptr;
               goto end;
            }
         }
         else if (sep != '\0')
         {
            value->sip_value_state = SIP_VALUE_BAD;
            goto get_next_val;
         }

         /*
          * c == SEMI, value contains single string
          * only one string until SEMI, use sip_str_t
          */
         if (c == SIP_SEMI)
         {
            char *t = hdr->sip_hdr_current;

            hdr->sip_hdr_current--;
            /* get rid of SP at end of value field */
            (void) sip_reverse_skip_white_space (hdr);
            value->str_val_ptr = value->sip_value_start;
            value->str_val_len = hdr->sip_hdr_current - value->str_val_ptr + 1;
            hdr->sip_hdr_current = t;
         }

         /*
          * if SEMI exists in the value, set params list
          * two situations, there is or not SLASH before SEMI
          */
         ret = sip_parse_params (hdr, &value->sip_param_list);
         if (ret == EPROTO)
         {
            value->sip_value_state = SIP_VALUE_BAD;
         }
         else if (ret != 0)
         {
            sip_free_phdr (parsed_header);
            return (ret);
         }
         goto get_next_val;
      }
      else
      {
         value->str_val_ptr = value->sip_value_start;
         value->str_val_len = hdr->sip_hdr_current - value->sip_value_start;
         goto end;
      }
    get_next_val:
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
 * header_name: int
 * headers: Expires, Min-Expires
 */
/* ARGSUSED */
int sip_parse_hdr_parser2 (_sip_header_t * hdr, sip_parsed_header_t ** phdr, int val_type)
{
   sip_parsed_header_t *parsed_header;
   int ret = 0;
   sip_hdr_value_t *value = NULL;

   if (hdr == NULL || phdr == NULL)
      return (EINVAL);
   /* check if already parsed */
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

   value = calloc (1, sizeof (sip_hdr_value_t));
   if (value == NULL)
   {
      sip_free_phdr (parsed_header);
      return (ENOMEM);
   }

   parsed_header->value = (sip_value_t *) value;

   value->sip_value_start = hdr->sip_hdr_current;
   value->sip_value_header = parsed_header;

   ret = sip_atoi (hdr, &value->int_val);
   if (ret != 0)
   {
      value->int_val = 0;
      value->sip_value_state = SIP_VALUE_BAD;
   }

   value->sip_value_end = hdr->sip_hdr_current - 1;

   *phdr = parsed_header;
   return (0);
}

/*
 * parser3 parses hdr format
 * header_name: <val1>[, <val2>]
 * Alert-Info, Call-Info, Error-Info, reply-to
 */
int sip_parse_hdr_parser3 (_sip_header_t * hdr, sip_parsed_header_t ** phdr, int type, boolean_t parse_uri)
{
   sip_parsed_header_t *parsed_header;
   sip_hdr_value_t *value = NULL;
   sip_hdr_value_t *last_value = NULL;

   if (hdr == NULL || phdr == NULL)
      return (EINVAL);
   /*
    * check if previously parsed
    */
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
      int r;

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

      if (type == SIP_STRS_VAL)
      {
         if (sip_find_token (hdr, SIP_LAQUOT) == 0)
         {
            char *cur;

            /* record the position after LAQUOT */
            cur = hdr->sip_hdr_current;
            /* get display name and store in str1 */
            hdr->sip_hdr_current = value->sip_value_start;
            if (*(hdr->sip_hdr_current) != SIP_LAQUOT)
            {
               /* record start pos of display name */
               char *tmp = hdr->sip_hdr_current;

               if (*hdr->sip_hdr_current == SIP_QUOTE)
               {
                  hdr->sip_hdr_current++;
                  tmp++;
                  if (sip_find_token (hdr, SIP_QUOTE) != 0)
                  {
                     value->sip_value_state = SIP_VALUE_BAD;
                     goto get_next_val;
                  }
                  hdr->sip_hdr_current -= 2;
               }
               else
               {
                  hdr->sip_hdr_current = cur - 2;
                  (void) sip_reverse_skip_white_space (hdr);
               }
               value->strs1_val_ptr = tmp;
               value->strs1_val_len = hdr->sip_hdr_current - tmp + 1;
            }
            else
            {
               value->strs1_val_ptr = NULL;
               value->strs1_val_len = 0;
            }

            /* set current to the char after LAQUOT */
            hdr->sip_hdr_current = cur;
            value->strs2_val_ptr = hdr->sip_hdr_current;
            if (sip_find_token (hdr, SIP_RAQUOT))
            {
               /* no RAQUOT */
               value->strs1_val_ptr = NULL;
               value->strs1_val_len = 0;
               value->strs2_val_ptr = NULL;
               value->strs2_val_len = 0;
               value->sip_value_state = SIP_VALUE_BAD;
               goto get_next_val;
            }
            value->strs2_val_len = hdr->sip_hdr_current - value->strs2_val_ptr - 1;
         }
         else
         {
            /*
             * have to be surrounded by AQUOT
             * invalid value
             */
            value->strs1_val_ptr = NULL;
            value->strs1_val_len = 0;
            value->strs2_val_ptr = NULL;
            value->strs2_val_len = 0;
            value->sip_value_state = SIP_VALUE_BAD;
            goto get_next_val;
         }
         if (parse_uri)
         {
            sip_parse_uri_str (&value->strs_s2, parsed_header, value);
         }
      }

      if (type == SIP_STR_VAL)
      {
         /* alert-info, error-info, call-info */
         if (sip_find_token (hdr, SIP_LAQUOT) == 0)
         {
            value->str_val_ptr = hdr->sip_hdr_current;
            if (sip_find_token (hdr, SIP_RAQUOT) == 0)
            {
               value->str_val_len = hdr->sip_hdr_current - value->str_val_ptr - 1;
            }
            else
            {
               value->str_val_ptr = NULL;
               value->str_val_len = 0;
               value->sip_value_state = SIP_VALUE_BAD;
               goto get_next_val;
            }
            hdr->sip_hdr_current--;
         }
         else
         {
            value->str_val_ptr = NULL;
            value->str_val_len = 0;
            value->sip_value_state = SIP_VALUE_BAD;
            goto get_next_val;
         }
         if (parse_uri)
         {
            sip_parse_uri_str (&value->str_val, parsed_header, value);
         }
      }

      r = sip_find_separator (hdr, SIP_COMMA, SIP_SEMI, '\0');
      if (r != 0)
         goto end;
      if (*hdr->sip_hdr_current == SIP_SEMI)
      {
         (void) sip_parse_params (hdr, &(value->sip_param_list));
         goto get_next_val;
      }

      if (*hdr->sip_hdr_current == SIP_COMMA)
      {
         hdr->sip_hdr_current--;
         goto get_next_val;
      }
    get_next_val:
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
 * parser4 parses hdr format, the whole field is one single str
 * header: Subject, MIME-Version, Organization, Server, User-Agent
 */
int sip_parse_hdr_parser4 (_sip_header_t * hdr, sip_parsed_header_t ** phdr)
{
   sip_parsed_header_t *parsed_header;
   sip_hdr_value_t *value = NULL;

   if (hdr == NULL || phdr == NULL)
      return (EINVAL);
   /*
    * check if previously parsed
    */
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

   value = calloc (1, sizeof (sip_hdr_value_t));
   if (value == NULL)
   {
      sip_free_phdr (parsed_header);
      return (ENOMEM);
   }

   parsed_header->value = (sip_value_t *) value;

   value->sip_value_start = hdr->sip_hdr_current;
   value->sip_value_header = parsed_header;

   value->str_val_ptr = hdr->sip_hdr_current;
   /* get rid of CRLF at end */
   value->str_val_len = hdr->sip_hdr_end - value->str_val_ptr - 2;
   value->sip_value_end = hdr->sip_hdr_end;

   *phdr = parsed_header;
   return (0);
}

int sip_parse_hdr_parser5 (_sip_header_t * hdr, sip_parsed_header_t ** phdr, boolean_t parse_uri)
{
   sip_parsed_header_t *parsed_header;
   sip_hdr_value_t *value = NULL;
   sip_param_t *tmp_param;
   boolean_t first_param = B_TRUE;

   if (hdr == NULL || phdr == NULL)
      return (EINVAL);
   /*
    * check if previously parsed
    */
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

   value = calloc (1, sizeof (sip_hdr_value_t));
   if (value == NULL)
   {
      sip_free_phdr (parsed_header);
      return (ENOMEM);
   }

   parsed_header->value = (sip_value_t *) value;

   value->sip_value_start = hdr->sip_hdr_current;
   value->auth_scheme_ptr = value->sip_value_start;
   value->sip_value_header = parsed_header;
   /* get auth_scheme */
   if (sip_find_white_space (hdr))
   {
      value->sip_value_state = SIP_VALUE_BAD;
      return (EINVAL);
   }
   value->auth_scheme_len = hdr->sip_hdr_current - value->auth_scheme_ptr;

   tmp_param = value->auth_param;

   /* parse auth_param */
   for (;;)
   {
      char *tmp_cur;
      boolean_t quoted_name = B_FALSE;
      char quoted_char = (char) 0;
      sip_param_t *new_param;
      boolean_t pval_is_uri = B_FALSE;

      if (sip_skip_white_space (hdr) != 0)
      {
         value->sip_value_state = SIP_VALUE_BAD;
         return (EPROTO);
      }
      tmp_cur = hdr->sip_hdr_current;

      new_param = calloc (1, sizeof (sip_param_t));
      if (new_param == NULL)
         return (ENOMEM);

      if (first_param == B_FALSE)
         tmp_param->param_next = new_param;
      else
         value->auth_param = new_param;

      tmp_param = new_param;
      tmp_param->param_name.sip_str_ptr = tmp_cur;

      if (sip_find_separator (hdr, SIP_EQUAL, SIP_COMMA, '\0') != 0)
      {
         tmp_param->param_name.sip_str_len = hdr->sip_hdr_current - tmp_cur;
         tmp_param->param_value.sip_str_ptr = NULL;
         tmp_param->param_value.sip_str_len = 0;
         goto end;
      }

      /*
       * End of param name
       */
      tmp_param->param_name.sip_str_len = hdr->sip_hdr_current - tmp_cur;

      if (sip_skip_white_space (hdr) != 0 || *hdr->sip_hdr_current == SIP_COMMA)
      {
         tmp_param->param_value.sip_str_ptr = NULL;
         tmp_param->param_value.sip_str_len = 0;
         continue;
      }

      /*
       * We are at EQUAL
       */
      hdr->sip_hdr_current++;

      if (sip_skip_white_space (hdr) != 0)
      {
         value->sip_value_state = SIP_VALUE_BAD;
         free (tmp_param);
         return (EPROTO);
      }

      if (*hdr->sip_hdr_current == SIP_QUOTE || *hdr->sip_hdr_current == SIP_LAQUOT)
      {
         if (*hdr->sip_hdr_current == SIP_QUOTE)
            quoted_char = SIP_QUOTE;
         else
         {
            quoted_char = SIP_RAQUOT;
            pval_is_uri = B_TRUE;
         }
         hdr->sip_hdr_current++;
         quoted_name = B_TRUE;
      }

      /*
       * start of param value
       */
      tmp_cur = hdr->sip_hdr_current;
      tmp_param->param_value.sip_str_ptr = tmp_cur;
      if (quoted_name)
      {
         if (sip_find_token (hdr, quoted_char) != 0)
         {
            value->sip_value_state = SIP_VALUE_BAD;
            free (tmp_param);
            return (EPROTO);
         }
         tmp_param->param_value.sip_str_len = hdr->sip_hdr_current - tmp_cur - 1;
      }

      if (sip_find_token (hdr, SIP_COMMA) != 0)
         goto end;
      else
      {
         if (!quoted_name)
         {
            char *t = hdr->sip_hdr_current;
            hdr->sip_hdr_current--;
            (void) sip_reverse_skip_white_space (hdr);
            tmp_param->param_value.sip_str_len = hdr->sip_hdr_current - tmp_cur;
            hdr->sip_hdr_current = t;
         }
      }

      if (first_param == B_TRUE)
         first_param = B_FALSE;
      if ((pval_is_uri == B_TRUE) && (parse_uri == B_TRUE))
      {
         /* Parse uri */
         sip_parse_uri_str (&tmp_param->param_value, parsed_header, value);
      }

   }

 end:
   *phdr = parsed_header;
   return (0);
}

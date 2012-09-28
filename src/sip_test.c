#include <sip_msg.h>

sip_msg_t sip_create (char *msgstr, size_t len)
{
   _sip_msg_t *sip_msg;
   int err;

   fprintf (stdout, ">>>\n%s<<<\n", msgstr);

   sip_msg = (_sip_msg_t *) sip_new_msg ();
   if (sip_msg == NULL)
   {
      return (NULL);
   }
   sip_msg->sip_msg_buf = (char *) msgstr;
   sip_msg->sip_msg_len = len; 
   if (sip_setup_header_pointers (sip_msg) != 0)
      goto error;
 
   if (sip_parse_first_line (sip_msg->sip_msg_start_line, &sip_msg->sip_msg_req_res))
      goto error;

   if (sip_get_to_uri_str ((sip_msg_t) sip_msg, &err) == NULL)
      goto error;

   if (sip_get_from_uri_str ((sip_msg_t) sip_msg, &err) == NULL)
      goto error;

   if (sip_get_callseq_num ((sip_msg_t) sip_msg, &err) < 0)
      goto error;

   if (sip_get_callid ((sip_msg_t) sip_msg, &err) == NULL)
      goto error;

   return (sip_msg);

error:
   sip_free_msg ((sip_msg_t) sip_msg);
   printf ("error: ...\n");
   return (NULL);
}

int main (int argc, char *argv[])
{
   FILE *file;
//   size_t len;
   char *buffer, *ptr; 
   sip_msg_t sip_msg;

   if (argc > 0)
   {
      int body = 0;
      int line = 0;
//      char *scrap;
      printf ("Starting sip load: %d [%s %s]\n", argc, argv[0], argv[1]);
      file = fopen (argv[1], "r");
      buffer = malloc (8192);
      ptr = buffer;
      for (;;)
      {
         if (fgets (ptr, 8192 - (ptr-buffer), file))
         {
            line++;
//            fprintf (stdout, "<%s>\n", ptr);
            if (strncmp (ptr, "\r\n", 2) == 0) // it's a blank line
            {
//fprintf (stdout, "blank line CRLF %d\n", line);
               if ((body == 0) && (strstr (buffer, "Content-Length: 0")) == NULL)
               {
//fprintf (stdout,"looking for boody %d\n", line);
                  body = 1;
                  ptr += strlen (ptr);
               }
               else
               {
                  fprintf (stdout, ">>>\n%s<<<\n", buffer);
                  body = 0;
                  ptr = buffer;
                  sip_msg = sip_create (buffer, strlen(buffer));
                  sip_free_msg (sip_msg);
               }
            }
            else
            {
               ptr += strlen (ptr);
 //              len = ptr - buffer;
            }
         }
         else
         {
            break;
         }
      }
   }

   return (0);
};

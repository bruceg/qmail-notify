#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <systime.h>
#include <iobuf/obuf.h>
#include <misc/misc.h>
#include <msg/msg.h>

#include "qmail-notify.h"

static const char* bounce_header = "{"
"From: <MAILER-DAEMON@}s{>\n"
"To: <}s{>\n"
"Subject: delayed delivery notice\n}";

static const char* mime_bounce_header = "{"
"MIME-Version: 1.0\n"
"Content-Type: multipart/mixed; boundary=\"}s{\"\n"
"\n"
"This is a multi-part message in MIME format.\n"
"(If you can see this message, your E-mail client is not MIME compatible.)\n"
"--}s{\n"
"Content-Type: text/plain; charset=us-ascii\n"
"Content-Transfer-Encoding: 7bit\n}";

static const char* bounce_body = "{"
"Your message has been received by }s{ but has been\n"
"undeliverable to the following recipients for at least }s{.\n"
"The mail system will continue to attempt to deliver your message\n"
"to these recipients for a total of }s{.  You do not need to\n"
"resend your message at this time.\n}";

static const char* recipients_prefix = "\nRecipient(s):\n";

static const char* message_seperator =
"\n"
"--- Below this line is a copy of the original message.\n"
"\n";

static const char* mime_message_seperator = "{"
"\n"
"The following attachment contains a copy of the original message.\n"
"\n"
"--}s{\n"
"Content-Type: message/rfc822\n"
"Content-Disposition: inline\n"
"\n}";

static const char* mime_message_end = "{\n--}s{--}";

static char mime_boundary[65];

static void make_mime_boundary(void)
{
  static char chars[] = "0123456789ABCDEFHIJKLMNOPQRTUVWX";
  int i;
  struct timeval now;
  gettimeofday(&now, 0);
  random_init(now.tv_sec ^ now.tv_usec ^ getpid());
  for(i = 0; i < 64; i++)
    mime_boundary[i] = chars[random_trunc(32)];
  mime_boundary[i] = 0;
}

static void copy_message(obuf* out, const char* filename)
{
  int fd = open_file("mess", filename);
  char buf[4096];
  if(fd == -1)
    die1sys(111, "Could not open message file");
  if(opt_mime)
    obuf_putf(out, mime_message_seperator, mime_boundary);
  else
    obuf_puts(out, message_seperator);
  if(opt_msgbytes < 0)
    for(;;) {
      ssize_t rd = read(fd, buf, sizeof buf);
      if(rd <= 0)
	break;
      if (!obuf_write(out, buf, rd))
	break;
    }
  else {
    ssize_t total = 0;
    while(total < opt_msgbytes) {
      ssize_t tord = ((unsigned)opt_msgbytes < sizeof buf) ?
	opt_msgbytes : (ssize_t)sizeof buf;
      ssize_t rd = read(fd, buf, tord);
      if(rd <= 0)
	break;
      if (!obuf_write(out, buf, rd))
	break;
      total += rd;
    }
    if(total >= opt_msgbytes)
      obuf_puts(out, "[...]");
  }
  close(fd);
  if(opt_mime)
    obuf_putf(out, mime_message_end, mime_boundary);
  obuf_putc(out, '\n');
}

void load_bounce_body(const char* filename)
{
  int in;
  struct stat sbuf;
  char* buf;
  if ((in = open(filename, O_RDONLY)) == -1)
    die3sys(111, "Could not open '", filename, "'");
  if (fstat(in, &sbuf) == -1)
    die3sys(111, "Could not stat '", filename, "'");
  if ((buf = malloc(sbuf.st_size)) == 0)
    die1(111, "Could not allocate bytes for loading bounce response file.");
  if (read(in, buf, sbuf.st_size) != sbuf.st_size)
    die1(111, "Could not read the bounce response file.");
  close(in);
  bounce_body = buf;
}
  
static void time2str(time_t secs, char* buf)
{
  const char* name;
  if(secs >= 24*60*60)
    name = " days", secs /= 24*60*60;
  else if(secs >= 60*60)
    name = " hours", secs /= 60*60;
  else if(secs >= 60)
    name = " minutes", secs /= 60;
  else
    name = " seconds";
  strcpy(buf, utoa(secs));
  strcat(buf, name);
}

void make_bounce_body(int fd, const char* sender, const char* filename,
		      const char* remotes, const char* locals, time_t age)
{
  const char* ptr;
  char time1[128];
  char time2[128];
  obuf out;

  obuf_init(&out, fd, 0, 0, 0);
  time2str(age, time1);
  time2str(queuelifetime, time2);

  obuf_putf(&out, bounce_header, me, sender);
  if(opt_mime) {
    make_mime_boundary();
    obuf_putf(&out, mime_bounce_header, mime_boundary, mime_boundary);
  }
  obuf_puts(&out, "\n");
  obuf_putf(&out, bounce_body, me, time1, time2);
  obuf_puts(&out, recipients_prefix);
  for(ptr = locals; *ptr; ptr += strlen(ptr)+1)
    if(*ptr == 'T')
      obuf_putf(&out, "{\t}s{\n}", ptr+1);
  for(ptr = remotes; *ptr; ptr += strlen(ptr)+1)
    if(*ptr == 'T')
      obuf_putf(&out, "{\t}s{\n}", ptr+1);
  if(opt_msgbytes)
    copy_message(&out, filename);
  if (!obuf_flush(&out))
    die1sys(111, "Could not write bounce message");
}

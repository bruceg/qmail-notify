/* qmail-notify -- Delayed delivery notification for qmail
 * Copyright (C) 2000  Bruce Guenter <bruceg@em.ca>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "cdb/cdb.h"
#include "dict/dict.h"
#include "msg/msg.h"
#include "msg/wrap.h"
#include "str/str.h"
#include "direntry.h"
#include "fork.h"
#include "systime.h"

const char program[] = "qmail-notify";
const int msg_show_pid = 0;

static const char* queue_dir = "/var/qmail/queue";
static const char* control_dir = "/var/qmail/control";
static const char* qmail_inject = "/var/qmail/bin/qmail-inject";
static const char* run_file = "/var/run/qmail-notify.time";

static time_t now;
static time_t lastrun;
static pid_t inject_pid;
static const char* me;
static time_t queuelifetime = 0;
static const char* extra_rcpt;

static int opt_checkrcpt = 0;
static int opt_debug = 0;
static int opt_nosend = 0;
static int opt_mime = 0;
static time_t opt_age = 4*60*60;
static const char* extra_rcpt_name = "postmaster";
static ssize_t opt_msgbytes = -1;

static dict rcpthosts;
static cdb morercpthosts;
static int morercpthosts_fd;
static str strbuf;

void msgf(const char* fmt, ...)
{
  va_list ap;
  fputs("qmail-notify: ", stderr);
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  fputs("\n", stderr);
}

void oom(void) { die1(111, "Out of memory"); }

void time2str(time_t time, char* buf)
{
  if(time >= 24*60*60)
    sprintf(buf, "%ld days", time/24/60/60);
  else if(time >= 60*60)
    sprintf(buf, "%ld hours", time/60/60);
  else if(time >= 60)
    sprintf(buf, "%ld minutes", time/60);
  else
    sprintf(buf, "%ld seconds", time);
}

int open_file(const char* prefix, const char* filename)
{
  char fullname[100];
  if (prefix != 0) {
    sprintf(fullname, "%s/%s", prefix, filename);
    return open(fullname, O_RDONLY);
  }
  return open(filename, O_RDONLY);
}

char* read_file(const char* prefix, const char* filename)
{
  struct stat statbuf;
  char* data;
  int fd = open_file(prefix, filename);
  if(fd == -1 || fstat(fd, &statbuf) == -1) {
    data = malloc(1);
    data[0] = 0;
  }
  else {
    data = malloc(statbuf.st_size+1);
    read(fd, data, statbuf.st_size);
    data[statbuf.st_size] = 0;
  }
  close(fd);
  return data;
}

char* read_line(const char* prefix, const char* filename)
{
  char* data = read_file(prefix, filename);
  char* nl = strchr(data, '\n');
  if(nl)
    *nl = 0;
  return data;
}

long read_int(const char* prefix, const char* filename, long dflt)
{
  char* data = read_line(prefix, filename);
  long result = dflt;
  if(*data) {
    char* ptr;
    result = strtol(data, &ptr, 10);
    if(*ptr)
      result = dflt;
  }
  free(data);
  return result;
}

unsigned count_undone(const char* list)
{
  unsigned undone = 0;
  for(;;) {
    if(*list == 0)
      return undone;
    if(*list == 'T')
      ++undone;
    list += strlen(list) + 1;
  }
}

int check_rcpt(const char* sender)
{
  char* domain;
  
  if(!opt_checkrcpt)
    return 1;

  domain = strchr(sender, '@');
  if(!domain)
    return 0;

  for(++domain; domain; domain = strchr(domain+1, '.')) {
    if (!str_copys(&strbuf, domain)) oom();
    if (dict_get(&rcpthosts, &strbuf)) return 1;
  }
  return 0;
}

int fork_inject(const char* sender)
{
  int p[2];

  if(opt_debug)
    msgf("forking %s -f '' -a '%s' '%s'", qmail_inject, sender, extra_rcpt);

  if(opt_nosend) {
    inject_pid = 0;
    return dup(1);
  }
  
  pipe(p);
  inject_pid = fork();
  switch(inject_pid) {
  case -1:
    die1sys(111, "Could not fork");
  case 0:
    close(p[1]);
    close(0);
    dup2(p[0], 0);
    close(p[0]);
    execl(qmail_inject, qmail_inject, "-f", "", "-a", sender, 
	  extra_rcpt, 0);
    die1sys(111, "Exec of qmail-inject failed");
  default:
    close(p[0]);
    return p[1];
  }
}

void wait_inject(void)
{
  int status;
  if(inject_pid) {
    if(waitpid(inject_pid, &status, WUNTRACED) == -1)
      die1sys(111, "Could not wait for qmail-inject to exit");
    if(!WIFEXITED(status))
      die1(111, "qmail-inject crashed");
    if(WEXITSTATUS(status))
      die1(111, "qmail-inject exited with an error");
  }
}

static char mime_boundary[65];

static void make_mime_boundary(void)
{
  static char chars[] = "0123456789ABCDEF";
  int i;
  struct timeval now;
  gettimeofday(&now, 0);
  srandom(now.tv_sec ^ now.tv_usec);
  for(i = 0; i < 64; i++)
    mime_boundary[i] = chars[random() % 16];
  mime_boundary[i] = 0;
}

static const char* bounce_header =
"From: <MAILER-DAEMON@%s>\n"
"To: <%s>\n"
"Subject: delayed delivery notice\n";

static const char* mime_bounce_header =
"MIME-Version: 1.0\n"
"Content-Type: multipart/mixed; boundary=\"%s\"\n"
"\n"
"This is a multi-part message in MIME format.\n"
"(If you can see this message, your E-mail client is not MIME compatible.)\n"
"--%s\n"
"Content-Type: text/plain; charset=us-ascii\n"
"Content-Transfer-Encoding: 7bit\n";

static const char* bounce_body =
"Your message has been received by %s but has been\n"
"undeliverable to the following recipients for at least %s.\n"
"The mail system will continue to attempt to deliver your message\n"
"to these recipients for a total of %s.  You do not need to\n"
"resend your message at this time.\n";

static const char* recipients_prefix = "\nRecipient(s):\n";

static const char* message_seperator =
"\n"
"--- Below this line is a copy of the original message.\n"
"\n";

static const char* mime_message_seperator =
"\n"
"The following attachment contains a copy of the original message.\n"
"\n"
"--%s\n"
"Content-Type: message/rfc822\n"
"Content-Disposition: inline\n"
"\n";

static const char* mime_message_end = "\n--%s--";

static void copy_message(FILE* out, const char* filename)
{
  int fd = open_file("mess", filename);
  char buf[4096];
  if(fd == -1)
    die1sys(111, "Could not open message file");
  if(opt_mime)
    fprintf(out, mime_message_seperator, mime_boundary);
  else
    fputs(message_seperator, out);
  if(opt_msgbytes < 0)
    for(;;) {
      ssize_t rd = read(fd, buf, sizeof buf);
      if(rd <= 0)
	break;
      if(fwrite(buf, rd, 1, out) != 1)
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
      if(fwrite(buf, rd, 1, out) != 1)
	break;
      total += rd;
    }
    if(total >= opt_msgbytes)
      fputs("[...]", out);
  }
  close(fd);
  if(opt_mime)
    fprintf(out, mime_message_end, mime_boundary);
  fputc('\n', out);
}

void send_bounce(const char* sender, const char* filename,
		 const char* remotes, const char* locals)
{
  const char* ptr;
  char time1[100];
  char time2[100];
  int fd = fork_inject(sender);
  FILE* out = fdopen(fd, "w");
  time2str(opt_age, time1);
  time2str(queuelifetime, time2);
  fprintf(out, bounce_header, me, sender);
  if(opt_mime) {
    make_mime_boundary();
    fprintf(out, mime_bounce_header, mime_boundary, mime_boundary);
  }
  fputs("\n", out);
  fprintf(out, bounce_body, me, time1, time2);
  fputs(recipients_prefix, out);
  for(ptr = locals; *ptr; ptr += strlen(ptr)+1)
    if(*ptr == 'T')
      fprintf(out, "\t%s\n", ptr+1);
  for(ptr = remotes; *ptr; ptr += strlen(ptr)+1)
    if(*ptr == 'T')
      fprintf(out, "\t%s\n", ptr+1);
  if(opt_msgbytes)
    copy_message(out, filename);
  if(fclose(out) == EOF)
    die1sys(111, "Writing to qmail-inject failed");
  wait_inject();
}

void make_bounce(const char* sender, const char* filename)
{
  char* remotes = read_file("remote", filename);
  char* locals = read_file("local", filename);
  unsigned undone = count_undone(remotes) + count_undone(locals);
  if(opt_debug)
    msgf("filename=%s sender='%s' undone=%d", filename, sender, undone);
  
  if(undone)
    send_bounce(sender, filename, remotes, locals);
  free(locals);
  free(remotes);
}

void scan_info(const char* filename)
{
  struct stat statbuf;
  char infoname[100];
  time_t expiry;
  int fd;
  sprintf(infoname, "info/%s", filename);
  if((fd = open(infoname, O_RDONLY)) == -1 ||
     fstat(fd, &statbuf) == -1)
    die1sys(111, "Can't open or stat info file");
  /* Handle the file only if it's expiry time (creation time + opt_age)
     is before now and after the last run */
  expiry = statbuf.st_mtime + opt_age;
  if(opt_debug)
    msgf("filename=%s expiry=%ld", filename, expiry);
  if(expiry > now) {
    if(opt_debug)
      msgf("ignoring, has not yet expired");
  }
  else if(expiry <= lastrun) {
    if(opt_debug)
      msgf("ignoring, was previously expired");
  }
  else {
    /* Load the sender address from the info file */
    char* sender = malloc(statbuf.st_size);
    read(fd, sender, statbuf.st_size);
    if(check_rcpt(sender+1))
      make_bounce(sender+1, filename);
    else if(opt_debug)
      msgf("ignoring, sender was not in rcpthosts");
    free(sender);
  }
  close(fd);
}

void scan_dir(const char* dirnum)
{
  DIR* dir;
  direntry* entry;
  char buf1[100];
  sprintf(buf1, "info/%s", dirnum);
  if((dir = opendir(buf1)) == 0)
    die1sys(111, "Can't open queue directory");
  while((entry = readdir(dir)) != 0) {
    if(entry->d_name[0] != '.') {
      char filename[100];
      sprintf(filename, "%s/%s", dirnum, entry->d_name);
      scan_info(filename);
    }
  }
  closedir(dir);
}

void scan_queue(void)
{
  DIR* dir;
  direntry* entry;
  wrap_chdir(queue_dir);
  if((dir = opendir("info")) == 0)
    die1sys(111, "Can't open queue directory");
  while((entry = readdir(dir)) != 0)
    if(entry->d_name[0] != '.')
      scan_dir(entry->d_name);
  closedir(dir);
}

static void load_rcpthosts(void)
{
  char* rh = read_file(0, "rcpthosts");
  if (!dict_init(&rcpthosts)) oom();
  if (rh) {
    const char* curr = rh;
    while (*curr) {
      const char* end;
      const char* next;
      if ((end = strchr(curr, '\n')) != 0)
	next = end + 1;
      else
	next = end = curr + strlen(curr);
      if (*curr != '#') {
	if (!str_copyb(&strbuf, curr, end-curr)) oom();
	if (!dict_add(&rcpthosts, &strbuf, 0)) oom();
      }
      curr = next;
    }
    free(rh);
  }
}

void load_config(void)
{
  wrap_chdir(control_dir);
  
  me = read_line(0, "me");
  if(!*me)
    die1(111, "Could not read control/me");
  queuelifetime = read_int(0, "queuelifetime", 604800);
  now = time(0);
  lastrun = read_int("", run_file, 0);
  
  if(extra_rcpt_name && *extra_rcpt_name) {
    if(strchr(extra_rcpt_name, '@'))
      extra_rcpt = extra_rcpt_name;
    else {
      char* er = malloc(strlen(extra_rcpt_name)+strlen(me)+2);
      strcpy(er, extra_rcpt_name);
      strcat(er, "@");
      strcat(er, me);
      extra_rcpt = er;
    }
  }
  else
    extra_rcpt = 0;

  if (opt_checkrcpt) load_rcpthosts();

  if(opt_debug) {
    msgf("me='%s'", me);
    msgf("queuelifetime=%ld", queuelifetime);
    msgf("extra_rcpt='%s'", extra_rcpt);
    msgf("now=%ld", now);
    msgf("lastrun=%ld", lastrun);
    msgf("opt_age=%ld", opt_age);
  }
}

const char* usage_str =
"usage: qmail-notify [-Nv] [-b BYTES] [-t SECONDS] [-x RECIP]\n"
"  -b N  Copy N bytes from the original message into the notice.\n"
"        Setting N to -1 means copy the entire message.  (defaults to -1)\n"
"  -d    Show debugging messages.\n"
"  -f F  Load the bounce response message from a file named F.\n"
"  -h    Show this usage help.\n"
"  -m    Encode the original message as a MIME attachment.\n"
"  -N    Don't send messages, just print them out.\n"
"  -r    Only send to senders with a domain listed in qmail's rcpthosts.\n"
"  -t N  Send notifications for messages that are N seconds old or older.\n"
"        (defaults to 4 hours)\n"
"  -x R  Send a copy of the notification to R.  (defaults to 'postmaster')\n";

void usage(const char* str)
{
  if(str)
    msgf("Error: %s", str);
  fputs(usage_str, stderr);
  exit(1);
}

void load_bounce_body(const char* filename)
{
  int in;
  struct stat sbuf;
  char* buf;
  if ((in = open(filename, O_RDONLY)) == -1)
    usage("Could not open bounce response file.");
  if (fstat(in, &sbuf) == -1)
    usage("Could not stat bounce response file.");
  if ((buf = malloc(sbuf.st_size)) == 0)
    usage("Could not allocate bytes for loading bounce response file.");
  if (read(in, buf, sbuf.st_size) != sbuf.st_size)
    usage("Could not read the bounce response file.");
  close(in);
  bounce_body = buf;
}
  
void parse_args(int argc, char* argv[])
{
  int ch;
  while((ch = getopt(argc, argv, "b:df:hmNrt:x:")) != EOF) {
    switch(ch) {
    case 'b': opt_msgbytes = atoi(optarg);    break;
    case 'd': opt_debug = 1;                  break;
    case 'f': load_bounce_body(optarg);       break;
    case 'h': usage(0);                       break;
    case 'm': opt_mime = 1;                   break;
    case 'N': opt_nosend = 1;                 break;
    case 'r': opt_checkrcpt = 1;              break;
    case 't': opt_age = atoi(optarg);         break;
    case 'x': extra_rcpt_name = optarg;       break;
    case '?': usage(0);
    }
  }
  if(optind < argc)
    usage(0);
}

void touch_run_file(void)
{
  FILE* out = fopen(run_file, "w");
  if(!out || fprintf(out, "%ld", now) == EOF || fclose(out) == EOF)
    die1(111, "Could not update run file");
}

int main(int argc, char* argv[])
{
  parse_args(argc, argv);
  load_config();
  scan_queue();
  if(!opt_nosend)
    touch_run_file();
  return 0;
}

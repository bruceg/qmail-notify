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
#include "cli/cli.h"
#include "dict/dict.h"
#include "msg/msg.h"
#include "msg/wrap.h"
#include "str/str.h"
#include "direntry.h"
#include "fork.h"
#include "systime.h"
#include "qmail-notify.h"

const char program[] = "qmail-notify";
const int msg_show_pid = 0;

static const char* queue_dir = "/var/qmail/queue";
static const char* control_dir = "/var/qmail/control";
static const char* qmail_inject = "/var/qmail/bin/qmail-inject";
static const char* run_file = "/var/run/qmail-notify.time";

static time_t now;
static time_t lastrun;
static pid_t inject_pid;
const char* me = 0;
time_t queuelifetime = 0;
static const char* extra_rcpt = 0;

int opt_checkrcpt = 0;
int opt_debug = 0;
int opt_nosend = 0;
int opt_mime = 0;
time_t opt_age = 4*60*60;
const char* extra_rcpt_name = 0;
int opt_msgbytes = -1;
const char* opt_bounce_filename = 0;

static dict rcpthosts;
static struct cdb morercpthosts;
static int morercpthosts_fd;
static str strbuf;

const char cli_help_prefix[] = "";
const char cli_help_suffix[] = "";
const char cli_args_usage[] = "";
const int cli_args_min = 0;
const int cli_args_max = 0;
cli_option cli_options[] = {
  { 'b', 0, CLI_INTEGER, 0, &opt_msgbytes,
    "Copy N bytes from the original message into the notice.",
    "entire message" },
  { 'd', 0, CLI_FLAG, 1, &opt_debug,
    "Show debugging messages", 0 },
  { 'f', 0, CLI_STRING, 0, &opt_bounce_filename,
    "Load the bounce response message from a file", 0 },
  { 'm', 0, CLI_FLAG, 1, &opt_mime,
    "Encode the original message as a MIME attachment", 0 },
  { 'N', 0, CLI_FLAG, 1, &opt_nosend,
    "Don't send messages, just print them out", 0 },
  { 'r', 0, CLI_FLAG, 1, &opt_checkrcpt,
    "Only respond to senders with a domain listed in qmail's rcpthosts", 0 },
  { 't', 0, CLI_INTEGER, 0, &opt_age,
    "Send notifications for messages that are at least N seconds old",
    "4 hours" },
  { 'x', 0, CLI_STRING, 0, &extra_rcpt_name,
    "Send a copy of the notification to the given recipient", 0 },
  { 0,0,0,0,0,0,0 }
};

void msgf(const char* fmt, ...)
{
  va_list ap;
  fputs("qmail-notify: ", stderr);
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  fputs("\n", stderr);
}

void oom(void) { die1(111, "Out of memory"); }

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
    if (morercpthosts_fd != -1 &&
	cdb_find(&morercpthosts, strbuf.s, strbuf.len) != 0)
      return 1;
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

void send_bounce(const char* sender, const char* filename,
		 const char* remotes, const char* locals)
{
  int fd = fork_inject(sender);
  FILE* out = fdopen(fd, "w");
  make_bounce_body(out, sender, filename, remotes, locals);
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
    die3sys(111, "Can't open or stat info file '", infoname, "'");
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
  if ((morercpthosts_fd = open_file(0, "morercpthosts.cdb")) != -1)
    cdb_init(&morercpthosts, morercpthosts_fd);
}

void load_config(void)
{
  wrap_chdir(control_dir);
  
  me = read_line("me");
  if(!*me)
    die1(111, "Could not read control/me");
  queuelifetime = read_int("queuelifetime", 604800);
  now = time(0);
  lastrun = read_int(run_file, 0);
  
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

void touch_run_file(void)
{
  FILE* out = fopen(run_file, "w");
  if(!out || fprintf(out, "%ld", now) == EOF || fclose(out) == EOF)
    die1(111, "Could not update run file");
}

int cli_main(int argc, char* argv[])
{
  if (opt_bounce_filename != 0) load_bounce_body(opt_bounce_filename);
  load_config();
  scan_queue();
  if(!opt_nosend)
    touch_run_file();
  return 0;
}

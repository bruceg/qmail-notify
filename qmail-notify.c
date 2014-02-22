/* qmail-notify -- Delayed delivery notification for qmail
 * Copyright (C) 2013  Bruce Guenter <bruceg@em.ca>
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
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sysdeps.h>
#include <systime.h>
#include <cdb/cdb.h>
#include <cli/cli.h>
#include <dict/dict.h>
#include <iobuf/iobuf.h>
#include <misc/misc.h>
#include <msg/msg.h>
#include <msg/wrap.h>
#include <str/str.h>

#include "conf_qmail.h"
#include "qmail-notify-cli.h"
#include "qmail-notify.h"

const char program[] = "qmail-notify";

static const time_t default_age = 4*60*60;

static time_t now;
static time_t lastrun;
static pid_t inject_pid;
const char* me = 0;
time_t queuelifetime = 0;
static const char* extra_rcpt = 0;

static const char* qmail_home;
static const time_t* opt_ages = 0;
static unsigned opt_age_count = 0;

static dict rcpthosts;
static struct cdb morercpthosts;
static int morercpthosts_fd;
static str strbuf;

void oom(void) { die1(111, "Out of memory"); }

void parse_age(const char* s, const cli_option* o)
{
  char* end;
  time_t* n;
  if ((n = realloc((char*)opt_ages, (opt_age_count+1) * sizeof *n)) == 0)
    oom();
  n[opt_age_count] = strtoul(s, &end, 0);
  if (*end != 0) die2(111, "Specified age is not a number: ", s);
  ++opt_age_count;
  opt_ages = n;
  (void)o;
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
    if (morercpthosts_fd != -1 &&
	cdb_find(&morercpthosts, strbuf.s, strbuf.len) != 0)
      return 1;
  }
  return 0;
}

int fork_inject(const char* sender)
{
  int p[2];

  debug6(1, "forking ", opt_qmail_inject, " -f '' -a '", sender, "' ", extra_rcpt);

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
    wrap_chdir(qmail_home);
    close(p[1]);
    close(0);
    dup2(p[0], 0);
    close(p[0]);
    execl(opt_qmail_inject, opt_qmail_inject, "-f", "", "-a", sender, extra_rcpt, NULL);
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
		 const char* remotes, const char* locals, time_t age)
{
  int fd = fork_inject(sender);
  make_bounce_body(fd, sender, filename, remotes, locals, age);
  if (close(fd) != 0)
    die1sys(111, "Writing to qmail-inject failed");
  wait_inject();
}

void make_bounce(const char* sender, const char* filename, time_t age)
{
  char* remotes = read_file("remote", filename);
  char* locals = read_file("local", filename);
  unsigned undone = count_undone(remotes) + count_undone(locals);
  debug6(1, "filename=", filename, " sender='", sender, "' undone=", utoa(undone));
  
  if(undone)
    send_bounce(sender, filename, remotes, locals, age);
  free(locals);
  free(remotes);
}

void scan_info(const char* filename)
{
  struct stat statbuf;
  char infoname[100];
  time_t expiry;
  int fd;
  unsigned i;
  strcpy(infoname, "info/");
  strcpy(infoname+5, filename);
  if((fd = open(infoname, O_RDONLY)) == -1 ||
     fstat(fd, &statbuf) == -1) {
    /* This could race with qmail-clean, ignore missing files. */
    if (errno == ENOENT)
      return;
    die3sys(111, "Can't open or stat info file '", infoname, "'");
  }
  /* Handle the file only if it's expiry time (creation time + opt_age)
     is before now and after the last run */
  for (i = 0; i < opt_age_count; ++i) {
    expiry = statbuf.st_mtime + opt_ages[i];
    debug4(1, "filename=", filename, " expiry=", utoa(expiry));
    if(expiry > now)
      debug1(1, "ignoring, has not yet expired");
    else if(expiry <= lastrun) {
      debug1(1, "ignoring, was previously expired");
      break;
    }
    else {
      /* Load the sender address from the info file */
      char* sender = malloc(statbuf.st_size);
      read(fd, sender, statbuf.st_size);
      if(check_rcpt(sender+1))
	make_bounce(sender+1, filename, opt_ages[i]);
      else
	debug2(1, "ignoring, sender was not in rcpthosts: ", sender+1);
      free(sender);
      break;
    }
  }
  close(fd);
}

void scan_dir(const char* dirnum)
{
  DIR* dir;
  direntry* entry;
  char buf1[100];
  strcpy(buf1, "info/");
  strcpy(buf1+5, dirnum);
  if((dir = opendir(buf1)) == 0)
    die1sys(111, "Can't open queue directory");
  while((entry = readdir(dir)) != 0) {
    if(entry->d_name[0] != '.') {
      char filename[100];
      strcpy(filename, dirnum);
      strcat(filename, "/");
      strcat(filename, entry->d_name);
      scan_info(filename);
    }
  }
  closedir(dir);
}

void scan_queue(void)
{
  DIR* dir;
  direntry* entry;
  wrap_chdir(qmail_home);
  wrap_chdir("queue");
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
  unsigned i;

  wrap_chdir(qmail_home);
  wrap_chdir("control");
  
  me = read_line("me");
  if(!*me)
    die1(111, "Could not read control/me");
  queuelifetime = read_int("queuelifetime", 604800);
  now = time(0);
  lastrun = read_int(opt_run_file, 0);
  
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

  debug3(1, "me='", me, "'");
  debug2(1, "queuelifetime=", utoa(queuelifetime));
  debug3(1, "extra_rcpt='", extra_rcpt, "'");
  debug2(1, "now=", utoa(now));
  debug2(1, "lastrun=", utoa(lastrun));
  for (i = 0; i < opt_age_count; ++i)
    debug2(1, "opt_ages[]=", utoa(opt_ages[i]));
}

void touch_run_file(void)
{
  obuf out;
  if (!obuf_open(&out, opt_run_file, OBUF_CREATE|OBUF_TRUNCATE, 0666, 0) ||
      !obuf_putu(&out, now) ||
      !obuf_close(&out))
    die1sys(111, "Could not update run file");
}

static int cmp_age(const void* aptr, const void* bptr)
{
  time_t a = *(time_t*)aptr;
  time_t b = *(time_t*)bptr;
  return b - a;
}

int cli_main(int argc, char* argv[])
{
  if (opt_debug)
    msg_debug_bits |= 0xff;
  if ((qmail_home = getenv("QMAILHOME")) == NULL)
    qmail_home = conf_qmail;
  if (!opt_ages) {
    opt_ages = &default_age;
    opt_age_count = 1;
  }
  else
    /* Sort the ages into descending order */
    qsort((void*)opt_ages, opt_age_count, sizeof *opt_ages, cmp_age);
  if (opt_bounce_filename != 0) load_bounce_body(opt_bounce_filename);
  load_config();
  scan_queue();
  if(!opt_nosend)
    touch_run_file();
  return 0;
  (void)argc;
  (void)argv;
}

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <str/str.h>

#include "qmail-notify.h"

int open_file(const char* prefix, const char* filename)
{
  static str fullname;
  if (!str_truncate(&fullname, 0)) oom();
  if (prefix != 0) {
    if (!str_copys(&fullname, prefix)) oom();
    if (!str_catc(&fullname, '/')) oom();
  }
  if (!str_cats(&fullname, filename)) oom();
  return open(fullname.s, O_RDONLY);
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

char* read_line(const char* filename)
{
  char* data = read_file(0, filename);
  char* nl = strchr(data, '\n');
  if(nl)
    *nl = 0;
  return data;
}

long read_int(const char* filename, long dflt)
{
  char* data = read_line(filename);
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

#include "conf_bin.c"
#include <installer.h>

void insthier(void)
{
  int bin = opendir(conf_bin);
  c(bin, "qmail-notify", -1, -1, 0755);
}

#ifndef QMAIL_NOTIFY__H__
#define QMAIL_NOTIFY__H__

void oom(void);
extern int opt_mime;
extern int opt_msgbytes;
extern time_t queuelifetime;
extern const char* me;

int open_file(const char* prefix, const char* filename);
char* read_file(const char* prefix, const char* filename);
char* read_line(const char* filename);
long read_int(const char* filename, long dflt);

void load_bounce_body(const char* filename);
void make_bounce_body(int fd, const char* sender, const char* filename,
		      const char* remotes, const char* locals, time_t age);

#endif

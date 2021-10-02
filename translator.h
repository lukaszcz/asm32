#ifndef TRANSLATOR_H
#define TRANSLATOR_H

void translator_init();
/* returns nonzero if successful */
int translate(const char *infile, const char *outfile);

#endif /* TRANSLATOR_H */

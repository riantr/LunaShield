#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* C99 sample for the MCIL spike: user input reaches a command sink through a
 * local buffer. A CIL front end should expose the snprintf -> system flow. */
static void run_query(const char *user_id) {
  char cmd[256];
  snprintf(cmd, sizeof(cmd), "SELECT * FROM users WHERE id = %s", user_id);
  system(cmd);
}

int main(int argc, char **argv) {
  if (argc > 1) { run_query(argv[1]); }
  return 0;
}

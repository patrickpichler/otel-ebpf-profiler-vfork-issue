#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

void run();

int main() {
    run();

    return 0;
}

void run() {
    pid_t pid;
    int status;

    printf("Run\n");

    while(true) {
      usleep(1000*100);
      pid = vfork();

      if (pid == -1) {
          perror("vfork failed");
          return;
      } else if (pid == 0) {
          int dev_null = open("/dev/null", O_WRONLY);
          dup2(dev_null, 1);
          close(dev_null);

          execlp("/bin/id", "id", NULL);
      } else {
          waitpid(pid, &status, 0);
          printf("Child process finished.\n");
      }
    }
}

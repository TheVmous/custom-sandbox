#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#define STACK_SIZE 1024*1024

struct childConfig {
    int fd;  //file descriptor: like the handle
    char** argv; //holds the parameters for the application
    int argc; //# of args in argc
};

int child(void* arg) {
    struct childConfig* config = arg;
    if (execve(config->argv[0], config->argv, NULL)) {
        fprintf(stderr, "execve failed!");
        return 1;
    }

    return 0;
}

int main (int argc, char** argv) {
    pid_t childpid;
    struct childConfig config = {0}; //initializes to all fields = 0


    int sockets[2];
    //creates pair of connected unix domain sockets
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {//socket pair returns 0 if success, -1 if error
        perror("socketpair");
        return 1;
    }

    //inputs all necessary stuff into childConfig
    config.fd = sockets[1]; //gives reliable 2-way comms between parent/child
    config.argv = argv + sizeof(char*); //pointer to argv[1]
    config.argc = argc - 1;

    //TODO: so are sockets [0] and [1] like two ends of the comms? why is 0 closed like this?
    //closes socket after child process executes so socket[0] stays in parent process only
    if (fcntl(sockets[0], F_SETFD, FD_CLOEXEC) == -1) {
        perror("fcmtl");
        return 1;
    }

    close(sockets[1]);


    char* stack = malloc(STACK_SIZE);
    if (stack == NULL) {
        return 1;
    }

    if ((childpid = clone(child, stack + STACK_SIZE, SIGCHLD, &config)) == -1) { //clone not a mac syscall
        fprintf(stderr, "clone failed!");
        return  1;
    }
    close(sockets[0]); //closing the last comms between parent and child
    return 0;
}

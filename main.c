#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/capability.h>
#include <string.h>
#include <seccomp.h> //TODO: double check if this is necessary

#define STACK_SIZE 1024*1024
#define USERNS_OFFSET 10000
#define USERNS_COUNT 2000
#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)

struct childConfig {
    int fd;  //file descriptor: like the handle
    char** argv; //holds the parameters for the application
    int argc; //# of args in argc

    /*
     * uid_t is an integer type used specially for user id's (similar to pid_t)
     * But using it for other ints won't cause errors (despite --readability)
    */
    uid_t uid;
    char *hostname; //string for hostname
    char *mountDir; //string for mount directory

};

//configures the name space
int handleChildUIDMap(pid_t childPid, int fd) {
    int uidMap = 0;
    int hasUserNs = -1;

    //checks if all bytes have been read and returns accordingly
    //read() takes bytes read from socket and stores in hasUserNs
    //waits for something to be written in the socket by the child process
    if (read(fd, &hasUserNs, sizeof(hasUserNs)) != sizeof(hasUserNs)) {
        return -1;
    }

    if (hasUserNs) {
        char path[PATH_MAX] = {0}; //size of array = path_max

        /*
         *'file++' is making it move in memory (pointer arithmetic)
         * '*file' derefences it and gives the first character but if first char = 0,
         * 0 is basically false and it evals to false
         * TODO: this for loop is a cool use of pointer arithmetic, look more into this!
        */
        for (char **file = (char *[]) {"uid_map", "gid_map", 0}; *file; file++) {

            /*
             *Snprintf acts like read() here, returning # of bytes produced by "/proc/%d/%s"
             *indicates that the length of the path is longer than the max path!
             *
             *Basically shouldn't happen but this handles it gracefully if somehow it does
             *
             * /proc Stores info on each process, %d indicates pid and the file afterward has more info on the process
             *  like which pids can this process access. so basically saying only these pid's can be accessed.
            */
            if (snprintf(path, sizeof(path), "/proc/%d/%s", childPid, *file) > sizeof(path)) {
                fprintf(stderr, "snprintf too mig? %m\n");
                //%m prints the error nums (set by other code)
                return -1;
            }

            //confirming path
            fprintf(stderr, "writing %s...", path);

            /*
             *O_WRONLY represents 1 (in hexadecimal) here to let open() know to write
             *O_WRONLY is a syscall flag. there's 16 flags
             */
            if ((uidMap = open(path, O_WRONLY)) == -1) {
                fprintf(stderr, "open failed: %m\n");
            }

            //userns_offset and userns_count are linux only
            /*
             *USERNS_OFFSET is the starting # of the PID
             *USERID_COUNT is the # of PIDs so ours will have 2000 process capability
             *  can accept processes w IDs between 10k and 12k.
             * basically telling it, it can only access these processes.
             *
             * restricts the root user on the system to accessing only these NS'
             * restricting the root also restricts the process
             */
            if (dprintf(uidMap, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT) == -1) {
                fprintf(stderr, "dprintf failed: %m\n");
                close(uidMap);
                return -1;
            }
            close(uidMap);
        }
    }

    /*
     * Writes '0' to the file descriptor (which is a socket), indicating
     *      success in setting up in parent.
     * if statement checking if the size of what was written ain't
     * equal to the num of bytes int (how much we told it to write)
     */
    if (write(fd, & (int) {0}, sizeof(int)) != sizeof(int)) {
        fprintf(stderr, "couldn't write: %m\n");
    }
    return 0;
}

int userns(struct childConfig *config)
{
    fprintf(stderr, "=> trying a user namespace...");
    /*
     * unshare syscall creates a namespace
     * CLONE_NEWUSER: a macro that indicates to created isolated set of UIDs for process
     *  i.e making a new root for the process
     *
     *  basically turns off access to all other users for this process,
     *      tricking it into thinking it's the only process here - that it's pid 0 (partially)
     *
*    * unshare and CLONE_NEWUSER are linux only
     */
    int hasUserNs = !unshare(CLONE_NEWUSER);
    // ^ will be != 0 if it has a userns, meaning true for booleans but functions return 0 if they work
    /*
     * Writing to the socket to tell parent that the child process (this) created the namespace successfully
     * This if-statement just reports if there was an error in writing to the parent socket.
     */
    if (write(config->fd, &hasUserNs, sizeof(hasUserNs)) != sizeof(hasUserNs)) {
        fprintf(stderr, "couldn't write: %m\n");
        return -1;
    }

    /*
     * Child process waits to read parent's confirmation signal that uid/gid have been applied to child's /proc files
     * Parent essentially says mappings are set up, child process can now renounce its own root privileges in the
     * namespace to become a normal process in it.
    */
    int result = 0;
    if (read(config->fd, &result, sizeof(result)) != sizeof(result)) {
        fprintf(stderr, "couldn't write: %m\n");
        return -1;
    }

    /*
     * Remember for if statements: 0 -> false, # -> true
     * If the parent reports that the gid/uid stuff hasn't been set up properly, abort plan!
    */
    if (result) return -1;


    if (hasUserNs) {
        fprintf(stderr, "done.\n");
    } else {
        fprintf(stderr, "unsupported? continuing.\n");
        //we can continue because CLONE_NEWUSER is an extra isolation feature, not the only one
        //User Namespaces can also be unavailable or disabled in certain systems
    }

    fprintf(stderr, "=> switching to uid %d / gid %d...", config->uid, config->uid);
    /*
     * setgroups() overwrites the GID list of the process that called it (given proper perms)
     * setresgid() sets the real, effective, and saved-set uid
     *      - real id (RUID) = the user running this process
     *      - effective id (EUID) = informs kernel of this process' perms
     *      - saved id (SUID) = used when process drops perms to act like a normal process
     *
     *      EUID is who're you're pretending to be in a sense while SUID stores your privileges should you drop them and
     *      then decide to get them back later.
     */
    if (setgroups(1, & (gid_t) { config->uid}) ||
        setresgid(config->uid, config->uid) ||
        setresuid(config->uid, config->uid, config->uid)) {

        fprintf(stderr, "%m\n");
        return -1;
    }
    fprintf(stderr, "done.\n");
    return 0;
}

//capabilities

int capabilities() {
    fprintf(stderr, "=> dropping capabilities...");

    /*
     * Auditing: logging system
     * Dropping this so the process can't access info outside the namespace
     *      (audit read/control access info outside the process)
     *      Write is also dropped to prevent writing false logs or DDOS attacks on the OS via write requests
    */
    //TODO: add the rest of the capabilities later
    int dropCaps[] = {
        CAP_AUDIT_CONTROL,
        CAP_AUDIT_READ,
        CAP_AUDIT_WRITE
    };

    /*
     * size_t is what's returned by sizeof, varies based on system (i.e 8 bytes for 64 bit systems)
     *      represents the size of any var.
     * numCaps here gets the size of the array by dividing the overall size of array dividing by size of one element
     *      instead of "sizeof(int" we have *dropCaps so it stays functional regardless of array type
     */
    size_t numCaps = sizeof(dropCaps) / sizeof(*dropCaps);
    fprintf(stderr, "bounding...");

    /*
     * prctl: controls processes/thread like telling it to drop the following capabilities
     *
     */
    for (size_t i = 0; i < num_caps; i++) {
        if (prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0)) {
            fprintf(stderr, "prctl failed: %m\n");
            return 1;
        }

        fprintf(stderr, "inheritable...");

        /*
         * cap_t is a struct storing the state of capabilities and we use it in syscall caps() to get a copy of
         *      the struct for all the caps for the process
         *
         * We then use this info to remove the inherited capabilities that are in the dropCaps[] and
         *      then set the adjusted struct of caps for the process
         */
        cap_t cap = NULL;
        if (!(caps = get_cap_proc())
            || cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEAR)
            || cap_set_proc(caps)) {

            fprintf(stderr, "failed: %m\n");

            if (caps) cap_free(caps); //checks if caps != null (aka #) and then will run cap_free()
            return 1;
            }

        /*
         * cap_free doesn't check for null, trusting the coder and also making it faster
         * If you call free twice, it causes an double-free error/null pointer exception
         * cap_free frees up the resources (allocated memory) for the cap struct
         */
        cap_free(caps);
        fprintf(stderr, "done.\n");
        return 0;
    }
}

//Just wrapping the sys call to swap the mount at '/' with a different one.
int pivotRoot(const char *newRoot, const char *putOld) {
    return syscall(SYS_pivot_root, newRoot, putOld);
}

/*
 * Mounting
 */
int mounts(struct childConfig *config) {
    fprintf(stderr, "=> remounting everything with MS_PRIVATE...");
    //we do this to make bind mount invisible outside of namespace:

    /*
     * Bind Mounting: making a certain directory accessible from another point/location
     *  & MS_REC makes it recursive, thus allowing access to the entire directory and subdirs too, incl their mounts
     *  Hence the connection is more faithful.
     *  (mounting in general is just kinda making the dir-usually from a storage device like usb-visible elsewhere
     *      while bind mounting is assigning a second path).
     *
     * We use MS_PRIVATE to prevent these bind mounts from showing up on the Host's system and confusing it.
     *  thus, any mounts added/removed in namespace ain't reflected in host.
     *  Reflection would be bad if say we deleted all files in our sandbox. Also, if our container dies, it would leave
     *      ghost mounts to which nothing is connected.
     *
     * How this makes us secure:
     *  Malware can spam mounting to DDOS or erase important things within the container to mirror it in host
     *  Malware can also inject new directories into host system and make them look normal.
     */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE NULL)) {
        fprintf(stderr, "failed! %m\n");
        return -1;
    }
    fprintf(stderr, "remounted.\n");

    /*
     * we do a lil switcheroo wiht the root of the host and the actual target location so we make
     *  the container think the target is its root.
     *
     * pivotRoot() needs this set up
     */
    fprintf(stderr, "=> making a temp directory and a bind mount there...");
    char mountDir[] = "/tmp/tmp.XXXXXX";
    if (!mkdtemp(mountDir)) {
        fprintf(stderr, "failed making a directory!\n");
        return -1;
    }

    if (mount(config->mountDir, mountDir, NULL, MS_BIND | MS_PRIVATE, NULL)) {
        fprintf(stderr, "bind mount failed!\n");
        return -1;
    }

    char innerMountDir[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
    /*
     * memcpy used to copy bytes of memory from one address to another.
     * sizeof(mountDir) - 1 to avoid the null terminator (/0) at the end of mountDir
     *  (all char[]s init as string have Null Terminators and are known as C-Strings)
     *  so that innerMountDir isn't cut off early by memcpy bc it will be longer than mountDir.
     *
     * creating the connection here.
    */
    memcpy(innerMountDir, mountDir, sizeof(mountDir) - 1);
    if (!mkdtemp(innerMountDir)) {
        fprintf(stderr, "failed making the inner directory!\n");
        return -1;
    }
    fprintf(stderr, "done.\n");

    //inverting the pov here
    fprintf(stderr, "=> pivoting root...");
    if (pivot_root(mountDir, innerMountDir)) {
        fprintf(stderr, "failed!\n");
        return -1;
    }
    fprintf(stderr, "done.\n");

    /*
     * basename() returns the string component after the final '/' in a path that is ended by null terminator
     */
    char *oldRootDir = basename(innerMountDir);
    char oldRoot[sizeof(innerMountDir) + 1] = {"/"}; //initializes the list with 1st element being '/'
    strcpy(&oldRoot[1], oldRootDir); //copies "/" from oldRoot to oldRootDir, labelling the dir in innerMountDir '/'

    fprintf(stderr, "=> unmounting %s...", oldRoot);
    if (chdir("/")) {
        fprintf(stderr, "chdir! %m\n");
        return -1;
    }

    /*
     * Because of MNT_DETACH, it lazily unmounts (cutting off sandbox from host syst)
     * Lazy unmounting is when the mount is immediately turned unavailable for new access but actual unmounting is
     *  delayed til mount is free (old accesses stop using it).
    */
    if (umount2(oldRoot, MNT_DETACH)) {
        fprintf(stderr, "umount failed! %m\n");
        return -1;
    }
    if (rmdir(oldRoot)) { //removing the empty directory where the mount to host used to be
        fprintf(stderr, "rmdir failed! %m\n");
        return -1;
    }

    fprintf(stderr, "done.\n");
    return 0;

}

//blacklisting syscalls now!
int syscalls() {
    scmp_filter_ctx ctx = NULL;
    /*
     * A seccomp filter dictates which syscalls should be filtered and how to handle these forbidden syscalls
     *
     * SCMP_SYS() is a macro used to find a syscall number by its name.
     *
     * TODO: add a lot more syscalls to this filter
    */
    fprintf(stderr, "=> filtering syscalls...");
    if (!(ctx = seccomp_init(SCMP_ACT_ALLOW)) //tells seccomp filter to do nothing if syscall !affects seccomp filter rules
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
            SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) //filtering using chmod to set user perms bit
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS)
        || seccomp_load(ctx)) {

        if (ctx) seccomp_release(ctx); //if ctx is initialized successfully, clean up its resources
        fprintf(stderr, "failed: %m\n");
        return 1;
    }
    seccomp_release(ctx);
    fprintfO(stderr, "done.\n");
    return 0;
}


int child(void* arg) {
    struct childConfig* config = arg;

    if (sethostname(config->hostname, strlen(config->hostname))
        || mounts(config)
        || userns(config)
        || capabilities()
        || syscalls()) {

        close(config->fd); //closing the socket (basically referring to fd in config
        return 1;
    }

    if (close(config->fd)) {
        fprintf(stderr, "close failed: %m\n");
        return -1;
    }

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

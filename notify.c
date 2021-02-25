#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <dirent.h>
#include <mntent.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/fanotify.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <poll.h>

static volatile int running = 1;
static volatile int signaled = 0;

static const char* mask2str(uint64_t mask)
{
    static char buffer[10];
    int offset = 0;

    if (mask & FAN_ACCESS)
        buffer[offset++] = 'R';
    if (mask & FAN_ONDIR)
        buffer[offset++] = 'D';
    if (mask & FAN_OPEN)
        buffer[offset++] = 'O';
    if (mask & FAN_OPEN_PERM)
        buffer[offset++] = 'P';
    if (mask & FAN_CLOSE_WRITE || mask & FAN_CLOSE_NOWRITE)
        buffer[offset++] = 'C';
    if (mask & FAN_MODIFY || mask & FAN_CLOSE_WRITE)
        buffer[offset++] = 'W';
    buffer[offset] = '\0';

    return buffer;
}



static void print_event(const struct fanotify_event_metadata *data, char pathname[], size_t buflen)
{
    int fd;
    ssize_t len;
    static char printbuf[100];
    static char procname[100];
    static char syscall[100];
    struct stat st;

    /* read process name */
    snprintf (printbuf, sizeof (printbuf), "/proc/%i/comm", data->pid);
    len = 0;
    fd = open (printbuf, O_RDONLY);
    if (fd >= 0) {
        len = read (fd, procname, sizeof (procname));
        while (len > 0 && procname[len-1] == '\n') {
            len--;
        }
    }
    if (len > 0) {
        procname[len] = '\0';
    } else {
        strcpy (procname, "unknown");
    }
    if (fd >= 0)
        close (fd);

    snprintf (printbuf, sizeof (printbuf), "/proc/%i/syscall", data->pid);
    len = 0;
    fd = open (printbuf, O_RDONLY);
    if (fd >= 0) {
        len = read (fd, syscall, 30);
        close (fd);
    }
    else {
	    strcpy(syscall, "none");
    }

    if (syscall[0] == 'r')
	    strcpy(syscall, "RU ");
    else {
	    int i;
	    for (i=0; syscall[i] != 0 && syscall[i] != ' '; i++);
	    syscall[i] = 0;
    }

    /* try to figure out the path name */
    snprintf (printbuf, sizeof (printbuf), "/proc/self/fd/%i", data->fd);
    len = readlink (printbuf, pathname, buflen);
    if (len < 0) {
        /* fall back to the device/inode */
        if (fstat (data->fd, &st) < 0) {
            perror ("stat");
            exit (1);
        }
        snprintf (pathname, buflen, "device %i:%i inode %ld\n",
                major (st.st_dev), minor (st.st_dev), st.st_ino);
    } else {
        pathname[len] = '\0';
    }

    printf ("%15s(%i)\t%s\t%s\t%s\n", procname, data->pid, mask2str(data->mask), syscall, pathname);
}

static void setup_fanotify(int fan_fd)
{
    int res;

    int famask = FAN_OPEN_PERM| FAN_MARK_MOUNT;

    res = fanotify_mark (fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, famask, AT_FDCWD, ".");
    //res = fanotify_mark (fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, famask, AT_FDCWD, "/proc");
    if (res < 0) {
        perror("fanotify_mark");
        exit (1);
    }


}

static void signal_handler (int signal)
{
    (void)signal;

    running = 0;
    signaled++;

    if (signaled > 1)
        _exit(1);
}

int main (int argc, char** argv)
{
    int fan_fd;
    int res;
    int err;
    void *buffer;
    struct fanotify_event_metadata *data;
    struct sigaction sa;
    struct pollfd pollfds[1];
    static int pollevents = POLLIN | POLLPRI | POLLERR | POLLHUP;

    fan_fd = fanotify_init (FAN_CLASS_CONTENT, O_RDONLY);
    if (fan_fd < 0) {
        err = errno;
        perror("fanotify_init");
        exit(1);
    }

    setup_fanotify (fan_fd);

    /* allocate memory for fanotify */
    buffer = NULL;
    err = posix_memalign (&buffer, 4096, 4096);
    if (err != 0 || buffer == NULL) {
        perror("posix_memalign");
        exit(1);
    }


    sa.sa_handler = signal_handler;
    sigemptyset (&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction (SIGINT, &sa, NULL) < 0) {
        perror ("sigaction");
        exit (1);
    }


    fcntl(0, F_SETFL, O_NONBLOCK);
    fcntl(fan_fd, F_SETFL, O_NONBLOCK);

    pollfds[0].fd = fan_fd;
    pollfds[0].events = pollevents;

    while (running) {
        int nready = poll (pollfds, 1, -1);
        if (nready == -1 && (errno == EINTR || errno == EAGAIN))
		continue;

        if (!pollfds[0].revents) {
            continue;
        }

        res = read (fan_fd, buffer, 4096);
        if (res == 0) {
            fprintf (stderr, "No more event\n");
            break;
        }
        if (res < 0) {
            if (errno == EINTR)
                continue;
            perror ("read");
            exit(1);
        }

        data = (struct fanotify_event_metadata *) buffer;
        while (FAN_EVENT_OK (data, res)) {
            char filepath[PATH_MAX];
            if (data->pid == getpid())
		    goto next;
            if (data->mask & FAN_OPEN_PERM) {
                struct fanotify_response resp = { data->fd };
		resp.response = FAN_ALLOW;
		usleep(10000);
		print_event (data, filepath, sizeof filepath);

                write(fan_fd, &resp, sizeof resp);
            }
	    //else if (data->mask & FAN_OPEN) {
	    //    print_event (data, filepath, sizeof filepath);
	    //}

next:
            close (data->fd);
            data = FAN_EVENT_NEXT (data, res);
        }
    }

    return 0;
}

#include <fcntl.h>
#include <libowfat/buffer.h>
#include <libowfat/fmt.h>
#include <libowfat/scan.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* 
 * the following constants control the behavior of kill_pid() - they serve as second argument
 * after we send SIGTERM to a process, we wait some time before sending SIGKILL
 * the supervisor will wait KILL_TIMEOUT_CHILD seconds for the child to die after SIGTERM
 * the main loop will wait KILL_TIMEOUT_SUPERVISOR seconds for the supervisor to die after SIGTERM 
 * if we have 0 here, we won't send SIGKILL at all (not recommended for KILL_TIMEOUT_CHILD)
 */
#define KILL_TIMEOUT_SUPERVISOR 0 /* the supervisor catches SIGTERM and invokes kill_pid() on its own, so setting null here should be safe */
#define KILL_TIMEOUT_CHILD 3

/* the global struct which holds the minicron config */
static struct minicron_config{
	char *childpidfile;
	char *daemonpidfile;
	unsigned int kill_after;
	unsigned int interval;
	unsigned short daemon;
	unsigned short syslog;
	char *child;
	char **argv; /* terminated with null pointer */
} config;

/* the state struct holds a few global variables, which we can't or don't want to pass as arguments */
struct minicron_state{
	pid_t pid_child;
	pid_t pid_supervisor;
} state;

void usage(char *);
int parse_args(int, char**);
void kill_pid(pid_t, unsigned int);
void daemonize();
void mainloop_sigtermhandler();
int mainloop();
void supervisor_sigchldhandler();
void supervisor_sigtermhandler();
void createpid(char*, pid_t);
void deletepid(char*);
int supervisor();
int child();

extern char **environ;

int main(int argc, char **argv) {
	int retval;
	
	if ((retval = parse_args(argc, argv))) {
		usage(argv[0]);
		return retval;
	}
	
	if (config.syslog) {
		openlog("minicron", LOG_PID, LOG_CRON);
		syslog(LOG_NOTICE, "Started the daemon. Running %s every %d seconds.", config.child, config.interval);
	}
	
	if (config.daemon)
		daemonize();
	
	mainloop();
	
	/* unreachable */
	return 0;
}

void usage(char *progname) {
	buffer_puts(buffer_2, "usage: ");
	buffer_puts(buffer_2, progname);
	buffer_puts(buffer_2, "[-p<pidfile>] [-P<pidfile>] [-k<N>] [-d] [-s] nseconds child [arguments...]\n\
Runs the child with the specified arguments every nseconds.\n\
The following options are available:\n\
-p<pidfile> - save the child PID in pidfile\n\
-P<pidfile> - save the daemon PID in pidfile\n\
-k<N> - kill the child after N seconds\n\
-d - daemonize after starting\n\
-s - send messages to syslog\n");
	buffer_flush(buffer_2);
}

int parse_args(int argc, char **argv) {
	int i;
	if (argc < 3)
		return 11;
		
	i = 1;
	while (argv[i][0] == '-') {
		argv[i]++;
		switch (argv[i][0]) {
			case 'p':
				argv[i]++;
				config.childpidfile = argv[i];
				break;
			case 'P':
				argv[i]++;
				config.daemonpidfile = argv[i];
				break;
			case 'k':
				argv[i]++;
				scan_uint(argv[i], &config.kill_after);
				break;
			case 'd':
				config.daemon = 1;
				break;
			case 's':
				config.syslog = 1;
				break;
			default:
				return 12;
		}
		i++;
	}
	
	scan_uint(argv[i], &config.interval);
	i++;
	
	config.child = argv[i];
	
	/* 
	   the remaining arguments will later be passed to the child
	   note that config.argv[0] should be equal to config.child prior to execve(2), according to POSIX
	   that's why we don't increment the index after the last operation 
	*/
	if (argv[i] != NULL)
		config.argv = &argv[i];
	
	return 0;
}

void kill_pid(pid_t pid, unsigned int timeout) {
	int state = 0, waitpid_r = 0;
	
	waitpid_r = waitpid(pid, &state, WNOHANG); /* check the child state */
	
	if (!(WIFEXITED(state) || WIFSIGNALED(state)) || waitpid_r==0) { /* the child has not exited yet */
		if (config.syslog) syslog(LOG_NOTICE, "Sending SIGTERM to PID %d.", pid);
		kill(pid, SIGTERM); /* sending SIGTERM to child */
	}
	else 
		return;
	
	if (timeout>0) {
	/* the child may ignore the SIGTERM, so we wait and check again */
		waitpid_r = waitpid(pid, &state, WNOHANG);
		if (!(WIFEXITED(state) || WIFSIGNALED(state)) || waitpid_r==0) /* check again before sleeping, in order to avoid useless blocking */
			sleep(timeout); 
		else 
			return;

		waitpid_r = waitpid(pid, &state, WNOHANG);
	
		if (!(WIFEXITED(state) || WIFSIGNALED(state)) || waitpid_r==0) {
			if (config.syslog) syslog(LOG_NOTICE, "Sending SIGKILL to PID %d.", pid);
			kill(pid, SIGKILL); /* finally send SIGKILL */
		}
		else
			return;
	} else /* timeout == 0, wait the process to die */
		waitpid(pid, &state, 0);
}

void daemonize() {
	pid_t pid; int fd;
	
	if (getppid()==1) return; /* already daemonized */
	
	umask(027); /* set a restrictive umask */
		
	pid = fork();
	if (pid<0) exit(-1); /* fork error */
	else if (pid>0) exit(0); /* the parent should exit */
	
	setsid(); /* create a new session */
	
	/* ignoring the tty signals */
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	
	/* we don't need SIGCHLD yet */
	signal(SIGCHLD, SIG_IGN);
		
	/* close all fds */
	for (fd=0; fd<getdtablesize(); fd++)
		close(fd);
		
	/* reopen the basic fds and redirect them to /dev/null */
	fd = open("/dev/null", O_RDWR);
	dup2(fd, STDIN_FILENO);
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);
}

void mainloop_sigtermhandler() {
	kill_pid(state.pid_supervisor, KILL_TIMEOUT_SUPERVISOR);
	deletepid(config.daemonpidfile);
	if(config.syslog) {
		syslog(LOG_NOTICE, "Stopping after receiving SIGTERM.");
		closelog();
	}
	exit(1);
}

int mainloop() {
	createpid(config.daemonpidfile, getpid());
	
	signal(SIGTERM, mainloop_sigtermhandler);
	signal(SIGINT, SIG_IGN); /* ignoring SIGINT */
	
	while (1) {
		state.pid_supervisor = fork();
		if (state.pid_supervisor < 0) /* fork failed */
			continue;
		else if (state.pid_supervisor == 0)
			supervisor();

		sleep(config.interval);
		
		kill_pid(state.pid_supervisor, KILL_TIMEOUT_SUPERVISOR);
	}
}

void supervisor_sigchldhandler() {
	if (config.syslog) syslog(LOG_NOTICE, "The child %s (PID %d) has ended.", config.child, state.pid_child);
	deletepid(config.childpidfile);
	_exit(0);
}

void supervisor_sigtermhandler() {
	kill_pid(state.pid_child, KILL_TIMEOUT_CHILD);
	if (config.syslog) syslog(LOG_NOTICE, "The child %s (PID %d) has ended.", config.child, state.pid_child);
	deletepid(config.childpidfile);
	_exit(1);
}

void createpid(char *pidfile, pid_t pid) {
	char *p, *buf;
	int fd;
	if (pidfile == NULL)
		return;
		
	/* check if the pidfile already exists, try to delete it and return on failure */
	if (!access(pidfile, F_OK))
		if (unlink(pidfile))
			return;
			
	p = buf = malloc(sizeof(char) * 8);
	p += fmt_uint(p, pid);
	p += fmt_str(p, "\n\0");
	
	fd = creat(pidfile, S_IRUSR); 
	
	write(fd, buf, strlen(buf));
	
	close(fd);
	
	free(buf);
}

void deletepid(char *pidfile) {
	if (pidfile == NULL)
		return;
	unlink(pidfile);
}

int supervisor() {
	signal(SIGTERM, supervisor_sigtermhandler); /* catch SIGTERM from the parent, if the interval has passed */
	signal(SIGCHLD, supervisor_sigchldhandler); /* catch SIGCHLD in order to _exit(2) immediately after the child returns */
	
	state.pid_child = vfork();
	if (state.pid_child < 0) /* fork failed */
		_exit(-1);
	else if (state.pid_child == 0)
		child();
		
	createpid(config.childpidfile, state.pid_child);
	// atexit(deletepid); /* won't work if the supervisor is killed by a signal! */
		
	if (config.syslog) {
		if (config.kill_after) {
			if (config.syslog) syslog(LOG_NOTICE, "Started %s (PID %d). Will wait %d seconds before killing it.", config.child, state.pid_child, config.kill_after);
		}
		else {
			if (config.syslog) syslog(LOG_NOTICE, "Started %s (PID %d).", config.child, state.pid_child, config.kill_after);
		}
	}
	
	if (config.kill_after) {
		sleep(config.kill_after);
		kill_pid(state.pid_child, KILL_TIMEOUT_CHILD);
	} else
		wait(0);
	
	if (config.syslog) syslog(LOG_NOTICE, "The child %s (PID %d) has ended.", config.child, state.pid_child);
	deletepid(config.childpidfile);
		
	_exit(0);
}

int child() {
	execve(config.child, config.argv, environ);
	/* execve(2) returns only on error, so if we reached this point, something is not OK */
	_exit(-1); 
}

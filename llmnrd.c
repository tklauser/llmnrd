/*
 * llmnrd -- LLMNR (RFC 4705) responder daemon.
 *
 * Copyright (C) 2014-2017 Tobias Klauser <tklauser@distanz.ch>
 *
 * This file is part of llmnrd.
 *
 * llmnrd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * llmnrd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with llmnrd.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/param.h>

#include "compiler.h"
#include "log.h"
#include "util.h"

#include "iface.h"
#include "llmnr.h"
#include "llmnr-packet.h"
#include "socket.h"

static bool llmnrd_running = true;
static int llmnrd_sock_ipv4 = -1;
static int llmnrd_sock_ipv6 = -1;

static const char *short_opts = "H:i:p:6dshV";
static const struct option long_opts[] = {
	{ "hostname",	required_argument,	NULL, 'H' },
	{ "interface",  required_argument,	NULL, 'i' },
	{ "port",	required_argument,	NULL, 'p' },
	{ "ipv6",	no_argument,		NULL, '6' },
	{ "daemonize",	no_argument,		NULL, 'd' },
	{ "syslog",	no_argument,		NULL, 's' },
	{ "help",	no_argument,		NULL, 'h' },
	{ "version",	no_argument,		NULL, 'V' },
	{ NULL,		0,			NULL, 0 },
};

static void __noreturn usage_and_exit(int status)
{
	fprintf(stdout, "Usage: llmnrd [OPTIONS]\n"
			"Options:\n"
			"  -H, --hostname NAME  set hostname to respond with (default: system hostname)\n"
			"  -i, --interface DEV  bind socket to a specific interface, e.g. eth0\n"
			"  -p, --port NUM       set port number to listen on (default: %d)\n"
			"  -6, --ipv6           enable LLMNR name resolution over IPv6\n"
			"  -d, --daemonize      run as daemon in the background\n"
			"  -s, --syslog         send all log output to syslog\n"
			"  -h, --help           show this help and exit\n"
			"  -V, --version        show version information and exit\n",
			LLMNR_UDP_PORT);
	exit(status);
}

static void __noreturn version_and_exit(void)
{
	fprintf(stdout, "llmnrd %s %s\n"
			"Copyright (C) 2014-2017 Tobias Klauser <tklauser@distanz.ch>\n"
			"Licensed under the GNU General Public License, version 2\n",
			VERSION_STRING, GIT_VERSION);
	exit(EXIT_SUCCESS);
}

static void signal_handler(int sig)
{
	switch (sig) {
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		llmnrd_running = false;
		break;
	case SIGHUP:
	default:
		/* ignore */
		break;
	}
}

static void register_signal(int sig, void (*handler)(int))
{
	sigset_t block_mask;
	struct sigaction saction;

	sigfillset(&block_mask);

	saction.sa_handler = handler;
	saction.sa_mask = block_mask;
	saction.sa_flags = SA_RESTART;

	if (sigaction(sig, &saction, NULL) != 0) {
		log_err("Failed to register signal handler for %s (%d)\n",
			strsignal(sig), sig);
	}
}

static void iface_event_handle(enum iface_event_type type, unsigned char af,
			       unsigned int ifindex)
{
	switch (af) {
	case AF_INET:
		socket_mcast_group_ipv4(llmnrd_sock_ipv4, ifindex, type == IFACE_ADD);
		break;
	case AF_INET6:
		socket_mcast_group_ipv6(llmnrd_sock_ipv6, ifindex, type == IFACE_ADD);
		break;
	default:
		/* ignore */
		break;
	}
}

static void hostname_change_handle(char *hostname, size_t maxlen)
{
	char *newname;

	newname = xzalloc(maxlen);
	if (gethostname(newname, maxlen) == 0) {
		newname[maxlen - 1] = '\0';
		if (strncmp(hostname, newname, maxlen) != 0) {
			log_info("Hostname changed to %s\n", newname);
			strncpy(hostname, newname, maxlen);
			llmnr_set_hostname(hostname);
		}
	}
	free(newname);
}

static bool write_pid_file(void)
{
	int fd;
	char buf[64];
	ssize_t len;

	fd = open(PIDFILE, O_CREAT|O_EXCL|O_RDWR, 0644);
	if (fd == -1) {
		log_err("Failed to open pid file %s: %s", PIDFILE, strerror(errno));
		return false;
	}

	if (snprintf(buf, sizeof(buf), "%ji\n", (intmax_t) getpid()) < 0)
		goto err;

	len = strlen(buf);
	if (write(fd, buf, len) != len)
		goto err;

	close(fd);
	return true;

err:
	log_err("Failed to write pid to %s", PIDFILE);
	if (fd != -1) {
		unlink(PIDFILE);
		close(fd);
	}
	return false;
}

int main(int argc, char **argv)
{
	int c, ret = -1;
	long num_arg;
	bool daemonize = false, ipv6 = false;
	char *hostname = NULL;
	char *iface = NULL;
	uint16_t port = LLMNR_UDP_PORT;
	int llmnrd_sock_rtnl = -1;
	int llmnrd_fd_hostname = -1;
	bool rm_pid_file = false;
	int nfds;

	setlinebuf(stdout);

	while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
		switch (c) {
		case 'd':
			daemonize = true;
			break;
		case 's':
			openlog("llmnrd", LOG_PID, LOG_DAEMON);
			log_to_syslog();
			break;
		case 'H':
			hostname = xstrdup(optarg);
			break;
		case 'i':
			iface = xstrdup(optarg);
			break;
		case 'p':
			num_arg = strtol(optarg, NULL, 0);
			if (num_arg < 0 || num_arg > UINT16_MAX) {
				log_err("Invalid port number: %ld\n", num_arg);
				return EXIT_FAILURE;
			}
			port = num_arg;
			break;
		case '6':
			ipv6 = true;
			break;
		case 'V':
			version_and_exit();
		case 'h':
			usage_and_exit(EXIT_SUCCESS);
		default:
			usage_and_exit(EXIT_FAILURE);
		}
	}

	register_signal(SIGINT, signal_handler);
	register_signal(SIGQUIT, signal_handler);
	register_signal(SIGTERM, signal_handler);
	register_signal(SIGHUP, signal_handler);

	if (!hostname) {
		hostname = xzalloc(MAXHOSTNAMELEN);
		if (gethostname(hostname, MAXHOSTNAMELEN) != 0) {
			log_err("Failed to get hostname");
			return EXIT_FAILURE;
		}
		hostname[MAXHOSTNAMELEN - 1] = '\0';

		llmnrd_fd_hostname = open("/proc/sys/kernel/hostname", O_RDONLY|O_CLOEXEC|O_NDELAY);
	}

	if (daemonize) {
		if (daemon(0, 0) != 0) {
			log_err("Failed to daemonize process: %s\n", strerror(errno));
			goto out;
		}
		if (!write_pid_file())
			goto out;
		rm_pid_file = true;
	}

	log_info("Starting llmnrd on port %u, hostname %s\n", port, hostname);
	if (iface)
		log_info("Binding to interface %s\n", iface);

	llmnrd_sock_ipv4 = socket_open_ipv4(port, iface);
	if (llmnrd_sock_ipv4 < 0)
		goto out;

	if (ipv6) {
		llmnrd_sock_ipv6 = socket_open_ipv6(port, iface);
		if (llmnrd_sock_ipv6 < 0)
			goto out;
	}

	llmnrd_sock_rtnl = socket_open_rtnl(ipv6);
	if (llmnrd_sock_rtnl < 0)
		goto out;

	llmnr_init(hostname, ipv6);

	ret = iface_init(llmnrd_sock_rtnl, iface, ipv6, &iface_event_handle);
	if (ret < 0)
		goto out;

	nfds = max(llmnrd_sock_ipv4, llmnrd_sock_rtnl);
	if (llmnrd_sock_ipv6 >= 0)
		nfds = max(nfds, llmnrd_sock_ipv6);
	if (llmnrd_fd_hostname >= 0)
		nfds = max(nfds, llmnrd_fd_hostname);
	nfds += 1;

	while (llmnrd_running) {
		fd_set rfds, efds;

		FD_ZERO(&rfds);
		FD_SET(llmnrd_sock_ipv4, &rfds);
		FD_SET(llmnrd_sock_rtnl, &rfds);
		if (llmnrd_sock_ipv6 >= 0)
			FD_SET(llmnrd_sock_ipv6, &rfds);

		FD_ZERO(&efds);
		if (llmnrd_fd_hostname >= 0)
			FD_SET(llmnrd_fd_hostname, &efds);

		ret = select(nfds, &rfds, NULL, &efds, NULL);
		if (ret < 0) {
			if (errno != EINTR) {
				log_err("Failed to select() on socket: %s\n", strerror(errno));
				goto out;
			}
		} else if (ret) {
			/* handle RTNL messages first so we can respond with
			 * up-to-date information.
			 */
			if (FD_ISSET(llmnrd_sock_rtnl, &rfds))
				iface_recv(llmnrd_sock_rtnl);
			if (FD_ISSET(llmnrd_sock_ipv4, &rfds))
				llmnr_recv(llmnrd_sock_ipv4);
			if (llmnrd_sock_ipv6 >= 0 && FD_ISSET(llmnrd_sock_ipv6, &rfds))
				llmnr_recv(llmnrd_sock_ipv6);
			if (llmnrd_fd_hostname >= 0 && FD_ISSET(llmnrd_fd_hostname, &efds))
				hostname_change_handle(hostname, MAXHOSTNAMELEN);
		}
	}

	log_info("Signal received. Stopping llmnrd.\n");

	ret = 0;
out:
	if (llmnrd_sock_rtnl >= 0)
		close(llmnrd_sock_rtnl);
	if (llmnrd_sock_ipv6 >= 0)
		close(llmnrd_sock_ipv6);
	if (llmnrd_sock_ipv4 >= 0)
		close(llmnrd_sock_ipv4);
	free(hostname);
	if (rm_pid_file)
		unlink(PIDFILE);
	return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

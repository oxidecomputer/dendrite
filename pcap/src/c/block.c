#define _GNU_SOURCE
#include <poll.h>
#include <stdio.h>
#include <errno.h>

#include "block.h"

int
block_on(int fd, int delay, int total) {
	struct pollfd pfd;

	if (fd < 0) {
		return (EINVAL);
	}

	pfd.fd = fd;
	pfd.events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
	pfd.revents = 0;

	while (total > 0) {
		if (poll(&pfd, 1, delay) != 0) {
			return 0;
		}
		total -= delay;
	}

	return (0);
}

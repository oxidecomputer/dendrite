#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/types.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/stropts.h>

#define MAXNAME 32
#define IPV6_SZ 16
#define IPV4_SZ 4

#define IOC 0x1de11001

static int tfport_fd = -1;
static int inet_fd = -1;

typedef struct tfport_ioc_l2 {
	struct sockaddr_storage	til_addr;
	uint_t			til_ifindex;
} tfport_ioc_l2_t;

static int
trigger_request(tfport_ioc_l2_t *ioc)
{
	struct strioctl crioc;

	crioc.ic_cmd = IOC;
	crioc.ic_timout = -1;
	crioc.ic_len = sizeof (*ioc);
	crioc.ic_dp = (char *)ioc;
	if (ioctl(tfport_fd, I_STR, &crioc) != 0)
		return -1;

	return 0;
}

int
trigger_ndp(uint32_t ifindex, uint8_t addr[IPV6_SZ])
{
	tfport_ioc_l2_t ioc;
	struct sockaddr *sock = (struct sockaddr *)&ioc.til_addr;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sock;

	sin6->sin6_family = AF_INET6;
	bcopy(addr, &sin6->sin6_addr, IPV6_SZ);
	ioc.til_ifindex = ifindex;

	return (trigger_request(&ioc));
}

int
trigger_arp(uint32_t ifindex, uint8_t addr[IPV4_SZ])
{
	tfport_ioc_l2_t ioc;
	struct sockaddr *sock = (struct sockaddr *)&ioc.til_addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)sock;

	sin->sin_family = AF_INET;
	bcopy(addr, &sin->sin_addr, IPV4_SZ);
	ioc.til_ifindex = ifindex;

	return (trigger_request(&ioc));
}

static int
count_interfaces()
{
	struct lifnum ln;

	bzero(&ln, sizeof (ln));

	ln.lifn_family = AF_INET6;
	if (ioctl(inet_fd, SIOCGLIFNUM, &ln) != 0) {
		perror("failed to get interface count");
		return -1;
	}

	return ln.lifn_count;

}

int
link_local_get(char *ifname, uint8_t ifaddr[IPV6_SZ])
{
	struct lifconf lc;
	int total;
	int rval = -1;

	if ((total = count_interfaces()) < 0)
		goto done;

	/* Fetch the config info for all interfaces from the kernel */
	bzero(&lc, sizeof (lc));
	lc.lifc_family = AF_INET6;
	lc.lifc_len = total * sizeof(struct lifreq);
	lc.lifc_buf = malloc(lc.lifc_len);
	if (lc.lifc_buf == NULL) {
		perror("out of memory");
		goto done;
	}
	if (ioctl(inet_fd, SIOCGLIFCONF, &lc) != 0) {
		perror("failed to get interface info");
		goto done;
	}

	/* Iterate over the config data counting link-local addresses */
	total = lc.lifc_len / sizeof(struct lifreq);
	for (int i = 0; i < total; i++) {
		struct lifreq *p = &lc.lifc_req[i];
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&p->lifr_addr;
		struct in6_addr *addr = &sin6->sin6_addr;

		if ((strcmp(p->lifr_name, ifname) == 0) &&
		    IN6_IS_ADDR_LINKLOCAL(addr)) {
			bcopy(addr, ifaddr, IPV6_SZ);
			rval = 0;
			break;
		}
	}

done:
	if (lc.lifc_buf != NULL)
		free(lc.lifc_buf);

	return (rval);
}

int
ifindex_get(char *ifname)
{
	struct lifreq lf;

	bzero(&lf, sizeof (lf));
	strncpy(lf.lifr_name, ifname, LIFNAMSIZ - 1);
	if (ioctl(inet_fd, SIOCGLIFINDEX, &lf) != 0) {
		fprintf(stderr, "index ioctl failed for %s: %s\n",
		    ifname, strerror(errno));
		return -1;
	}

	return lf.lifr_index;
}

void
netsupport_fini() {
	if (inet_fd >= 0)
		close(inet_fd);
	if (tfport_fd >= 0)
		close(tfport_fd);
}

int
netsupport_init() {
	if ((inet_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		perror("failed to open PF_INET");
		return -1;
	}

	tfport_fd = open("/dev/net/tfport0", O_RDWR);
	if (tfport_fd < 0) {
		perror("failed to open /dev/net/tfport0");
		return -1;
	}

	return 0;
}

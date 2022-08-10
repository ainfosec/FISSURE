// Taken from the gssm project (http://www.thre.at/gsm)
// Any license you like

#include "tun.h"

int mktun(const char *chan_name, unsigned char *ether_addr) {

	struct ifreq ifr;
	// struct ifreq ifw;
	char if_name[IFNAMSIZ];
	int fd, one = 1;
	// int sd;

	// construct TUN interface
	if((fd = open("/dev/net/tun", O_RDWR)) == -1) {
		perror("open");
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", chan_name);
	if(ioctl(fd, TUNSETIFF, (void *)&ifr) == -1) {
		perror("TUNSETIFF");
		close(fd);
		return -1;
	}

	// save actual name
	memcpy(if_name, ifr.ifr_name, IFNAMSIZ);

	// get ether addr
	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, if_name, IFNAMSIZ);
	if(ioctl(fd, SIOCGIFHWADDR, (void *)&ifr) == -1) {
		perror("SIOCGIFHWADDR");
		close(fd);
		return -1;
	}
	memcpy(ether_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	// set persistent
	if(ioctl(fd, TUNSETPERSIST, (void *)&one) == -1) {
		perror("TUNSETPERSIST");
		close(fd);
		return -1;
	}

	// set interface up
	/* XXX must be root
	if((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		close(fd);
		return -1;
	}

	// get current flags
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
	if(ioctl(sd, SIOCGIFFLAGS, &ifr) == -1) {
		perror("SIOCGIFFLAGS");
		close(sd);
		close(fd);
		return -1;
	}

	// set up
	memset(&ifw, 0, sizeof(ifw));
	strncpy(ifw.ifr_name, if_name, IFNAMSIZ - 1);
	ifw.ifr_flags = ifr.ifr_flags | IFF_UP | IFF_RUNNING;
	if(ioctl(sd, SIOCSIFFLAGS, &ifw) == -1) {
		perror("SIOCSIFFLAGS");
		close(sd);
		close(fd);
		return -1;
	}
	close(sd);
	 */

	return fd;
}


static inline int min(int a, int b) {

	return (a < b)? a : b;
}

static const unsigned int DEFAULT_MTU = 1500;
//static const unsigned short ether_type = 0xFFFE; // magic number, in case we need it for a wireshark filter

int write_interface(int fd, unsigned char *data, unsigned int data_len,
   uint64_t src_addr, uint64_t dst_addr, unsigned short ether_type) {

	unsigned char frame[DEFAULT_MTU]; // XXX buffer overflow?
	struct ethhdr eh;

	if(fd < 0)
		return data_len;

	unsigned char src_mac[6];
	unsigned char dst_mac[6];
	uint8_t i, shift;
	for(i=0;i<6;i++) {
		shift = 8*(5-i);
		src_mac[i] = (src_addr >> shift) & 0xff;
		dst_mac[i] = (dst_addr >> shift) & 0xff;
	}

	memcpy(eh.h_dest, dst_mac, ETH_ALEN);
	memcpy(eh.h_source, src_mac, ETH_ALEN);
	eh.h_proto = htons(ether_type);

	memcpy(frame, &eh, sizeof(eh));
	memcpy(frame + sizeof(eh), data,
	   min(data_len, sizeof(frame) - sizeof(eh)));

	if(write(fd, frame, sizeof(eh) + data_len) == -1) {
		perror("write");
		return -1;
	}

	return data_len;
}

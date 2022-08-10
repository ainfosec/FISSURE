#include<stdio.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include <string.h>


int output;

/*
 * Standard libpcap format.
 */
#define TCPDUMP_MAGIC           0xa1b2c3d4

void write_pcap_header(void)
{
  struct pcap_file_header hdr;
  hdr.magic = TCPDUMP_MAGIC;
  hdr.version_major = PCAP_VERSION_MAJOR;
  hdr.version_minor = PCAP_VERSION_MINOR;
  hdr.thiszone = 0;
  hdr.sigfigs = 3; /* milliseconds */
  hdr.snaplen = 100;
  hdr.linktype = DLT_USER0;
  write(output,&hdr, sizeof(hdr));
}

#if defined( _POSIX_SOURCE) || defined(__APPLE__)
static pid_t ws_pid;
extern "C" pid_t popen2(const char *shell_cmd, int *p_fd_in, int *p_fd_out);
#endif

#pragma pack(1)
struct pcap_pkthdr_safe
{
  unsigned int tv_sec;
  unsigned int tv_usec;
  bpf_u_int32 caplen;	/* length of portion present */
  bpf_u_int32 len;	/* length this packet (off wire) */
};

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

void write_wiresark(unsigned char *f, unsigned char len,int rfspeed)
{
  struct pcap_pkthdr_safe pkt;
  static size_t rx_count = 0;

  char buf[1500];
  char* p;
  //struct ether_header* eth = (struct ether_header*) buf;
  memset(buf, 0, sizeof(buf));
  p=buf;
  *p++ = rfspeed;
  *p++ = 0;
  *p++ = 0;

  memcpy(p, (char*) f, len);

  pkt.tv_sec = 0;
  pkt.tv_usec = 0;
  pkt.caplen = len  + 3;
  pkt.len = pkt.caplen;
  write(output,&pkt, sizeof(pkt));
  write(output,&buf, pkt.caplen);
#if defined( _POSIX_SOURCE)
  syncfs(output);
#endif
  rx_count++;
  printf("Got %6u\r", (unsigned int)rx_count);
  fflush(stderr);
}

int open_wirreshark()
{
  int dummy;

  if(!output)
    {
      ws_pid = popen2("wireshark -k -i -",&output,&dummy);
      if(output==0)
        {
          perror("Unable to open wireshark\n");
          return 1;
        }
    }
  write_pcap_header();
  return 0;
}



/*
 * Generic EDNS0 handling + client mac
 *
 * @author Benjamin Petrin
 */
#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef ADDMAC

#include "relay.h"
#include "common.h"

#include <sys/types.h>
#include <arpa/nameser.h>
#include <string.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

//PUTBYTE, use like PUTSHORT and PUTLONG
#define PUTBYTE(i, p) \
  *p = i;             \
  p += 1;

/*
 * The below macros, structures, and functions up to and
 * including the logic of get_mac_from_ip are adapted
 * from the linux IP command written by Alexey N. Kuznetsov
 *
 */

#define NDA_RTA(r) ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg)))) 

struct rtnl_handle
{
  int                     fd;
  struct sockaddr_nl      local;
  struct sockaddr_nl      peer;
  __u32                   seq;
  __u32                   dump;
};

int rcvbuf = 1024 * 1024;

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
  memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
  while (RTA_OK(rta, len)) {
    if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
      tb[rta->rta_type] = rta;
    rta = RTA_NEXT(rta,len);
  }
  return 0;
}

/*
 *  * skip_questions
 *
 * In:      msg             - pointer to start of packet
 *
 * Returns:  Pointer to position in packet after questions section
 *
 * Takes a single dns query and returns the end of the question section
 * This is useful if you need to append data to the additional section
 * This function is largely derived from the Dnsmasq project
 * Dnsmasq is Copyright (c) 2000-2010 Simon Kelley
 * See: http://www.thekelleys.org.uk/dnsmasq/doc.html
 *
 */
unsigned char* skip_questions(char* msg, int plen){
   /* pointer into the message */
   char *p;
   /* the question we are on */
   int q;

   /* the question count is 2 bytes starting at byte 4 */
   p = (char* ) (msg + 4);
   int qdcount;
   GETSHORT(qdcount, p);

   /* skip over the header */
   p = (char* ) (msg + 12);

   for (q=0; q<qdcount; q++){
       while (1)
         {
           if (((*p) & 0xc0) == 0xc0) /* pointer for name compression */
             {
              p += 2;
               break;
             }
           else if (*p)
             { /* another segment of length *p */
               p += (*p) + 1;
             }
           else
             { /* *p == 0, the end */
               p++;
               break;
             }
         }
         /* skip over the class and type */
       p += 4;
     }
   return p;
 }

/*
 * fills in lladdr
 *
 * returns non-zero on error
 *
 */
int get_mac_from_ip(char * lladdr, struct in_addr addr)
{
  int foundIP = 0;

  struct rtnl_handle rth = { .fd = -1 };
  socklen_t addr_len;
  int sndbuf = 32768;

  memset(&rth, 0, sizeof(rth));

  //NETLINK_ROUTE is used to retreive routing information
  rth.fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  setsockopt(rth.fd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf));
  setsockopt(rth.fd,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf));
  memset(&rth.local, 0, sizeof(rth.local));
  rth.local.nl_family = AF_NETLINK;
  rth.local.nl_groups = 0;
  bind(rth.fd, (struct sockaddr*)&rth.local, sizeof(rth.local));
  addr_len = sizeof(rth.local);
  getsockname(rth.fd, (struct sockaddr*)&rth.local, &addr_len);
  rth.seq = time(NULL);

  //our request structure
  struct {
    struct nlmsghdr nlh;
    struct rtgenmsg g;
  } req;

  memset(&req, 0, sizeof(req));
  req.nlh.nlmsg_len = sizeof(req);
  //RTM_GETNEIGH to get neighbor table entries
  req.nlh.nlmsg_type = RTM_GETNEIGH;
  //NLM_F_ROOT - returns entire table
  //NLM_F_MATCH - returns matching entries, not implemented in kernel
  //NLM_F_REQUEST - must be set on all requests
  req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
  req.nlh.nlmsg_pid = 0;
  req.nlh.nlmsg_seq = rth.dump = ++rth.seq;
  req.g.rtgen_family = AF_UNSPEC;
  send(rth.fd, (void*)&req, sizeof(req), 0);

  struct sockaddr_nl nladdr;
  struct iovec iov;
  struct msghdr msg = {
    .msg_name = &nladdr,
    .msg_namelen = sizeof(nladdr),
    .msg_iov = &iov,
    .msg_iovlen = 1,
  };
  char buf[16384];
  iov.iov_base = buf;

  unsigned int status;
  iov.iov_len = sizeof(buf);
  status = recvmsg(rth.fd, &msg, 0);

  struct nlmsghdr *h = (struct nlmsghdr*)buf;
  while (NLMSG_OK(h, status)) { 
    struct ndmsg *r = NLMSG_DATA(h);
    int len = h->nlmsg_len;
    struct rtattr * tb[NDA_MAX+1];

    len -= NLMSG_LENGTH(sizeof(*r));

    //parse all the returned attributes
    parse_rtattr(tb, NDA_MAX, NDA_RTA(r), h->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

    //inspect the destination
    if (tb[NDA_DST]) {
      if (memcmp(&addr, RTA_DATA(tb[NDA_DST]), 4) == 0) {
        //we are currently looking at the IP we are interested in
        foundIP = 1;
      }
    }
    //inspect the link layer address for this IP
    if (tb[NDA_LLADDR] && foundIP) {
      //we found it
      memcpy(lladdr, RTA_DATA(tb[NDA_LLADDR]), 6);
      return 0;
    }

    h = NLMSG_NEXT(h, status);
  }
  //log_debug(1, "Failed to find IP %s in the arp table", inet_ntoa(addr));
  return 1;
}

/*
 * adds an opt rr to the packet that is suitable
 * for holding an EDNS0 option (the first 11  bits)
 * up to but not including the RDLENGTH
 *
 * returns a pointer to rd length
 *
 */
unsigned char* edns0_add_opt_rr(char *header, int* plen)
{
  unsigned char* p = skip_questions(header, *plen);
  
  /* two bytes starting at the 10th byte specify the arcount */
  int arcount;
  unsigned char* temp = header + 10;
  GETSHORT(arcount, temp);
  temp -= 2;
  PUTSHORT(arcount + 1, temp);
  
  /* name - left blank */
  PUTBYTE(0, p);
  *plen += 1;

  /* type is 16 bits unsigned, value of 41 (0x29) is OPT RR */
  PUTSHORT(0x0029, p);
  *plen += 2;

  /* class is the max size of udp message */
  PUTSHORT(0x05a0, p);
  *plen +=2;

  /* the ttl, 32 bits, is repurposed as follows */
  /* upper 8 bits of 12 bit RCODE + version */
  PUTSHORT(0x0000, p);
  /* additional flags, all left as 0 */
  PUTSHORT(0x0000, p);
  *plen += 4;

  /*initialize the length to 0 */
  PUTSHORT(0x0000, p);
  *plen += 2;
  
  /* back up the pointer to the length */
  p -= 2;
  return p;
}

/*
 * (in/out) header - the packet
 * (in/out) plen - length of the packet
 * (out) psuedo_rr - will become pointer to the length part
 *   of a new or existing psuedo_rr. If it is new
 *   the length will have a value of 0, otherwise
 *   it will have the value that will need to be
 *   incremented
 *
 * Finds or creaates a pseudo rr.
 *
 * returns - non-zero on error
 *
 */
int edns0_get_opt_rr(char *header, int *plen, unsigned char** pseudo_rr)
{
  int arcount;
  unsigned char* temp = header + 10;
  GETSHORT(arcount, temp);
  
  if (arcount == 0)
  {
    /* we need to create a pseudo rr */
    *pseudo_rr = edns0_add_opt_rr(header, plen);
    return 0;
  }
  else if (arcount == 1)
  {
    /* one exists, it's length is 9 octets after the questions */
    *pseudo_rr = (unsigned char*) (skip_questions(header, *plen) + 9);
    return 0;
  }
  else
  {
    /* something is wrong if theres more than one addition section */
    pseudo_rr = NULL;
    return 1;
  }
}

/*edns0_add_client_mac
 *
 * (in/out) pseudo_rr - pointer to the length section of pseudo_rr
 * (in/out) plen - length of packet
 * (in) udpaddr - source
 *
 * returns - non-zero on error
 *
 */
int edns0_add_client_mac(unsigned char* pseudo_rr, int *plen, const struct sockaddr_in *fromaddrp)
{
  unsigned char *ptr = pseudo_rr;

  if (fromaddrp->sin_family != AF_INET)
  {
    /* we currently only support ipv4 */
    return 1;
  }

  int orig_length;
  GETSHORT(orig_length, ptr);

  char lladdr[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  if (get_mac_from_ip(lladdr, fromaddrp->sin_addr))
  {
    return 1;
  }
  
  /* add to the length this options total length */
  PUTSHORT(orig_length + 10, pseudo_rr);
  
  /* in the event the previous length was non-zero, skip over that much */
  pseudo_rr += orig_length;

  /* now that we have the client mac, we can add it to the option */
  
  /* rdata */
  /* option-code */
  PUTSHORT(5, pseudo_rr);
  /* option-length - 6 bytes for a mac address */
  PUTSHORT(0x0006, pseudo_rr);
  *plen += 4;
  
  /* the payload itself, 6 octets containing the MAC address */
  PUTBYTE(lladdr[0],pseudo_rr);
  PUTBYTE(lladdr[1],pseudo_rr);
  PUTBYTE(lladdr[2],pseudo_rr);
  PUTBYTE(lladdr[3],pseudo_rr);
  PUTBYTE(lladdr[4],pseudo_rr);
  PUTBYTE(lladdr[5],pseudo_rr);
  
  *plen += 6;

  return 0;
}
#endif /* ADDMAC  */

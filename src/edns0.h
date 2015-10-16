#ifndef _DNRD_EDNS0_H_
#define _DNRD_EDNSO_H_

int edns0_get_opt_rr(char *header, int *plen, unsigned char** pseudo_rr);
int edns0_add_client_mac(unsigned char* pseudo_rr, int *plen, const struct sockaddr_in *fromaddrp);

#endif /* _DNRD_EDNS0_H_ */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <inttypes.h>

void usage()
{
    printf("usage: ssh-ciphers <host> [<port>]\n"
           "  host   hostname or IP address\n"
           "  port   port to connect to. [22]\n");
    exit(1);
}

int try_connect(char *addr, char *port)
{
    printf("[+] Connecting\n");

    /* Hints */
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = 0;
    hints.ai_protocol = 0;

    /* Resolve */
    int r;
    struct addrinfo *results;
    r = getaddrinfo(addr, port, &hints, &results);
    if(0 != r)
    {
        printf("[-] Could not resolve address: %s\n", gai_strerror(r));
        return -1;
    }

    printf("[+] Address resolved\n");

    /* Connect */
    r = -1;
    int sock;
    struct addrinfo *ai;
    for(ai = results; ai; ai = ai->ai_next)
    {
        printf("[+] Trying to connect ...\n");
        sock = socket(ai->ai_family, SOCK_STREAM, ai->ai_protocol);
        if(-1 == sock)
        {
            printf("[-] Failed\n");
            continue;
        }

        r = connect(sock, ai->ai_addr, ai->ai_addrlen);
        if(-1 == r)
        {
            printf("[-] Connect failed\n");
            continue;
        }

        printf("[+] Connected\n");
        break;
    }

    /* Free */
    freeaddrinfo(results);

    if(-1 != r)
        return sock;
    else
        return -1;
}

ssize_t readline(int sock, char **buf)
{
    unsigned int bufsize = 1024;
    *buf = realloc(*buf, bufsize);
    assert(*buf);

    memset(*buf, 0, bufsize);

    char c;
    unsigned int len;
    for(len = 0;;)
    {
        if(len == bufsize)
        {
            bufsize *= 2;
            *buf = realloc(*buf, bufsize);
            assert(*buf);
        }
        if(read(sock, &c, 1) != 1)
        {
            printf("[-] read failed / EOF\n");
            return len;
        }
        if(c == '\n')
        {
            if(len > 1 && (*buf)[len - 1] == '\r')
                len--;
            (*buf)[len] = '\0';
            return len;
        }
        (*buf)[len++] = c;
    }
}

int dump_name_list(char **p, int *left, const char *name)
{
    const char *margin = "    "; 
    printf("* %s\n", name);

    uint32_t nlen;
    nlen = ntohl(*((uint32_t *)*p));
    
    *p += 4;
    *left -= 4;
    
    if(*left < nlen)
        return 1;

    int newline = 1;
    (*left) -= nlen;
    for(int i = 0; i < nlen; i++, (*p)++)
    {
        if(**p == ',')
        {
            newline = 1;
            printf("\n");
            continue;
        }
        printf("%s%c", newline ? margin : "", **p);
        newline = 0;
    }
    if(nlen) printf("\n");
    return 0;
}

int decode_packet(char *buf, int buflen)
{
    char *p = buf;
    int left = buflen;
    
    /* Message type number */
    if(left < 1) goto tooshort;
    if(*p++ != 20)
    {
        printf("[-] Unsupported message number: %i"
               " - expected 20 (SSH_MSG_KEXINIT)\n", buf[0]);
        return 1;
    }
    left--;
    /* Cookie */
    if(left < 16) goto tooshort;
    printf("[>] Message number   20 (SSH_MSG_KEXINIT)\n");
    printf("[>] Cookie           ");
    for(int i = 0; i < 16; i++, p++, left--)
    {
        printf("%02X ", (uint8_t)*p);
    }
    printf("\n");
    /* name-lists */
    const char *lists[] = { "kex_algorithms", "server_host_key_algorithms",
                            "encryption_algorithms_client_to_server",
                            "encryption_algorithms_server_to_client",
                            "mac_algorithms_client_to_server",
                            "mac_algorithms_server_to_client",
                            "compression_algorithms_client_to_server",
                            "compression_algorithms_server_to_client",
                            "languages_client_to_server",
                            "languages_server_to_client", NULL };
    for(int i = 0; lists[i] != NULL; i++)
    {
        if(dump_name_list(&p, &left, lists[i]) != 0)
        {
            printf("[-] Error decoding name-list %s\n", lists[i]);
            return 1;
        }
        printf("\n");
    }
    /* first_kex_packet_follows */
    if(left < 1) goto tooshort;
    left--;
    printf("[>] first_kex_packet_follows   %s\n", *p++ ? "TRUE" : "FALSE");

    return 0;
tooshort:
    printf("[-] Payload too short\n");
    return 1;
}

int main(int argc, char *argv[])
{
    if(argc < 2)
        usage();
    
    int sock;
    sock = try_connect(argv[1], argc == 3 ? argv[2] : "22");

    if(-1 == sock)
        return 1;

    int r;
    char *buf = NULL;
   
    for (;;)
    {
        r = readline(sock, &buf);   /* SSH-2.0-OpenSSH_5.1 */
        if(r < 0)
        {
            printf("[-] Unexpected EOF or error\n");
            goto end;
        }

        if(strncmp(buf, "SSH-", 4))
            continue;

        if(strncmp(buf, "SSH-2.0", 7))
        {
            printf("[-] Need version 2.0 SSH. Got '%s'\n", buf);
            goto end;
        }
        printf("[+] SSH version 2.0\n");
        break;
    }
    write(sock, buf, r);
    write(sock, "\r\n", 2);

    uint32_t pkglen;
    uint32_t paylen;
    uint8_t  padlen;
    char padbytes[256];
    for(;;)
    {
        /* Package length */
        assert(read(sock, &pkglen, 4) == 4);
        pkglen = ntohl(pkglen);
        /* Padding length */
        assert(read(sock, &padlen, 1) == 1);
        
        if(padlen >= pkglen)
        {
            printf("[-] Package length <= 0\n");
            goto end;
        }
        /* Payload length */
        paylen = pkglen - padlen - 1;
        printf("[+] Received package\n");
        printf("[.] Package length : %u\n", pkglen);
        printf("[.] Padding length : %u\n", padlen);

        if(pkglen > 10000000)
        {
            printf("[-] Package seems to be too long - ABORTING\n");
            goto end;
        }
        assert((buf = realloc(buf, paylen)));
        r = read(sock, buf, paylen);
        if(r != paylen)
        {
            printf("[-] Read payload failed\n");
            goto end;
        }
        r = read(sock, padbytes, padlen);
        if(r != padlen)
        {
            printf("[-] Read padding failed\n");
            goto end;
        }
        decode_packet(buf, paylen);
        break;
    }    
    

end:
    free(buf);
    close(sock);

    return 0;
}


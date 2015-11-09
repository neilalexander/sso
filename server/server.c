#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include <sodium.h>

#include "../shared/types.h"
#include "../shared/packet.h"
#include "../hiredis/hiredis.h"
#include "server.h"

struct sso_config config;

void print_hex(const char *s)
{
  while (*s)
    printf("%02x", (unsigned int) *s++);

  printf("\n");
}

int main(int argc, char** argv)
{
    char local_realm[REALM_LENGTH];
    if (argc == 1)
        strncpy(local_realm, "default", REALM_LENGTH);
    else
        strncpy(local_realm, argv[1], REALM_LENGTH);

    printf("Starting for realm '%s'\n", local_realm);

    unsigned char local_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char local_sk[crypto_box_SECRETKEYBYTES];

    char local_pk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    char local_sk_hex[crypto_box_SECRETKEYBYTES * 2 + 1];

    redisContext *c;

    printf("Attempting to connect to redis database... ");

    struct timeval timeout = {1, 500000};
    c = redisConnectWithTimeout("localhost", 6379, timeout);

    if (c == NULL || c->err)
    {
        printf("failed.\n");

        redisFree(c);
        exit(1);
    }

    printf("succeeded.\n");

    redisReply* skreply = redisCommand(c, "HGET realm:%s secretkey", local_realm);
    redisReply* pkreply = redisCommand(c, "HGET realm:%s publickey", local_realm);

    if (skreply->type == REDIS_REPLY_NIL ||
        pkreply->type == REDIS_REPLY_NIL)
    {
        fprintf(stderr, "Either secret or public key missing, generating new ones\n");

        crypto_box_keypair(local_pk, local_sk);

        sodium_bin2hex(local_pk_hex, sizeof(local_pk_hex), (const unsigned char*) &local_pk, crypto_box_PUBLICKEYBYTES);
        sodium_bin2hex(local_sk_hex, sizeof(local_sk_hex), (const unsigned char*) &local_sk, crypto_box_SECRETKEYBYTES);

        redisReply* setreply = redisCommand(c,"HSET realm:%s secretkey %s", local_realm, local_sk_hex);
        freeReplyObject(setreply);

        setreply = redisCommand(c,"HSET realm:%s publickey %s", local_realm, local_pk_hex);
        freeReplyObject(setreply);
    }
        else
    {
        strncpy(local_sk_hex, skreply->str, crypto_box_SECRETKEYBYTES * 2 + 1);
        strncpy(local_pk_hex, pkreply->str, crypto_box_SECRETKEYBYTES * 2 + 1);

        sodium_hex2bin(local_sk, crypto_box_SECRETKEYBYTES,
                local_sk_hex, crypto_box_SECRETKEYBYTES * 2 + 1,
                " ", NULL, NULL);
        sodium_hex2bin(local_pk, crypto_box_PUBLICKEYBYTES,
                local_pk_hex, crypto_box_PUBLICKEYBYTES * 2 + 1,
                " ", NULL, NULL);
    }

    freeReplyObject(skreply);
    freeReplyObject(pkreply);

    FILE *f;
    f = fopen("publickey.txt", "w");
    fputs((char*) &local_pk, f);
    fclose(f);

    int sd, optval;
    char recvbuffer[4096];

    printf("Realm public key: %s\n", local_pk_hex);

    struct sockaddr_in6 server;
    struct sockaddr_in6 endpoints[FD_SETSIZE];
    unsigned int sockets[FD_SETSIZE];

    memset(&sockets, 0, sizeof(int) * FD_SETSIZE);
    memset(&endpoints, 0, sizeof(struct sockaddr) * FD_SETSIZE);

    fd_set socketset;
    FD_ZERO(&socketset);

    memset(&server, 0, sizeof(struct sockaddr_in6));
    server.sin6_family = AF_INET6;
    server.sin6_port = htons(35469);
    server.sin6_addr = in6addr_any;

    socklen_t addr_size = sizeof(struct sockaddr_in6);

    if ((sd = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
    {
        perror("socket");
        exit(-1);
    }

    optval = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
        perror("setsockopt(SO_REUSEADDR)");

    optval = 0;
    if (setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, (char*) &optval, sizeof(optval)) < 0)
        perror("setsockopt(IPV6_V6ONLY)");

    if (bind(sd, (struct sockaddr*) &server, sizeof(struct sockaddr_in6)) < 0)
    {
        perror("bind");
        exit(-1);
    }

    char printableAddress[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &server.sin6_addr, printableAddress, INET6_ADDRSTRLEN);
    printf("Binding on address [%s]:%d\n", printableAddress, htons(server.sin6_port));

    if (listen(sd, FD_SETSIZE) < 0)
    {
        perror("listen");
        exit(-1);
    }

    while (1)
    {
        int maxfd = sd;
        FD_ZERO(&socketset);
        FD_SET(sd, &socketset);

        for (int i = 0; i < FD_SETSIZE; i ++)
        {
            if (sockets[i] > 0)
            {
                if (sockets[i] > maxfd)
                    maxfd = sockets[i];
                FD_SET(sockets[i], &socketset);
            }
        }

        int len = select(maxfd + 1, &socketset, NULL, NULL, 0);
        if (len < 0)
        {
            perror("select");
            return -1;
        }

        if (FD_ISSET(sd, &socketset))
        {
            for (int i = 0; i < FD_SETSIZE; i ++)
            {
                if (sockets[i] == 0)
                {
                    sockets[i] = accept(sd, (struct sockaddr*) &endpoints[i], &addr_size);
                    break;
                }
            }
        }

        for (int i = 0; i < FD_SETSIZE; i ++)
        {
            if (FD_ISSET(sockets[i], &socketset))
            {
                struct sso_packet packet;
                struct sso_packet responsepacket;

                memset(&packet, 0, sizeof(struct sso_packet));
                memset(&responsepacket, 0, sizeof(struct sso_packet));

                int bytes = recv(sockets[i], &packet, sizeof(struct sso_packet), 0);

                if (bytes == 0)
                {
                    close(sockets[i]);
                    memset(&sockets[i], 0, sizeof(int));
                    memset(&endpoints[i], 0, sizeof(struct sockaddr_in6));

                    continue;
                }

                printf("Received %d bytes\n", bytes);

                unsigned char session_pk[crypto_box_PUBLICKEYBYTES];
                unsigned char session_sk[crypto_box_SECRETKEYBYTES];

                char spkhex[crypto_box_PUBLICKEYBYTES * 2 + 1];
                char sskhex[crypto_box_SECRETKEYBYTES * 2 + 1];
                char pkhex[crypto_box_PUBLICKEYBYTES * 2 + 1];

                sodium_bin2hex(pkhex, sizeof(pkhex), (const unsigned char*) &packet.publickey, crypto_box_PUBLICKEYBYTES);
                printf("Packet type 0x%02x (payload length %i) from %s\n", packet.type, packet.length, pkhex);

                switch (packet.type)
                {
                    case STAGE1_CLIENT_TO_SERVER:
                    {
                        if (crypto_box_seal_open(
                                (unsigned char*) &packet.payload,
                                (const unsigned char*) &packet.payload,
                                (unsigned long long) packet.length,
                                (const unsigned char*) local_pk,
                                (const unsigned char*) local_sk)
                            != 0)
                        {
                            perror("crypto_box_seal_open");
                            break;
                        }

                        printf("Incoming authentication request from user '%s', password '%s'\n",
                                packet.payload.s1_c2s.username,
                                packet.payload.s1_c2s.password);

                        // TODO:
                        // - hostname check
                        // - user authentication (identity sources?)

                        unsigned char session_pk[crypto_box_PUBLICKEYBYTES];
                        unsigned char session_sk[crypto_box_SECRETKEYBYTES];
                        crypto_box_keypair(session_pk, session_sk);

                        char spkhex[crypto_box_PUBLICKEYBYTES * 2 + 1];
                        char sskhex[crypto_box_SECRETKEYBYTES * 2 + 1];
                        sodium_bin2hex(spkhex, sizeof(spkhex), (const unsigned char*) &session_pk, crypto_box_PUBLICKEYBYTES);
                        sodium_bin2hex(sskhex, sizeof(sskhex), (const unsigned char*) &session_sk, crypto_box_SECRETKEYBYTES);

                        redisReply* setreply;

                        setreply = redisCommand(c, "HSET realm:%s/session:%s secretkey %s", local_realm, pkhex, sskhex);
                        freeReplyObject(setreply);

                        setreply = redisCommand(c, "HSET realm:%s/session:%s publickey %s", local_realm, pkhex, spkhex);
                        freeReplyObject(setreply);

                        setreply = redisCommand(c, "HSET realm:%s/session:%s username %s", local_realm, pkhex, packet.payload.s1_c2s.username);
                        freeReplyObject(setreply);

                        setreply = redisCommand(c, "EXPIRE realm:%s/session:%s %i", local_realm, pkhex, DEFAULT_TICKET_LIFE_SECONDS);
                        freeReplyObject(setreply);

                        memcpy(responsepacket.payload.ticket.publickey, packet.publickey, crypto_box_PUBLICKEYBYTES);
                        memcpy(responsepacket.payload.ticket.username, packet.payload.s1_c2s.username, USERNAME_LENGTH);
                        memcpy(responsepacket.payload.ticket.hostname, packet.payload.s1_c2s.hostname, HOSTNAME_LENGTH);

                        taia_now(&responsepacket.payload.ticket.issuedtime);
                        taia_now(&responsepacket.payload.ticket.expirytime);
                        responsepacket.payload.ticket.expirytime.sec += DEFAULT_TICKET_LIFE_SECONDS;

                        memcpy(&responsepacket.payload.currenttime, &responsepacket.payload.ticket.issuedtime, sizeof(struct taia));

                        responsepacket.type = STAGE1_SERVER_TO_CLIENT;
                        responsepacket.length = sizeof(struct sso_packet_payload);
                        memcpy(responsepacket.publickey, session_pk, crypto_box_PUBLICKEYBYTES);
                        memset(responsepacket.nonce, 0, crypto_box_NONCEBYTES);

                        if (crypto_box_detached(
                                (unsigned char*) &responsepacket.payload.ticket,
                                (unsigned char*) &responsepacket.payload.ticketmac,
                                (const unsigned char*) &responsepacket.payload.ticket,
                                (unsigned long long) sizeof(struct sso_ticket),
                                (const unsigned char*) &responsepacket.nonce,
                                (const unsigned char*) &local_pk,
                                (const unsigned char*) &local_sk
                            ) != 0)
                        {
                            perror("crypto_box_detached(ticket)");
                        }

                        if (crypto_box_detached(
                                (unsigned char*) &responsepacket.payload,
                                (unsigned char*) &responsepacket.mac,
                                (const unsigned char*) &responsepacket.payload,
                                (unsigned long long) responsepacket.length,
                                (const unsigned char*) &responsepacket.nonce,
                                (const unsigned char*) &packet.publickey,
                                (const unsigned char*) &local_sk
                            ) != 0)
                        {
                            perror("crypto_box_detached(payload)");
                        }

                        if (send(sockets[i], &responsepacket, sizeof(struct sso_packet), 0) < 0)
                            perror("send");

                        memset(&packet, 0, sizeof(struct sso_packet));
                        memset(&responsepacket, 0, sizeof(struct sso_packet));

                        break;
                    }

                    case STAGE2_CLIENT_TO_SERVER:
                    {
                        redisReply* sskreply = redisCommand(c, "HGET realm:%s/session:%s secretkey", local_realm, pkhex);
                        redisReply* spkreply = redisCommand(c, "HGET realm:%s/session:%s publickey", local_realm, pkhex);

                        if (sskreply->type == REDIS_REPLY_NIL ||
                            spkreply->type == REDIS_REPLY_NIL)
                        {
                            fprintf(stderr, "No session exists for this public key\n");
                            break;
                        }

                        sodium_hex2bin(session_sk, crypto_box_SECRETKEYBYTES,
                                sskreply->str, crypto_box_SECRETKEYBYTES * 2 + 1,
                                " ", NULL, NULL);
                        sodium_hex2bin(session_pk, crypto_box_PUBLICKEYBYTES,
                                spkreply->str, crypto_box_PUBLICKEYBYTES * 2 + 1,
                                " ", NULL, NULL);

                        freeReplyObject(sskreply);
                        freeReplyObject(spkreply);

                        if (crypto_box_open_detached(
                                (unsigned char*) &packet.payload,
                                (const unsigned char*) &packet.payload,
                                (const unsigned char*) &packet.mac,
                                (unsigned long long) packet.length,
                                (const unsigned char*) &packet.nonce,
                                (const unsigned char*) &packet.publickey,
                                (const unsigned char*) &session_sk)
                            != 0)
                        {
                            perror("crypto_box_open_detached(payload)");
                            break;
                        }

                        printf("Incoming ticket request for target '%s'\n", packet.payload.s2_c2s.target);

                        if (crypto_box_open_detached(
                                (unsigned char*) &packet.payload.ticket,
                                (const unsigned char*) &packet.payload.ticket,
                                (const unsigned char*) &packet.payload.ticketmac,
                                (unsigned long long) sizeof(struct sso_ticket),
                                (const unsigned char*) &packet.nonce,
                                (const unsigned char*) &local_pk,
                                (const unsigned char*) &local_sk)
                            != 0)
                        {
                            perror("crypto_box_open_detached(ticket)");
                            break;
                        }

                        struct taia now;
                        taia_now(&now);

                        if (now.sec > packet.payload.ticket.expirytime.sec)
                        {
                            fprintf(stderr, "Ticket-granting ticket has expired\n");
                            break;
                        }

                        if (strcmp((const char*) packet.payload.s2_c2s.target, "") == 0)
                        {
                            fprintf(stderr, "No target specified, rejecting\n");
                            break;
                        }

                        redisReply* apkreply = redisCommand(c, "HGET realm:%s/application:%s publickey", local_realm, packet.payload.s2_c2s.target);

                        if (apkreply->type == REDIS_REPLY_NIL)
                        {
                            fprintf(stderr, "Application is not known or no public key available, rejecting\n");
                            break;
                        }

                        char application_pk[crypto_box_PUBLICKEYBYTES];
                        sodium_hex2bin(session_pk, crypto_box_PUBLICKEYBYTES,
                                apkreply->str, crypto_box_PUBLICKEYBYTES * 2 + 1,
                                " ", NULL, NULL);

                        freeReplyObject(apkreply);

                        // TODO:
                        // - hostname check

                        memcpy(responsepacket.payload.ticket.publickey, packet.payload.ticket.publickey, crypto_box_PUBLICKEYBYTES);
                        memcpy(responsepacket.payload.ticket.username, packet.payload.ticket.username, USERNAME_LENGTH);
                        memcpy(responsepacket.payload.ticket.hostname, packet.payload.ticket.hostname, HOSTNAME_LENGTH);
                        memcpy(responsepacket.payload.ticket.target, packet.payload.s2_c2s.target, HOSTNAME_LENGTH);

                        taia_now(&responsepacket.payload.ticket.issuedtime);
                        taia_now(&responsepacket.payload.ticket.expirytime);
                        responsepacket.payload.ticket.expirytime.sec += DEFAULT_TICKET_LIFE_SECONDS;

                        memcpy(&responsepacket.payload.currenttime, &responsepacket.payload.ticket.issuedtime, sizeof(struct taia));

                        responsepacket.type = STAGE2_SERVER_TO_CLIENT;
                        responsepacket.length = sizeof(struct sso_packet_payload);
                        memcpy(responsepacket.publickey, session_pk, crypto_box_PUBLICKEYBYTES); // TODO: Change to application key
                        memset(responsepacket.nonce, 0, crypto_box_NONCEBYTES);

                        if (crypto_box_detached(
                                (unsigned char*) &responsepacket.payload.ticket,
                                (unsigned char*) &responsepacket.payload.ticketmac,
                                (const unsigned char*) &responsepacket.payload.ticket,
                                (unsigned long long) sizeof(struct sso_ticket),
                                (const unsigned char*) &responsepacket.nonce,
                                (const unsigned char*) &application_pk,
                                (const unsigned char*) &local_sk
                            ) != 0)
                        {
                            perror("crypto_box_detached(ticket)");
                        }

                        if (crypto_box_detached(
                                (unsigned char*) &responsepacket.payload,
                                (unsigned char*) &responsepacket.mac,
                                (const unsigned char*) &responsepacket.payload,
                                (unsigned long long) responsepacket.length,
                                (const unsigned char*) &responsepacket.nonce,
                                (const unsigned char*) &packet.publickey,
                                (const unsigned char*) &local_sk
                            ) != 0)
                        {
                            perror("crypto_box_detached(payload)");
                        }

                        if (send(sockets[i], &responsepacket, sizeof(struct sso_packet), 0) < 0)
                            perror("send");

                        memset(&packet, 0, sizeof(struct sso_packet));
                        memset(&responsepacket, 0, sizeof(struct sso_packet));

                        break;
                    }

                    default:
                        fprintf(stderr, "Unexpected packet type %d\n", packet.type);
                        break;
                }

                memset(&recvbuffer, 0, 4096);
            }
        }
    }

    return 0;
}

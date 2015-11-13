#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include <sodium.h>
#include <sys/un.h>

#include "../shared/types.h"
#include "../shared/packet.h"
#include "client.h"
#include "control.h"

int main(int argc, char** argv)
{
    int usd, sd, optval;
    struct sockaddr_un control_addr;
    struct sockaddr_in6 serv_addr;
    struct hostent *server;

    struct sso_ticket masterticket;
    char masterticketmac[crypto_box_MACBYTES];

    unsigned char remote_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char session_pk[crypto_box_PUBLICKEYBYTES];

    unsigned char local_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char local_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(local_pk, local_sk);

    FILE *f;
    f = fopen("publickey.txt", "r");
    fgets((char*) &remote_pk, crypto_box_PUBLICKEYBYTES + 1, f);
    fclose(f);

    char hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), (const unsigned char*) &local_pk, crypto_box_PUBLICKEYBYTES);
    printf("Local public key: %s\n", hex);
    sodium_bin2hex(hex, sizeof(hex), (const unsigned char*) &remote_pk, crypto_box_PUBLICKEYBYTES);
    printf("Remote public key: %s\n", hex);

    if ((usd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        fprintf(stderr, "Failed to create control socket: ");
        perror("socket(AF_UNIX)");
        exit(-1);
    }

    control_addr.sun_family = AF_UNIX;
    strcpy(control_addr.sun_path, "/tmp/sso.sock");
    unlink(control_addr.sun_path);

    if (bind(usd, (struct sockaddr*) &control_addr, strlen(control_addr.sun_path) + sizeof(control_addr.sun_family)) < 0)
    {
        fprintf(stderr, "Failed to bind control socket: ");
        perror("bind(AF_UNIX)");
        exit(-1);
    }

    socklen_t addr_size = sizeof(struct sockaddr_in6);

    if ((sd = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
    {
        perror("socket(AF_INET6)");
        exit(-1);
    }

    while (1)
    {
        int maxfd = sd > usd ? sd : usd;

        fd_set socketset;
        FD_ZERO(&socketset);
        FD_SET(sd, &socketset);
        FD_SET(usd, &socketset);

        int len = select(maxfd + 1, &socketset, NULL, NULL, 0);
        if (len < 0)
        {
            perror("select");
            return -1;
        }

        if (FD_ISSET(usd, &socketset))
        {

        }

        if (FD_ISSET(sd, &socketset))
        {

        }
    }

    struct sso_packet packet;
    memset(&packet, 0, sizeof(struct sso_packet));
    packet.type = STAGE1_CLIENT_TO_SERVER;
    packet.length = sizeof(struct sso_packet_payload) + crypto_box_SEALBYTES;
    memcpy(packet.publickey, local_pk, crypto_box_PUBLICKEYBYTES);

    strncpy((char*) packet.payload.s1_c2s.username, "HELLO", USERNAME_LENGTH);
    strncpy((char*) packet.payload.s1_c2s.password, "HIYA", PASSWORD_LENGTH);

    if (crypto_box_seal(
            (unsigned char*) &packet.payload,
            (const unsigned char*) &packet.payload,
            (unsigned long long) packet.length - crypto_box_SEALBYTES,
            (const unsigned char*) remote_pk
        ) != 0)
    {
        perror("crypto_box_seal");
    }

    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_port = htons(35469);
    inet_pton(AF_INET6, "::", &serv_addr.sin6_addr);

    if (connect(sd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        perror("connect");

    printf(
        "Sending %d bytes (payload %d bytes)... ",
        (unsigned int) sizeof(struct sso_packet),
        (unsigned int) sizeof(struct sso_packet_payload)
    );

    int n = send(sd, &packet, sizeof(struct sso_packet), 0);
    if (n < 0)
        perror("failed");
    else
        printf("sent!\n");

    memset(&packet, 0, sizeof(struct sso_packet));

    int bytes = recv(sd, &packet, sizeof(struct sso_packet), 0);

    if (bytes == 0)
    {
        close(sd);
        perror("recv");
        exit(-1);
    }

    char pkhex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(pkhex, sizeof(pkhex), (const unsigned char*) &packet.publickey, crypto_box_PUBLICKEYBYTES);
    printf("Received %d bytes\n", bytes);
    printf("Packet type 0x%02x (payload length %i)\n", packet.type, packet.length);
    printf("Public key: %s\n", pkhex);

    if (crypto_box_open_detached(
            (unsigned char*) &packet.payload,
            (const unsigned char*) &packet.payload,
            (const unsigned char*) &packet.mac,
            (unsigned long long) packet.length,
            (const unsigned char*) &packet.nonce,
            (const unsigned char*) remote_pk,
            (const unsigned char*) local_sk)
        != 0)
    {
        perror("crypto_box_open_easy");
        return -1;
    }

    printf("Received something successfully.\n");

    memcpy(&session_pk, &packet.publickey, crypto_box_PUBLICKEYBYTES);
    memcpy(&masterticket, &packet.payload.ticket, sizeof(struct sso_ticket));
    memcpy(&masterticketmac, &packet.payload.ticketmac, crypto_box_MACBYTES);

    memset(&packet, 0, sizeof(struct sso_packet));

    packet.type = STAGE2_CLIENT_TO_SERVER;
    packet.length = sizeof(struct sso_packet_payload) + crypto_box_MACBYTES;
    memcpy(packet.publickey, local_pk, crypto_box_PUBLICKEYBYTES);
    memset(packet.nonce, 0, crypto_box_NONCEBYTES);

    memcpy(&packet.payload.ticket, &masterticket, sizeof(struct sso_ticket));
    memcpy(&packet.payload.ticketmac, &masterticketmac, crypto_box_MACBYTES);
    strncpy((char*) packet.payload.s2_c2s.target, "test", TARGET_LENGTH);

    if (crypto_box_detached(
            (unsigned char*) &packet.payload,
            (unsigned char*) &packet.mac,
            (const unsigned char*) &packet.payload,
            (unsigned long long) packet.length,
            (const unsigned char*) &packet.nonce,
            (const unsigned char*) session_pk,
            (const unsigned char*) local_sk
        ) != 0)
    {
        perror("crypto_box_easy(payload)");
    }

    printf(
        "Sending %d bytes (payload %d bytes)... ",
        (unsigned int) sizeof(struct sso_packet),
        packet.length
    );

    n = send(sd, &packet, sizeof(struct sso_packet), 0);
    if (n < 0)
        perror("failed");
    else
        printf("sent!\n");

    memset(&packet, 0, sizeof(struct sso_packet));

    exit(0);
}

#include "packet.h"

char* sso_generatePacket()
{
    struct sso_packet_headers h;
    h.flags = 0x0;
    h.length = 32;
}

#include <stdio.h>
#include "tom.h"


int 
main(int argc, char **argv) 
{
    struct tom tomi;

    /* ----------------------- */
    if (tom_init(&tomi, "eth1") != TOM_OK) {
        printf("Well, shit.\n");
        return 1;
    }

    struct ip_addr a;

    a.type = TOM_IP4;
    a.mask = 12;
    a.addr[0] = 172;
    a.addr[1] = 16;
    a.addr[2] = 0;
    a.addr[3] = 0;
    tom_add_target(&tomi, &a);

    struct ip_addr b;
    b.type = TOM_IP4;
    b.mask = 0;
    b.addr[0] = 0;
    b.addr[1] = 0;
    b.addr[2] = 0;
    b.addr[3] = 0;
    tom_add_target(&tomi, &b);


    printf("Great success\n");
    //tom_capture_one(&tomi);
     while (tom_capture_one(&tomi) != TOM_FAIL) { 

     }


    tom_free(&tomi);



    return 0;
}

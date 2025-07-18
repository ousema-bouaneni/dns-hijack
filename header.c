/*
 * header.c
 *
 *
 *      some of the code is from site BinaryTides, written by Silver Moon
 */

#include<sys/socket.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<string.h>

#include "header.h"

unsigned short checksum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}


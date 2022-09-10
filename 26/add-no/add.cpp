#include <stdio.h>
#include <stdint.h>
#include "add.h"

uint32_t add(FILE* f1, FILE* f2){
    
    uint32_t n1,n2;
    fread(&n1,sizeof(uint32_t),1,f1);
    fread(&n2,sizeof(uint32_t),1,f2);
    
    //printf("f1: %X\n",n1);
    uint32_t tmp1=n1>>24|(n1&0x00ff0000)>>8|(n1&0x0000ff00)<<8|n1<<24;
    uint32_t tmp2=n2>>24|(n2&0x00ff0000)>>8|(n2&0x0000ff00)<<8|n2<<24;
    uint32_t rst=tmp1+tmp2;
    printf("%u(0X%X) + %u(0X%X) = %u(0X%X)\n",tmp1,tmp1,tmp2,tmp2,rst,rst);
    
    
    
    return 0;
}

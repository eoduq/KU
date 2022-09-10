#include <stdio.h>
#include "add.h"

int main(int argc, const char * argv[]) {
    // insert code here...
    if(argc==3){
        FILE* f1=fopen(argv[1],"r");
        FILE* f2=fopen(argv[2],"r");
        add(f1,f2);
        
    	fclose(f1);
    	fclose(f2);
    }
    else{
        printf("Input error\n");
    }
    
    return 0;
}

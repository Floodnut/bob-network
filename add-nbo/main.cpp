#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>

uint32_t toNbo(char* argv){
    FILE* file;
    uint32_t n = 0;
    file = fopen(argv, "r");
    fread(&n, 4, 4, file);
    fclose(file);

    return ntohl(n);
    //return ((n & 0xff000000) >> 24) | ((n & 0xff0000)>>8) | ((n & 0xff00) << 8) | ((n & 0xff) << 24);
}

int main(int argc, char** argv){

    uint32_t a = toNbo(argv[1]);
    uint32_t b = toNbo(argv[2]);
    
    printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n", a, b, a, b, a + b, a + b);

    return 0;
}
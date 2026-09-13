/* Synthetic public test frame only. No OS store or real key material. */
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
static void pause_ms(long ms) { struct timespec time={ms/1000,(ms%1000)*1000000}; nanosleep(&time,0); }
int main(int argc,char **argv) {
    if(argc!=2 && argc!=4) return 10;
    unsigned char request[513]; size_t used=0;
    for(;;) { ssize_t n=read(0,request+used,sizeof(request)-used); if(n<0)return 11;if(n==0)break;used+=(size_t)n;if(used==sizeof(request))return 12; }
    unsigned char frame[107]={0}; memcpy(frame,"EABKSEED",8);frame[8]=1;frame[9]=2;
    memset(frame+10,0x31,32);memset(frame+42,0x41,32);memset(frame+74,0x51,32);
    size_t size=strcmp(argv[1],"extra")==0?107:strcmp(argv[1],"short")==0?105:106;
    if(write(1,frame,size)!=(ssize_t)size)return 13;
    if(strcmp(argv[1],"exit-error")==0)return 14;
    if(strcmp(argv[1],"no-exit")==0){close(1);pause_ms(1000);}
    if(strcmp(argv[1],"no-eof")==0){
        if(argc!=4)return 16;
        pid_t child=fork();if(child<0)return 15;
        if(child==0){
            FILE *marker=fopen(argv[2],"w");if(!marker)_exit(17);fputs("held",marker);fclose(marker);
            int count=0;while(access(argv[3],F_OK)!=0 && count++<2000)pause_ms(5);
            marker=fopen(argv[2],"w");if(!marker)_exit(18);fputs(access(argv[3],F_OK)==0?"released":"timeout",marker);fclose(marker);
            _exit(0);
        }
    }
    return 0;
}

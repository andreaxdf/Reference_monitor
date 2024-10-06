
#include <unistd.h>
#include <errno.h>
#include <stdio.h>


int main(int argc, char** argv){
	int ret = syscall(134,1,2);
	printf("ret=%d errno=%d\n", ret, errno);
}

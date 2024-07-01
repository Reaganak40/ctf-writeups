#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char* argv[]){
	char fname[128];
	unsigned long long otp[2];

	if(argc!=2){
		printf("usage : ./otp [passcode]\n");
		return 0;
	}

	int fd = open("/dev/urandom", O_RDONLY);
	if(fd==-1) exit(-1);
	
	// read 16 bytes from /dev/urandom
	if(read(fd, otp, 16)!=16) exit(-1);
	close(fd);
	
	// create a file in tmp named with otp[0] and write otp[1] to it
	sprintf(fname, "/tmp/%llu", otp[0]);
	FILE* fp = fopen(fname, "w")
	if(fp==NULL){ exit(-1); }
	fwrite(&otp[1], 8, 1, fp);
	fclose(fp);

	printf("OTP generated.\n");
	
	// reading from fname file
	unsigned long long passcode=0;
	FILE* fp2 = fopen(fname, "r");
	if(fp2==NULL){ exit(-1); }
	fread(&passcode, 8, 1, fp2);
	fclose(fp2);
	
	// compare passcode with argv[1] in hex
	if(strtoul(argv[1], 0, 16) == passcode){
		printf("Congratz!\n");
		system("/bin/cat flag");
	}
	else{
		printf("OTP mismatch\n");
	}

	unlink(fname);
	return 0;
}


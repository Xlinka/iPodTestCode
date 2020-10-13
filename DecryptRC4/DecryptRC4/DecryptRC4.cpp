#include <io.h>
#include <stdlib.h>
#include <stdio.h>
#include "rc4.h"


unsigned int
readword(unsigned char* data, unsigned int pos)
{
	return (data[pos]) + (data[pos + 1] << 8) + (data[pos + 2] << 16) + (data[pos + 3] << 24);
}

char
testmarker(unsigned int marker)
{
	unsigned int mask;
	unsigned int decrypt;
	unsigned int temp1, temp2;
	mask = (marker & 0xff) | ((marker & 0xff) << 8) | ((marker & 0xff) << 16) | ((marker & 0xff) << 24);
	decrypt = marker ^ mask;
	temp1 = decrypt >> 24;
	temp2 = decrypt << 8;

	if (temp1 == 0) {
		return 0; /*false*/
	}
	temp2 = temp2 >> 24;
	decrypt = decrypt << 16;
	decrypt = decrypt >> 24;
	if ((temp1 < temp2) && (temp2 < decrypt)) {
		temp1 = temp1 & 0xf;
		temp2 = temp2 & 0xf;
		decrypt = decrypt & 0xf;;
		if ((temp1 > temp2) && (temp2 > decrypt)) {
			if (decrypt != 0) return 1; // this marker is enable
		}
		return 0;
	}
}

int
main(int argc, char** argv)
{
	FILE* fdin, * fdout;
	unsigned char header[512];
	int i, j;
	unsigned int key = 0, pos = 0;
	unsigned int offset[] = { 0x5,0x25,0x6f,0x69,0x15,0x4d,0x40,0x34 };
	unsigned int amarker, word, temp1;
	unsigned int constant = 0x54c3a298;
	unsigned int r1, r2, r12, r14;
	unsigned char buff[4];
	unsigned char cle[4];

	rc4_key rc4k;
	char isencrypted = 0;

	if (!(fdin = fopen("Firmware-20.6.3.bin", "r"))) {
		perror("open");
		return 1;
	}

	/*reading the header of the file*/

	for (i = 0; i < 512; i++) {
		header[i] = getc(fdin);
	}

	/*compute the key from the file input*/
	for (i = 0; i < 8; i++) {
		pos = offset[i] * 4;
		amarker = readword(header, pos);
		printf("Marker %d : %x\n", i + 1, amarker);
		if (testmarker(amarker)) {
			isencrypted = 1;
			printf("Marker %d is set\n", i + 1);
			pos = (offset[i + 1] * 4) + 4;
			for (j = 0; j < 2; j++) {
				word = readword(header, pos);
				temp1 = amarker;
				temp1 ^= word;
				temp1 ^= constant;
				key = temp1;
				pos += 4;
			}
			r1 = 0x6f;
			for (j = 2; j < 128; j += 2) {
				r2 = readword(header, j * 4);
				r12 = readword(header, (j + 1) * 4);
				r14 = r2 | (r12 >> 16);
				r2 &= 0xffff;
				r2 |= r12;
				r1 ^= r14;
				r1 = r1 + r2;
			}
			key ^= r1;
			printf("Assosiated key is %x\n", key);
		}
	}
	if (!isencrypted) {
		fclose(fdin);
		printf("thefile is unencrypted\n");
		return EXIT_SUCCESS;
	}

	if (!(fdout = fopen("FirmwareAupd.bin","w+"))) {
		perror("open");
		return EXIT_FAILURE;
	}
	cle[3] = (key & 0xff000000) >> 24;
	cle[2] = (key & 0xff0000) >> 16;
	cle[1] = (key & 0xff00) >> 8;
	cle[0] = (key & 0xff);

	/*PREPERATE KEY*/
	prepare_key(cle, 4, &rc4k);

	/*Decryotion loop*/

	while (!feof(fdin))
	{
		buff[0] = fgetc(fdin);
		buff[1] = fgetc(fdin);
		buff[2] = fgetc(fdin);
		buff[3] = fgetc(fdin);
		rc4(buff, 4, &rc4k);
		fputc(buff[0], fdout);
		fputc(buff[1], fdout);
		fputc(buff[2], fdout);
		fputc(buff[3], fdout);
	}
	fclose(fdin);
	fclose(fdout);
	return EXIT_SUCCESS;
}
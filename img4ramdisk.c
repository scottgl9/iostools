#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define OFF1 0x02
#define OFF2 0x17

#ifndef uint8_t
#define uint8_t unsigned char
#endif

// at offsets 0x02 and 0x17 (3 byte little endian length of .raw.dmg): 02 73 70
void header_update_size(char *buf, char *filename) {
	size_t size=0;
	struct stat st;

	if (stat(filename, &st) == -1) {
		printf("Failed to stat file %s\n", filename);
		return;
	}
	size = st.st_size;

	//b[0] = (uint8_t) (size >>  0u);
	buf[OFF1+2] = (uint8_t) (size >>  8u);
	buf[OFF1+1] = (uint8_t) (size >> 16u);
	buf[OFF1] = (uint8_t) (size >> 24u);

	buf[OFF2+2] = (uint8_t) (size >>  8u);
	buf[OFF2+1] = (uint8_t) (size >> 16u);
	buf[OFF2] = (uint8_t) (size >> 24u);

	printf("Updated size to: %.2X %.2X %.2X (size=%X)\n", buf[OFF2]&0xFF, buf[OFF2+1]&0xFF, buf[OFF2+2]&0xFF, size);
}

int main(int argc, char **argv) {
	char buf[512];
	char filename[255];
	size_t count;

	if (argc < 3) {
		printf("Usage: %s <unpack|pack> <ramdisk_name>.dmg\n", argv[0]);
		return 0;
	}

	if (!strcmp(argv[1], "unpack")) {
	FILE *fin, *fout1, *fout2;

	strcpy(filename, argv[2]);
	strcat(filename, ".dmg");

	printf("Opening %s\n", filename);
	fin = fopen(filename, "rb");
	if (!fin) {
		printf("Error opening %s\n", filename);
		exit(-1);
	}
	fread(buf, 1, 27, fin);

	strcpy(filename, argv[2]);
	strcat(filename, ".hdr");
	fout1 = fopen(filename, "wb");
	fwrite(buf, 1, 27, fout1);
	fclose(fout1);
	printf("Created %s\n", filename);

	strcpy(filename, argv[2]);
	strcat(filename, ".raw.dmg");
	fout2 = fopen(filename, "wb");

	while (!feof(fin)) {
		count = fread(buf, 1, 512, fin);
		fwrite(buf, 1, count, fout2);
	}
	fclose(fout2);
	printf("Created %s\n", filename);
	fclose(fin);
	} else if (!strcmp(argv[1], "pack")) {
	FILE *fin1, *fin2, *fout;
        strcpy(filename, argv[2]);
        strcat(filename, ".new.dmg");
	printf("Creating %s\n", filename);

        fout = fopen(filename, "wb");

        strcpy(filename, argv[2]);
        strcat(filename, ".hdr");
        fin1 = fopen(filename, "rb");
        fread(buf, 1, 27, fin1);

	strcpy(filename, argv[2]);
	strcat(filename, ".raw.dmg");

	// at offsets 0x02 and 0x17 (3 byte big endian length of .raw.dmg): 02 73 70
	header_update_size(buf, filename);

	fwrite(buf, 1, 27, fout);
        fclose(fin1);

        fin2 = fopen(filename, "rb");

        while (!feof(fin2)) {
                count = fread(buf, 1, 512, fin2);
                fwrite(buf, 1, count, fout);
        }
        fclose(fout);
        fclose(fin2);

	}
}

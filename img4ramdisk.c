#include <stdio.h>

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
	fwrite(buf, 1, 27, fout);
        fclose(fin1);

        strcpy(filename, argv[2]);
        strcat(filename, ".raw.dmg");
        fin2 = fopen(filename, "rb");

        while (!feof(fin2)) {
                count = fread(buf, 1, 512, fin2);
                fwrite(buf, 1, count, fout);
        }
        fclose(fout);
        fclose(fin2);

	}
}

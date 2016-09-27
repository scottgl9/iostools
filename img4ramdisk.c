#include <stdio.h>

int main(int argc, char **argv) {
	char buf[512];
	char filename[255];
	FILE *fin, *fout1, *fout2;
	size_t count;

	if (argc < 2) {
		printf("Usage: %s <ramdisk_name>.dmg\n", argv[0]);
		return 0;
	}
	strcpy(filename, argv[1]);
	strcat(filename, ".dmg");

	printf("Opening %s\n", filename);
	fin = fopen(filename, "rb");
	fread(buf, 1, 27, fin);

	strcpy(filename, argv[1]);
	strcat(filename, ".hdr");
	fout1 = fopen(filename, "wb");
	fwrite(buf, 1, 27, fout1);
	fclose(fout1);
	printf("Created %s\n", filename);

	strcpy(filename, argv[1]);
	strcat(filename, ".raw.dmg");
	fout2 = fopen(filename, "wb");

	while (!feof(fin)) {
		count = fread(buf, 1, 512, fin);
		fwrite(buf, 1, count, fout2);
	}
	fclose(fout2);
	printf("Created %s\n", filename);
	fclose(fin);
}

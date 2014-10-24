#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "radix.h"
#include "buffer.h"

struct patricia_table *prefix_tree_;

void ReadAsMapping(char *filename) {
	FILE *f;
	char line[200], *prefix_str, *asnum_str, *token;
	u_int32_t prefix, prefixlen;
	char *asnum;

	f = fopen(filename, "r");
	if (f == NULL) {
		fprintf(stderr, "Unable to open file %s\n", filename);
		exit(1);
	}

	prefix_tree_ = patricia_new();
	while (!feof(f)) {
		if (!fgets(line, 200, f))
			break;
		line[strlen(line) - 1] = 0;

		prefix_str = strtok(line, " ");
		asnum_str = strtok(NULL, " ");

		token = strtok(prefix_str, "/");
		prefix = inet_addr(token);
		token = strtok(NULL, "/");
		prefixlen = atoi(token);

		asnum = strdup(asnum_str);

		patricia_insert(prefix_tree_, prefix, prefixlen, asnum);
	}
	fclose(f);
}

int MapSingleAddress(in_addr_t addr, char **asnum)
{
    unsigned int prefix, prefix_len;
    int retval = patricia_lookup_all(prefix_tree_, addr, &prefix, (prefixlen_t *)&prefix_len, (void **)asnum);
    return retval;
}

void MapAddresses(char *filename) {
	FILE *f;
	char addr_str[30];
	u_int32_t addr;
	char *asnum;
	int retval;

	f = fopen(filename, "r");
	if (f == NULL) {
		fprintf(stderr, "Unable to open file %s\n", filename);
		exit(1);
	}

	while (!feof(f)) {
		if (fscanf(f, "%s\n", addr_str) < 0)
			break;
		addr = inet_addr(addr_str);
		retval = MapSingleAddress(addr, &asnum);
		printf("%s ", addr_str);
		if (!retval)
		    printf("*");
		else
		    printf("%s", asnum);
		printf("\n");
	}
	fclose(f);
}

#if 0
int main(int argc, char *argv[]) {
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <asmapfile> <addresses>\n", argv[0]);
		exit(1);
	}

	ReadAsMapping(argv[1]);
	MapAddresses(argv[2]);

	return 0;
}
#endif

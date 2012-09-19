#include <stdio.h>

int main() {
	FILE *file = fopen("tmp","w");
	fprintf(file,"Hello, file.\n");
	return 0;
}

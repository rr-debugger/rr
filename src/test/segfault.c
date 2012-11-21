#include <stdlib.h>

int main(int argc, char *argv[]) {
	*((int*)rand()) = rand();
	return 0;
}

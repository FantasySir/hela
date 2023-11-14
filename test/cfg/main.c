#include <stdio.h>

int add(int a, int b)
{
	return a + b;
}

int main(void)
{
	int a = 1;
	int b = 2;
	printf("a + b = %d", add(a, b));
	return 0;
}
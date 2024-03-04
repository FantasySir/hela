#include <string.h>
#include <stdio.h>
#include "sm3.h"
#include <time.h>
#define M 1000

int main( int argc, char *argv[] )
{
	
	unsigned char output3[32];
	int i;
	clock_t start, end;
	int flag;

	//---------------------------------------------------------------
	start = clock();
	for (flag = 0; flag < M; flag++)
	{
		sm3_file("ITM3.txt", output3);
	}
	end = clock();
	
	printf("�ļ�HASH:\n   ");
	for (i = 0; i<32; i++)
	{
		printf("%02x", output3[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	printf("\n");


	printf("SM3�㷨C����ʵ�����ĵ�ʱ��Ϊ��%lf����", (float)(end - start)/M);
	//--------------------------------------------------
    
}
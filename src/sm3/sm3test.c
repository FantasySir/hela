
#include <string.h>
#include <stdio.h>
#include "sm3.h"
// 样例 1
// Input:"abc"  
// Output:66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0

// 样例 2 
// Input:"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
// Output:debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732
int main( int argc, char *argv[] )
{
	unsigned char *input = "abc";
	int ilen = 3;
	unsigned char output[32];
	int i;
	sm3_context ctx;

	//--------------------------------------------------
	printf("输入消息:\n");
	printf("%s\n",input);

	sm3(input, ilen, output);//调用sm3算法环节

	printf("杂凑值:\n   ");
    for(i=0; i<32; i++)
	{
		printf("%02x",output[i]);
		if (((i+1) % 4 ) == 0) printf(" ");
	} 
	printf("\n");
	printf("---------------------------------------------------------------------------\n");
	//--------------------------------------------------
    
	printf("输入消息:\n");
	for(i=0; i < 16; i++)
		printf("abcd");
	printf("\n");


    sm3_starts( &ctx );
	for(i=0; i < 16; i++)
		sm3_update( &ctx, "abcd", 4 );
    sm3_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sm3_context ) );//ctx置0
	

	printf("杂凑值:\n   ");
	for(i=0; i<32; i++)
	{
		printf("%02x",output[i]);
		if (((i+1) % 4 ) == 0) printf(" ");
	}   
	printf("\n"); 
}
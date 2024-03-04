# SM3密码杂凑算法基础学习

## 术语与定义

1 比特串bit string

由0和1组成的二进制数字序列。

2 大端big-endian

数据在内存中的一种表示格式，规定左边为高有效位，右边为低有效位。数的高阶字节放在存储器的低地址，数的低阶字节放在存储器的高地址。

3 消息message

任意有限长度的比特串。本文本中消息作为杂凑算法的输入数据。

4 杂凑值hash value

杂凑算法作用于消息后输出的特定长度的比特串。本文本中的杂凑值长度为256比特。

5 字word

长度为32的比特串

## 符号

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204180733261-837668677.png)

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204180746089-1660458826.png)



## 常量与函数

1
![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204180800620-1277777528.png)

2
![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204180823104-91079963.png)

3
![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204180841979-1054474866.png)

4
![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204180859370-1920728129.png)


## 算法描述

### 概述

对长度为l(l < 2^64) 比特的消息m， SM3杂凑算法经过填充和迭代压缩，生成杂凑值，杂凑值长度
为256比特

### 填充

假设消息m 的长度为l 比特。首先将比特“ 1”添加到消息的末尾，再添加k 个“ 0”， k是满
足l + 1 + k ≡ 448mod512 的最小的非负整数。然后再添加一个64位比特串，该比特串是长度l的二进
制表示。填充后的消息m′ 的比特长度为512的倍数。

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204180935354-802455231.png)

### 迭代压缩

1 迭代过程

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181101354-140470353.png)

2 消息扩展

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181140573-1088184788.png)

3 压缩函数

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181203573-1186421667.png)



压缩函数框图

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181219776-719227816.jpg)

其中，字的存储为大端(big-endian)格式

4 杂凑值

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181243933-829416454.png)

## C语言实现

### 函数与结构体定义

```
/**
 *  SM3 上下文结构体
 */
typedef struct
{
    unsigned long total[2];     /* 被处理的字节数  */
    unsigned long state[8];     /* 中间摘要 state  */
    unsigned char buffer[64];   /* 被处理的数据块 */

    unsigned char ipad[64];     /* HMAC: 内填充inner padding        */
    unsigned char opad[64];     /* HMAC: 外填充outer padding        */

}
sm3_context;

/**
 *      SM3 上下文设置
 *
 *      参数  ctx      被初始化的上下文
 */
void sm3_starts( sm3_context *ctx );

/**
 *      SM3 缓冲过程
 *
 * 参数 ctx      SM3 上下文
 * 参数 input    承载数据的缓冲区
 * 参数 ilen     input数据的长度
 */
void sm3_update( sm3_context *ctx, unsigned char *input, int ilen );

/**
 *      SM3 最终摘要
 *
 * 参数 ctx      SM3 上下文
 */
void sm3_finish( sm3_context *ctx, unsigned char output[32] );

/**
 *      Output = SM3( input 缓冲内容 )
 *
 * 参数 input    承载数据的缓冲区
 * 参数 ilen     input 数据的长度
 * 参数 output   SM3 校验结果
 */
void sm3( unsigned char *input, int ilen,
           unsigned char output[32]);
```

### 代码实现

```
/*
 * 32-比特 整数操作宏 (大端法)
 */
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}

#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}


/*
 * SM3 上下文设置
 */
void sm3_starts( sm3_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x7380166F;
    ctx->state[1] = 0x4914B2B9;
    ctx->state[2] = 0x172442D7;
    ctx->state[3] = 0xDA8A0600;
    ctx->state[4] = 0xA96F30BC;
    ctx->state[5] = 0x163138AA;
    ctx->state[6] = 0xE38DEE4D;
    ctx->state[7] = 0xB0FB0E4E;

}

static void sm3_process( sm3_context *ctx, unsigned char data[64] )
{
    unsigned long SS1, SS2, TT1, TT2, W[68],W1[64];
    unsigned long A, B, C, D, E, F, G, H;
	unsigned long T[64];
	unsigned long Temp1,Temp2,Temp3,Temp4,Temp5;
	int j;
	int i;
	
	for(j = 0; j < 16; j++)
		T[j] = 0x79CC4519;
	for(j =16; j < 64; j++)
		T[j] = 0x7A879D8A;

//-------消息填充------------

    GET_ULONG_BE( W[ 0], data,  0 );
    GET_ULONG_BE( W[ 1], data,  4 );
    GET_ULONG_BE( W[ 2], data,  8 );
    GET_ULONG_BE( W[ 3], data, 12 );
    GET_ULONG_BE( W[ 4], data, 16 );
    GET_ULONG_BE( W[ 5], data, 20 );
    GET_ULONG_BE( W[ 6], data, 24 );
    GET_ULONG_BE( W[ 7], data, 28 );
    GET_ULONG_BE( W[ 8], data, 32 );
    GET_ULONG_BE( W[ 9], data, 36 );
    GET_ULONG_BE( W[10], data, 40 );
    GET_ULONG_BE( W[11], data, 44 );
    GET_ULONG_BE( W[12], data, 48 );
    GET_ULONG_BE( W[13], data, 52 );
    GET_ULONG_BE( W[14], data, 56 );
    GET_ULONG_BE( W[15], data, 60 );

	//------------------------------
	printf("填充后的消息:\n");
	for(i=0; i< 8; i++)
		printf("%08x ",W[i]);
	printf("\n");
	for(i=8; i< 16; i++)
		printf("%08x ",W[i]);
	printf("\n");
//------------------------------------------------------------

#define FF0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17)) 
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23)) 

//----------消息扩展------------------------------------------
	for(j = 16; j < 68; j++ )
	{		
		Temp1 = W[j-16] ^ W[j-9];
		Temp2 = ROTL(W[j-3],15);
		Temp3 = Temp1 ^ Temp2;
		Temp4 = P1(Temp3);
		Temp5 =  ROTL(W[j - 13],7 ) ^ W[j-6];
		W[j] = Temp4 ^ Temp5;
	}

	printf("扩展后的消息 W0-67:\n");
	for(i=0; i<68; i++)
	{
		printf("%08x ",W[i]);
		if(((i+1) % 8) == 0) printf("\n");
	}
	printf("\n");


	for(j =  0; j < 64; j++)
	{
        W1[j] = W[j] ^ W[j+4];
	}

    printf("扩展后的消息 W'0-63:\n");
	for(i=0; i<64; i++)
	{
		printf("%08x ",W1[i]);
		if(((i+1) % 8) == 0) printf("\n");
	}
	printf("\n");
//--------------------------------------------------------------
//--------迭代压缩-------------------------

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

	printf("迭代压缩中间值:\n");
	printf("j     A       B        C         D         E        F        G       H\n");
	printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",A,B,C,D,E,F,G,H);

	for(j =0; j < 16; j++)
	{
		SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7); 
		SS2 = SS1 ^ ROTL(A,12);
		TT1 = FF0(A,B,C) + D + SS2 + W1[j];
		TT2 = GG0(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTL(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL(F,19);
		F = E;
		E = P0(TT2);

		printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);
	}
	
	for(j =16; j < 64; j++)
	{
		SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7); 
		SS2 = SS1 ^ ROTL(A,12);
		TT1 = FF1(A,B,C) + D + SS2 + W1[j];
		TT2 = GG1(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTL(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL(F,19);
		F = E;
		E = P0(TT2); 

		printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);	
	}

    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H; 
    
	/*
	   printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",ctx->state[0],ctx->state[1],ctx->state[2],
		                          ctx->state[3],ctx->state[4],ctx->state[5],ctx->state[6],ctx->state[7]);*/
}

/*
 * SM3 缓冲过程
 */
void sm3_update( sm3_context *ctx, unsigned char *input, int ilen )
{
    int fill;
    unsigned long left;

    if( ilen <= 0 )
        return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (unsigned long) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, fill );
        sm3_process( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        sm3_process( ctx, input );
        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
    {
        memcpy( (void *) (ctx->buffer + left),
                (void *) input, ilen );
    }
}

static const unsigned char sm3_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SM3 最终摘要
 */
void sm3_finish( sm3_context *ctx, unsigned char output[32] )
{
    unsigned long last, padn;
    unsigned long high, low;
    unsigned char msglen[8];

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_ULONG_BE( high, msglen, 0 );
    PUT_ULONG_BE( low,  msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );


    sm3_update( ctx, (unsigned char *) sm3_padding, padn );
    sm3_update( ctx, msglen, 8 );

    PUT_ULONG_BE( ctx->state[0], output,  0 );
    PUT_ULONG_BE( ctx->state[1], output,  4 );
    PUT_ULONG_BE( ctx->state[2], output,  8 );
    PUT_ULONG_BE( ctx->state[3], output, 12 );
    PUT_ULONG_BE( ctx->state[4], output, 16 );
    PUT_ULONG_BE( ctx->state[5], output, 20 );
    PUT_ULONG_BE( ctx->state[6], output, 24 );
    PUT_ULONG_BE( ctx->state[7], output, 28 );
}

/*
 * output = SM3( input 缓冲内容 )
 */
void sm3( unsigned char *input, int ilen,
           unsigned char output[32] )
{
    sm3_context ctx;

    sm3_starts( &ctx );
    sm3_update( &ctx, input, ilen );
    sm3_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sm3_context ) );//ctx置0
}
```

主函数：

```
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
```

### 运行结果

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181343511-669885373.png)

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181352026-346497202.png)

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181400792-1290594530.png)

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181407198-205219623.png)
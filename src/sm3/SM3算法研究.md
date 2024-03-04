# SM3�����Ӵ��㷨����ѧϰ

## �����붨��

1 ���ش�bit string

��0��1��ɵĶ������������С�

2 ���big-endian

�������ڴ��е�һ�ֱ�ʾ��ʽ���涨���Ϊ����Чλ���ұ�Ϊ����Чλ�����ĸ߽��ֽڷ��ڴ洢���ĵ͵�ַ�����ĵͽ��ֽڷ��ڴ洢���ĸߵ�ַ��

3 ��Ϣmessage

�������޳��ȵı��ش������ı�����Ϣ��Ϊ�Ӵ��㷨���������ݡ�

4 �Ӵ�ֵhash value

�Ӵ��㷨��������Ϣ��������ض����ȵı��ش������ı��е��Ӵ�ֵ����Ϊ256���ء�

5 ��word

����Ϊ32�ı��ش�

## ����

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204180733261-837668677.png)

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204180746089-1660458826.png)



## �����뺯��

1
![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204180800620-1277777528.png)

2
![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204180823104-91079963.png)

3
![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204180841979-1054474866.png)

4
![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204180859370-1920728129.png)


## �㷨����

### ����

�Գ���Ϊl(l < 2^64) ���ص���Ϣm�� SM3�Ӵ��㷨�������͵���ѹ���������Ӵ�ֵ���Ӵ�ֵ����
Ϊ256����

### ���

������Ϣm �ĳ���Ϊl ���ء����Ƚ����ء� 1����ӵ���Ϣ��ĩβ�������k ���� 0���� k����
��l + 1 + k �� 448mod512 ����С�ķǸ�������Ȼ�������һ��64λ���ش����ñ��ش��ǳ���l�Ķ���
�Ʊ�ʾ���������Ϣm�� �ı��س���Ϊ512�ı�����

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204180935354-802455231.png)

### ����ѹ��

1 ��������

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181101354-140470353.png)

2 ��Ϣ��չ

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181140573-1088184788.png)

3 ѹ������

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181203573-1186421667.png)



ѹ��������ͼ

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181219776-719227816.jpg)

���У��ֵĴ洢Ϊ���(big-endian)��ʽ

4 �Ӵ�ֵ

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181243933-829416454.png)

## C����ʵ��

### ������ṹ�嶨��

```
/**
 *  SM3 �����Ľṹ��
 */
typedef struct
{
    unsigned long total[2];     /* ��������ֽ���  */
    unsigned long state[8];     /* �м�ժҪ state  */
    unsigned char buffer[64];   /* ����������ݿ� */

    unsigned char ipad[64];     /* HMAC: �����inner padding        */
    unsigned char opad[64];     /* HMAC: �����outer padding        */

}
sm3_context;

/**
 *      SM3 ����������
 *
 *      ����  ctx      ����ʼ����������
 */
void sm3_starts( sm3_context *ctx );

/**
 *      SM3 �������
 *
 * ���� ctx      SM3 ������
 * ���� input    �������ݵĻ�����
 * ���� ilen     input���ݵĳ���
 */
void sm3_update( sm3_context *ctx, unsigned char *input, int ilen );

/**
 *      SM3 ����ժҪ
 *
 * ���� ctx      SM3 ������
 */
void sm3_finish( sm3_context *ctx, unsigned char output[32] );

/**
 *      Output = SM3( input �������� )
 *
 * ���� input    �������ݵĻ�����
 * ���� ilen     input ���ݵĳ���
 * ���� output   SM3 У����
 */
void sm3( unsigned char *input, int ilen,
           unsigned char output[32]);
```

### ����ʵ��

```
/*
 * 32-���� ���������� (��˷�)
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
 * SM3 ����������
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

//-------��Ϣ���------------

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
	printf("�������Ϣ:\n");
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

//----------��Ϣ��չ------------------------------------------
	for(j = 16; j < 68; j++ )
	{		
		Temp1 = W[j-16] ^ W[j-9];
		Temp2 = ROTL(W[j-3],15);
		Temp3 = Temp1 ^ Temp2;
		Temp4 = P1(Temp3);
		Temp5 =  ROTL(W[j - 13],7 ) ^ W[j-6];
		W[j] = Temp4 ^ Temp5;
	}

	printf("��չ�����Ϣ W0-67:\n");
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

    printf("��չ�����Ϣ W'0-63:\n");
	for(i=0; i<64; i++)
	{
		printf("%08x ",W1[i]);
		if(((i+1) % 8) == 0) printf("\n");
	}
	printf("\n");
//--------------------------------------------------------------
//--------����ѹ��-------------------------

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

	printf("����ѹ���м�ֵ:\n");
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
 * SM3 �������
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
 * SM3 ����ժҪ
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
 * output = SM3( input �������� )
 */
void sm3( unsigned char *input, int ilen,
           unsigned char output[32] )
{
    sm3_context ctx;

    sm3_starts( &ctx );
    sm3_update( &ctx, input, ilen );
    sm3_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sm3_context ) );//ctx��0
}
```

��������

```
int main( int argc, char *argv[] )
{
	unsigned char *input = "abc";
	int ilen = 3;
	unsigned char output[32];
	int i;
	sm3_context ctx;

	//--------------------------------------------------
	printf("������Ϣ:\n");
	printf("%s\n",input);

	sm3(input, ilen, output);//����sm3�㷨����

	printf("�Ӵ�ֵ:\n   ");
    for(i=0; i<32; i++)
	{
		printf("%02x",output[i]);
		if (((i+1) % 4 ) == 0) printf(" ");
	} 
	printf("\n");
	printf("---------------------------------------------------------------------------\n");
	//--------------------------------------------------
    
	printf("������Ϣ:\n");
	for(i=0; i < 16; i++)
		printf("abcd");
	printf("\n");


    sm3_starts( &ctx );
	for(i=0; i < 16; i++)
		sm3_update( &ctx, "abcd", 4 );
    sm3_finish( &ctx, output );

    memset( &ctx, 0, sizeof( sm3_context ) );//ctx��0
	

	printf("�Ӵ�ֵ:\n   ");
	for(i=0; i<32; i++)
	{
		printf("%02x",output[i]);
		if (((i+1) % 4 ) == 0) printf(" ");
	}   
	printf("\n"); 
}
```

### ���н��

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181343511-669885373.png)

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181352026-346497202.png)

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181400792-1290594530.png)

![](http://images2015.cnblogs.com/blog/810693/201702/810693-20170204181407198-205219623.png)
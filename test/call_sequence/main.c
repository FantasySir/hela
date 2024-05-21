#include "../../src/data_dealer.h"
#include "../../src/sm3.h"

int main(void)
{
	SEQ **syscall_seq = (SEQ **)malloc(sizeof(SEQ*) * 100);
	con_syscall_init(syscall_seq, 8, 2);
	char *cs = (char *)malloc(sizeof(char) * 25);
	unsigned char dig_s[65]= { 0 };
	int diff_point = 0;

	int i;

	char *test_s = "101102103104105106107108";
	char test_dig[65];
	digest_gen(test_s, 24, test_dig);

	for (i = 100; i < 140; ++i) {
		update_syscall_seq(syscall_seq[0], i);
		if (queueIsFull(syscall_seq[0])) {
			int len = combine_sequence(syscall_seq[0], &cs);
			digest_gen(cs, len, dig_s);
			printf("digest: %s\n", dig_s);
			if (strcmp(test_dig, dig_s) != 0) {
				diff_point++;
			}
		}
	}
	if (diff_point > 4) {
		printf("近20次调用出现严重偏差！，偏差值：%s! 请求终止容器！\n", "19/20");
	}


	return 0;
}
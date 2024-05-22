#ifndef DATA_DEALER__H
#define DATA_DEALER__H

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>

// #include "sm3.h"


#define CHECKBATCH 24

/* Queue */

struct queue {
	int *data;
	int size;	// 队列容量
	int front;
	int rear;
	int checkCount;
	int deviation;
};

typedef struct queue SEQ;

static int queueNext(struct queue *q, int idx)
{
	return (idx + 1) % (q->size + 1);
}

int queueIsFull(struct queue *q) {
	int r_next = queueNext(q, q->rear);
	return r_next == q->front;
}


int queueAppend(struct queue *q, int data)
{
	if (queueIsFull(q)) {
		q->front = queueNext(q, q->front);
	}
	if (q->size < 1) {
		return 0;
	}
	q->data[q->rear] = data;
	q->rear = queueNext(q, q->rear);

	return 1;
}

/* Queue end */

// int push_data_to_prometheus(char *target_url, void *event)
// {
// 	CURL *curl;
// 	CURLcode res;
// 	char post_data[512];
	
// 	/* format data to push */
	
// }


/* syscall data dealer*/


/**
 * @description: 初始化系统调用序列
 * @param {SEQ} **syscall_seq 所有系统调用序列组，每个syscall_seq都是某个容器的系统调用序列
 * @param {int} syscall_seq_cap 系统调用序列最大大小，即系统调用到几个时进行一次结算
 * @param {int} syscall_seq_size 容器数量，有多少容器就有多少系统调用序列
 * @return {*}
 */
void con_syscall_init(SEQ **syscall_seq, int syscall_seq_cap, int syscall_seq_size)
{
        int i;

	for (i = 0; i < syscall_seq_size; ++i) {
		syscall_seq[i] = (SEQ *)malloc(sizeof(SEQ));
		syscall_seq[i]->front = syscall_seq[i]->rear = 0;
		syscall_seq[i]->data = (int *)malloc(sizeof(int) * (syscall_seq_cap + 1));
		syscall_seq[i]->size = syscall_seq_cap;
		syscall_seq[i]->checkCount = 0;
		syscall_seq[i]->deviation = 0;
	}
}

int update_syscall_seq(SEQ *syscall_seq, int new_syscall)
{
	int ret = queueAppend(syscall_seq, new_syscall);
	syscall_seq->checkCount++;
	return ret;
}

int sequence_batch_check(SEQ *syscall_seq)
{
	return syscall_seq->checkCount >= CHECKBATCH;
}

int add_deviation(SEQ *syscall_seq)
{
	syscall_seq->deviation++;
	return syscall_seq->deviation;
}

/**
 * @description: 合并系统调用序列
 * @param {SEQ} *syscall_seq 系统调用序列
 * @param {char} **out_seq 合并结果，作为返回值
 * @return {*} 合并后长度
 */
int combine_sequence(SEQ *syscall_seq, char **out_seq)
{
	int c_p = syscall_seq->front;
	int s_p = 0;
	char *seq_combine = *out_seq;
	// printf("q front is : %d\n", syscall_seq->data[syscall_seq->front]);
	if (queueIsFull(syscall_seq)) {
		// 融合序列为string
		while (c_p != syscall_seq->rear) {
			if (syscall_seq->data[c_p] > 1000) {
				return 0;
			} else if (syscall_seq->data[c_p] >= 100) { // 3个数
				int i;
				int num = syscall_seq->data[c_p];
				int temp;
				for (i = 0; i < 3; ++i) {
					temp = num % 10;
					num = num / 10;
					seq_combine[s_p + 2 - i] = temp + '0';
				}
				s_p += 3;
			} else if (syscall_seq->data[c_p] >= 10) { // 2个数
				int i;
				int num = syscall_seq->data[c_p];
				int temp;
				for (i = 0; i < 2; ++i) {
					temp = num % 10;
					num = num / 10;
					seq_combine[s_p + 1 - i] = temp + '0';
				}
				s_p += 2;
			} else { // 1个数
				seq_combine[s_p] = syscall_seq->data[c_p] + '0';
				s_p += 1;
			}
			c_p = queueNext(syscall_seq, c_p);
		}
		seq_combine[s_p] = '\0';
	}
	return s_p;		
}

void digest_gen(char *in, int len, unsigned char out[64]) 
{
	unsigned char digest[32];
	unsigned char *ori_msg = (unsigned char *)in;
	sm3_once_calcu(ori_msg, len, digest);
	sm3_hexdigest(digest, out);
}



void freeSeq(SEQ **syscall_seq, int syscall_seq_cap, int syscall_seq_size)
{
        int i;

	for (i = 0; i < syscall_seq_size; ++i) {
		free(syscall_seq[i]->data);
		free(syscall_seq[i]);
	}
}

/* syscall data dealer end*/

#endif // !DATA_DEALER__H
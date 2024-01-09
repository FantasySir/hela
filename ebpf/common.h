/*
 Copyright (c) 2023 Broin All rights reserved.
 Use of this source code is governed by a BSD-style
 license that can be found in the LICENSE file.
 */

#ifndef COMMON__H
#define COMMON__H

#include <stdarg.h>
#include <stdio.h>
#define SUCCESS 1
#define FAIL 0

/* Color format */
#ifndef ANSI_COLOR
#define ANSI_COLOR

#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_RESET "\x1b[0m"

#endif // !ANSI_COLOR

int hela_error(const char *fmt, ...) {
  char printf_buf[1034];
  va_list args;
  int printed;

  // For error only
  const char *error_prefix = COLOR_RED "[ERROR]: " COLOR_RESET;
  int prefix_length = snprintf(printf_buf, sizeof(printf_buf), "%s", error_prefix);

  va_start(args, fmt);
  // 注意使用vsnprintf而不是vsprintf来避免潜在的缓冲区溢出
  printed = vsnprintf(printf_buf + prefix_length, sizeof(printf_buf) - prefix_length, fmt, args);
  va_end(args);

  // 如果vsnprintf返回的值大于或等于缓冲区大小，则输出被截断
  if (printed >= sizeof(printf_buf) - prefix_length) {
    printf_buf[sizeof(printf_buf) - 1] = '\0'; // 确保字符串结束符
    printed = sizeof(printf_buf) - prefix_length - 1;
  }

  puts(printf_buf);
  return printed; // 返回格式化后的文本长度（不包括前缀）
}


int hela_info(const char *fmt, ...) {
  char printf_buf[1034];
  va_list args;
  int printed;

  // For infomation only
  const char *info_prefix = COLOR_GREEN "[INFO]: " COLOR_RESET;
  int prefix_length = snprintf(printf_buf, sizeof(printf_buf), "%s", info_prefix);

  va_start(args, fmt);
  // 注意使用vsnprintf而不是vsprintf来避免潜在的缓冲区溢出
  printed = vsnprintf(printf_buf + prefix_length, sizeof(printf_buf) - prefix_length, fmt, args);
  va_end(args);

  // 如果vsnprintf返回的值大于或等于缓冲区大小，则输出被截断
  if (printed >= sizeof(printf_buf) - prefix_length) {
    printf_buf[sizeof(printf_buf) - 1] = '\0'; // 确保字符串结束符
    printed = sizeof(printf_buf) - prefix_length - 1;
  }

  puts(printf_buf);
  return printed; // 返回格式化后的文本长度（不包括前缀）
}

#endif //  COMMON__H
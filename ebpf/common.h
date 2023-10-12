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

int error(const char *fmt, ...) {
  char printf_buf[1034];
  va_list args;
  int printed;

  // For error only
  int i;
  char s[10] = "[ERROR]: ";
  for (i = 0; i < 9; ++i) {
    printf_buf[i] = s[i];
  }

  va_start(args, fmt);
  printed = vsprintf(printf_buf + 9, fmt, args);
  va_end(args);

  puts(printf_buf);
  return printed;
}

#endif //  COMMON__H
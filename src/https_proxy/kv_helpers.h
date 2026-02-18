#ifndef KV_HELPERS_H
#define KV_HELPERS_H

#include "kvec.h"
#include "string.h"
#include <stdio.h>

typedef kvec_t(unsigned char) byte_array;

static inline void kv_push_bytes(byte_array *v, const void *src, size_t len) {
  size_t new_n = v->n + len;
  if (new_n > v->m) {
    kv_resize(unsigned char, *v, new_n);
  }
  memcpy(v->a + v->n, src, len);
  v->n = new_n;
}

static inline void kv_erase_bytes(byte_array *v, size_t off, size_t len) {
  memmove(v->a + off, v->a + off + len, v->n - (off + len));
  v->n -= len;
}

static inline void kv_move_bytes(byte_array *from, byte_array *to, size_t len) {
  kv_push_bytes(to, from->a, len);
  kv_erase_bytes(from, 0, len);
}

static inline void kv_copy_bytes(byte_array *from, byte_array *to, size_t len){
  kv_push_bytes(to, from->a, len);
}

static inline void kv_print_bytes(byte_array *b) {
  char tmp[b->n+1];
  tmp[b->n] = '\0';
  memcpy(tmp, b->a, b->n);
  printf(tmp);
  printf("\n");
  return; 
}

#endif

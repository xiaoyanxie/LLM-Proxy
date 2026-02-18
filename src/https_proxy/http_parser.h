#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include <stdlib.h>
#include <ctype.h>
#include "kv_helpers.h" 

typedef enum {
  HTC_STATE_HEADERS = 1,
  HTC_STATE_BODY_WITH_CLEN,
  HTC_STATE_CHUNKED,
  HTC_STATE_READ_UNTIL_CLOSED,
  HTC_STATE_DONE
} http_transfer_state_enum;

typedef enum {
  DEC_STATE_SIZE = 0,
  DEC_STATE_DATA,
  DEC_STATE_DATA_CRLF,
  DEC_STATE_TRAILERS,
  DEC_STATE_DONE
} chunk_decoder_state_enum;

typedef struct {
  size_t chunk_size;
  size_t chunk_bytes_read;
  size_t off;
  int state;
  int done;
} chunk_decoder;

typedef enum {
  HTTP_MSG_RESPONSE = 0,
  HTTP_MSG_REQUEST  = 1
} http_msg_kind;

typedef struct parse_header_result {
  int has_content_length;
  size_t content_length;
  int is_chunked;
  int has_body;

  http_msg_kind kind;
  int status_code;
  char method[16];
  char target[256];
  char host[256];
  char full_url[512];

  int is_html;
} parse_header_result;

typedef struct {
    http_transfer_state_enum state;
    size_t header_scan_offset;
    size_t body_remaining_len;
    chunk_decoder chunk_dec;
    parse_header_result header_result; // last parsed header
    byte_array http_resp_buf;
} http_parser;

void http_parser_init(http_parser *p);
void http_parser_reset(http_parser *p);
void http_parser_free(http_parser *p);
int http_parser_process(http_parser *p,
                        byte_array *in,
                        http_msg_kind kind,
                        int (*done_callback)(byte_array*, parse_header_result*, void*),
                        void* u_ptr);
#endif 
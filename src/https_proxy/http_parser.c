#include "http_parser.h"
#include "kv_helpers.h"
#include "kvec.h"
#include <stdio.h>

static int hex2digit(unsigned char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}

char *trim_inplace(char *s) {
  if (!s)
  return NULL;
  
  char *start = s;
  char *end;
  while (*start && isspace((unsigned char)*start)) {
    start++;
  }
  if (*start == '\0') {
    s[0] = '\0';
    return s;
  }
  end = start + strlen(start) - 1;
  while (end > start && isspace((unsigned char)*end)) {
    end--;
  }
  *(end + 1) = '\0';
  if (start != s) {
    memmove(s, start, (end + 2) - start);
  }
  
  return s;
}

void http_parser_init(http_parser *p) {
  p->state = HTC_STATE_HEADERS;
  p->header_scan_offset = 0;
  p->body_remaining_len = 0;
  kv_init(p->http_resp_buf);
  memset(&p->chunk_dec, 0, sizeof(p->chunk_dec));
}

void http_parser_reset(http_parser *p) {
  p->state = HTC_STATE_HEADERS;
  p->header_scan_offset = 0;
  p->body_remaining_len = 0;
  p->http_resp_buf.n = 0;
  memset(&p->chunk_dec, 0, sizeof(p->chunk_dec));
}

void http_parser_free(http_parser *p) {
  kv_destroy(p->http_resp_buf);
}


void parse_header(unsigned char *header,
                  size_t header_size,
                  http_msg_kind kind,
                  parse_header_result *res)
{
  // reset result
  res->has_content_length = 0;
  res->content_length     = 0;
  res->is_chunked         = 0;
  res->has_body           = 0;
  res->is_html            = 0;
  res->status_code        = 0;
  res->kind               = kind;

  if (kind == HTTP_MSG_REQUEST) {
    res->method[0]   = '\0';
    res->target[0]   = '\0';
    res->host[0]     = '\0';   // NEW
    res->full_url[0] = '\0';   // NEW
  }

  unsigned char *sol = header;
  size_t bytes_parsed = 0;

  // ---- 1) find end of start line ----
  unsigned char *eol = memmem(sol, header_size, "\r\n", 2);
  if (!eol) {
    return; // incomplete header
  }

  size_t line_len = (size_t)(eol - sol);
  char   start_line[line_len + 1];
  memcpy(start_line, sol, line_len);
  start_line[line_len] = '\0';

  // ---- 2) parse start line depending on kind ----
  if (kind == HTTP_MSG_RESPONSE) {
    // e.g. "HTTP/1.1 200 OK"
    char ver[16];
    int code = 0;
    if (sscanf(start_line, "%15s %d", ver, &code) == 2) {
      res->status_code = code;
    }

    if ((res->status_code >= 100 && res->status_code < 200) ||
        res->status_code == 204 || res->status_code == 304) {
      res->has_body = 0;
    } else {
      res->has_body = 1;
    }

  } else { // HTTP_MSG_REQUEST
    // e.g. "GET /path HTTP/1.1" or "GET https://example.com/path HTTP/1.1"
    char method[16]  = {0};
    char target[256] = {0};
    char ver[16]     = {0};

    if (sscanf(start_line, "%15s %255s %15s", method, target, ver) >= 2) {
      strncpy(res->method, method, sizeof(res->method) - 1);
      res->method[sizeof(res->method) - 1] = '\0';

      strncpy(res->target, target, sizeof(res->target) - 1);
      res->target[sizeof(res->target) - 1] = '\0';
    }

    res->has_body = 0;
  }

  bytes_parsed += (eol - sol + 2);
  sol = eol + 2;

  // ---- 3) parse header fields ----
  while (bytes_parsed < header_size) {
    eol = memmem(sol, header_size - bytes_parsed, "\r\n", 2);
    if (!eol) {
      return; // header truncated
    }
    size_t line_size = (size_t)(eol - sol) + 2;
    bytes_parsed += line_size;

    // blank line = end of headers
    if (line_size == 2) {
      sol = eol + 2;
      break;
    }

    unsigned char *colon = memchr(sol, ':', line_size);
    if (!colon) {
      sol = eol + 2;
      continue;
    }

    size_t name_size  = (size_t)(colon - sol);
    size_t value_size = line_size - name_size - 2 - 1; // minus ':' and "\r\n"

    char name[name_size + 1];
    char value[value_size + 1];
    name[name_size]   = '\0';
    value[value_size] = '\0';

    memcpy(name,  sol,           name_size);
    memcpy(value, colon + 1,     value_size);
    trim_inplace(value);  // trims leading/trailing spaces

    if (strcasecmp(name, "Content-Length") == 0) {
      res->has_content_length = 1;
      res->content_length = (size_t)atoi(value);

    } else if (strcasecmp(name, "Transfer-Encoding") == 0) {
      if (strcasestr(value, "chunked") != NULL) {
        res->is_chunked = 1;
      }

    } else if (strcasecmp(name, "Content-Type") == 0) {
      if (strstr(value, "text/html") != NULL ||
          strstr(value, "application/xhtml+xml") != NULL) {
        res->is_html = 1;
      }

    } else if (kind == HTTP_MSG_REQUEST &&
               strcasecmp(name, "Host") == 0) {
      // NEW: capture Host header (no scheme)
      strncpy(res->host, value, sizeof(res->host) - 1);
      res->host[sizeof(res->host) - 1] = '\0';
    }

    sol = eol + 2;
  }

  // ---- 4) final has_body decision ----
  if (kind == HTTP_MSG_RESPONSE) {
    if ((res->status_code >= 100 && res->status_code < 200) ||
        res->status_code == 204 || res->status_code == 304) {
      res->has_body = 0;
    } else if (res->is_chunked || res->has_content_length) {
      res->has_body = 1;
    } else {
      res->has_body = 1; // read-until-close
    }

  } else { // HTTP_MSG_REQUEST
    if (res->is_chunked || res->has_content_length) {
      res->has_body = 1;
    } else {
      res->has_body = 0;
    }
  }

  // ---- 5) build full_url for requests (optional but useful) ----
  if (kind == HTTP_MSG_REQUEST) {
    // If target is already absolute (http:// or https://), just copy it
    if (strncmp(res->target, "http://", 7) == 0 ||
        strncmp(res->target, "https://", 8) == 0) {
      strncpy(res->full_url, res->target, sizeof(res->full_url) - 1);
      res->full_url[sizeof(res->full_url) - 1] = '\0';
    } else if (res->host[0] != '\0' && res->target[0] != '\0') {
      // origin-form like "/path" + Host header → reconstruct absolute URL
      // for an HTTPS MITM proxy it's reasonable to assume "https://"
      const char *scheme = "https://";

      char path_buf[256];
      // ensure target starts with '/'
      if (res->target[0] == '/') {
        strncpy(path_buf, res->target, sizeof(path_buf) - 1);
        path_buf[sizeof(path_buf) - 1] = '\0';
      } else {
        // prepend '/'
        snprintf(path_buf, sizeof(path_buf), "/%s", res->target);
      }

      snprintf(res->full_url,
               sizeof(res->full_url),
               "%s%s%s",
               scheme,
               res->host,
               path_buf);
    } else {
      // fallback: no host or target, leave full_url empty
      res->full_url[0] = '\0';
    }
  }
}


int parse_chunk_size(unsigned char *line, size_t line_size) {
  size_t i = 0;
  size_t value = 0;
  int digits = 0;
  while (i < line_size && (line[i] == ' ' || line[i] == '\t')) {
    i++;
  }
  for (; i < line_size; ++i) {
    unsigned char c = line[i];
    int d = hex2digit(c);
    if (d >= 0) {
      value = (value << 4) | (size_t)d;
      digits++;
    } else {
      break;
    }
  }
  if (digits == 0) {
    return -1;
  }
  return value;
}

int parse_chunk(chunk_decoder *dec, byte_array *in) {
  // printf("Dec: %ld, %ld, %d, %ld, %d\n", dec->chunk_bytes_read,
  // dec->chunk_size, dec->done, dec->off, dec->state);
  size_t unread = in->n - dec->off;
  while (!dec->done) {
    if (dec->state == DEC_STATE_SIZE) {
      unread = in->n - dec->off;
      unsigned char *sol = in->a + dec->off;
      unsigned char *eol = memmem(sol, unread, "\r\n", 2);
      if (eol == NULL) {
        return 0;
      }
      size_t line_size = eol - sol;
      int chunk_size = parse_chunk_size(sol, line_size);
      if (chunk_size < 0) {
        return 1;
      }
      dec->chunk_size = chunk_size;
      dec->chunk_bytes_read = 0;
      if (chunk_size == 0) {
        dec->state = DEC_STATE_TRAILERS;
      } else {
        dec->state = DEC_STATE_DATA;
      }
      dec->off = (eol + 2) - in->a;
    }
    
    if (dec->state == DEC_STATE_DATA) {
      unread = in->n - dec->off;
      if (unread == 0) { // no data beyond off
        return 0;
      }
      size_t remaining_in_chunk = dec->chunk_size - dec->chunk_bytes_read;
      if (remaining_in_chunk > unread) {
        dec->off += unread;
        dec->chunk_bytes_read += unread;
        return 0;
      }
      dec->off += remaining_in_chunk;
      dec->chunk_bytes_read += remaining_in_chunk;
      dec->state = DEC_STATE_DATA_CRLF;
      continue;
    }
    
    if (dec->state == DEC_STATE_DATA_CRLF) {
      unread = in->n - dec->off;
      if (unread < 2) {
        return 0;
      }
      if (!(in->a[dec->off] == '\r' && in->a[dec->off + 1] == '\n')) {
        return 1;
      }
      dec->off += 2;
      dec->state = DEC_STATE_SIZE;
      continue;
    }
    
    if (dec->state == DEC_STATE_TRAILERS) {
      unread = in->n - dec->off;
      if (unread < 2) {
        return 0;
      }
      unsigned char *sol = in->a + dec->off;
      unsigned char *eol = memmem(sol, unread, "\r\n", 2);
      if (!eol) {
        return 0;
      }
      
      size_t line_len = eol - sol;
      
      if (line_len == 0) {
        dec->off += 2;
        dec->state = DEC_STATE_DONE;
        dec->done = 1;
        return 0;
      } else {
        dec->off += line_len + 2;
      }
    }
  }
  return 0;
}

// parse the part of IN that forms a full http response into resp_buf, and after full response is parsed=
// call DONE_CALLBACK with (OUT, U_PTR)
int http_parser_process(http_parser *p, byte_array *in, http_msg_kind kind,
  int (*done_callback)(byte_array*, parse_header_result*, void*), void* u_ptr) {
    while (1) {
      if (p->state == HTC_STATE_HEADERS) {
        size_t off = p->header_scan_offset;
        if (in->n <= off) return 0;
        
        size_t unscanned = in->n - off;
        unsigned char *end_of_header =
        memmem(in->a + off, unscanned, "\r\n\r\n", 4);
        if (!end_of_header) {
          if (in->n < 4) return 0;
          p->header_scan_offset = in->n - 4;
          return 0;
        }
        
        unsigned char *start = in->a;
        size_t header_size = (end_of_header - start) + 4;
        
        parse_header_result* res = &(p->header_result);
        parse_header(start, header_size, kind, res);
        
        // // build modified header with X-Proxy
        // unsigned char modified_header[header_size + 15];
        // memcpy(modified_header, start, header_size - 2);
        // memcpy(modified_header + header_size - 2, "X-Proxy:CS112\r\n", 15);
        // memcpy(modified_header + header_size + 13, "\r\n", 2);
        
        kv_move_bytes(in, &p->http_resp_buf, header_size);

        p->header_scan_offset = 0;
        
        if (!res->has_body) {
          p->state = HTC_STATE_DONE;
        } else if (res->is_chunked) {
          p->state = HTC_STATE_CHUNKED;
        } else if (res->has_content_length) {
          p->body_remaining_len = res->content_length;
          p->state = (p->body_remaining_len == 0)
          ? HTC_STATE_DONE
          : HTC_STATE_BODY_WITH_CLEN;
        } else {
          p->state = HTC_STATE_READ_UNTIL_CLOSED;
        }
        continue;
      }
      
      if (p->state == HTC_STATE_READ_UNTIL_CLOSED) {
        if (in->n == 0) return 0;
        kv_move_bytes(in, &p->http_resp_buf, in->n);
        return 0;
      }
      
      if (p->state == HTC_STATE_BODY_WITH_CLEN) {
        if (in->n == 0) return 0;
        size_t to_move = p->body_remaining_len < in->n
        ? p->body_remaining_len
        : in->n;
        if (to_move > 0) {
          kv_move_bytes(in, &p->http_resp_buf, to_move);
          p->body_remaining_len -= to_move;
        }
        if (p->body_remaining_len == 0) {
          p->state = HTC_STATE_DONE;
          continue;
        }
        return 0;
      }
      
      if (p->state == HTC_STATE_CHUNKED) {
        int status = parse_chunk(&p->chunk_dec, in);
        if (status > 0) {
          return 1;
        }
        size_t consumed = p->chunk_dec.off;
        if (consumed > 0) {
          kv_move_bytes(in, &p->http_resp_buf, consumed);
          p->chunk_dec.off -= consumed;
        }
        if (p->chunk_dec.done) {
          p->state = HTC_STATE_DONE;
          continue;
        }
        return 0;
      }
      
      if (p->state == HTC_STATE_DONE) {
        if (done_callback != NULL){
          if (done_callback(&p->http_resp_buf, &p->header_result, u_ptr) != 0) {
            return 1;
          }
        }
        http_parser_reset(p);
        continue; // ready for next response on this connection
      }
    }
  }
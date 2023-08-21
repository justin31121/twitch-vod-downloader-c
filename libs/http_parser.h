#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

// TODO: Do something about content_length. Do not recompute the size every time

#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>

#ifdef HTTP_PARSER_VERBOSE
#  include <stdio.h>
#  define HTTP_PARSER_LOG(...) do{ fprintf(stderr, "HTTP_PARSER: " __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#else
#  define HTTP_PARSER_LOG(...)
#endif //HTTP_PARSER_VERBOSE

#ifndef HTTP_PARSER_DEF
#  define HTTP_PARSER_DEF static inline
#endif //HTTP_PARSER_DEF

typedef enum{
  HTTP_PARSER_RET_ABORT = 0,
  HTTP_PARSER_RET_CONTINUE = 1,
  HTTP_PARSER_RET_SUCCESS = 2,
}Http_Parser_Ret;

typedef Http_Parser_Ret (*Http_Parser_Write_Callback)(void *userdata, const char *data, size_t size);

typedef struct{
  const char *data;
  size_t len;
}Http_Parser_String;

typedef bool (*Http_Parser_Header_Callback)(void *userdata, Http_Parser_String key, Http_Parser_String value);

typedef enum{
  // initial state
  HTTP_PARSER_STATE_IDLE = 0,
    
  HTTP_PARSER_STATE_IN_HEADER,

  // either way of size-information was found
  HTTP_PARSER_STATE_IN_HEADER_CONTENT_LENGTH,
  HTTP_PARSER_STATE_IN_HEADER_CHUNKED,

  // content-length
  HTTP_PARSER_STATE_CONTENT_LENGTH,

  // chunked
  HTTP_PARSER_STATE_CHUNKED_CONSUME,
  HTTP_PARSER_STATE_CHUNKED,
}Http_Parser_State;

typedef struct{
  Http_Parser_Write_Callback callback;
  Http_Parser_Header_Callback header_callback;
  void *userdata;
  Http_Parser_State state;

  int64_t content_length;
  int64_t bytes_to_read;
  int response_code;
}Http_Parser;

// Public
HTTP_PARSER_DEF Http_Parser http_parser(Http_Parser_Write_Callback callback, Http_Parser_Header_Callback, void *userdata);
HTTP_PARSER_DEF Http_Parser_Ret http_parser_consume(Http_Parser *parser, const char *data, size_t size);
HTTP_PARSER_DEF bool http_parser_dump(void *userdata, Http_Parser_String key, Http_Parser_String value);

// Private
HTTP_PARSER_DEF Http_Parser_Ret http_parser_consume_headers(Http_Parser *parser, Http_Parser_String s);
HTTP_PARSER_DEF Http_Parser_String http_parser_string_chop_by_delim(Http_Parser_String *s, char delim);
HTTP_PARSER_DEF Http_Parser_String http_parser_string_trim(Http_Parser_String s);
bool http_parser_string_eq(Http_Parser_String s, const char *cstr);
HTTP_PARSER_DEF bool http_parser_string_chop_int64_t(Http_Parser_String *s, int64_t *n);
HTTP_PARSER_DEF bool http_parser_string_chop_hex(Http_Parser_String *s, int64_t *n);

#ifdef HTTP_PARSER_IMPLEMENTATION

static const char *http_parser_string_cstr_content_length = "content-length";
static const char *http_parser_string_cstr_transfer_encoding = "transfer-encoding";
static const char *http_parser_string_cstr_chunked = "chunked";

static const char *http_parser_string_cstr_http1 = "HTTP/1.1 ";

HTTP_PARSER_DEF Http_Parser http_parser(Http_Parser_Write_Callback callback, Http_Parser_Header_Callback header_callback, void *userdata) {
  Http_Parser parser = {0};
  parser.callback = callback;
  parser.header_callback = header_callback;
  parser.userdata = userdata;
  parser.state = HTTP_PARSER_STATE_IDLE;
  return parser;
}

HTTP_PARSER_DEF bool http_parser_string_eq_impl(Http_Parser_String s, const char *cstr, size_t cstr_len) {

  if(s.len != cstr_len )
      return false;

  for(size_t i=0;i<cstr_len;i++) {
    char src = cstr[i];
    char dst = s.data[i];

    if('A' <= dst && dst <= 'Z' &&
       'a' <= src && src <= 'z') {
      src -= 32; // 'a' -> 'A'
    }
    
    if(src != dst) {
      return false;
    }
      
  }

  return true;
}

#define http_parser_string_eq(s, cstr)				\
  http_parser_string_eq_impl((s), (cstr), ( strlen((cstr)) ) )

// only gets called in either HTTP_PARSER_STATE_IN_HEADER_CONTENT_LENGTH
// or HTTP_PARSER_STATE_IN_HEADER_CHUNKED
HTTP_PARSER_DEF Http_Parser_Ret http_parser_consume_headers(Http_Parser *parser, Http_Parser_String s) {
  Http_Parser_String line, key, value;
  while(s.len) {
    line = http_parser_string_chop_by_delim(&s, '\n');
    if(line.len && line.data[0] == '\r') {

      if(!parser->callback) {
	return HTTP_PARSER_RET_SUCCESS;
      }
	    
      if(parser->state == HTTP_PARSER_STATE_IN_HEADER_CONTENT_LENGTH) {		       	parser->state = HTTP_PARSER_STATE_CONTENT_LENGTH;
      } else {
	parser->state = HTTP_PARSER_STATE_CHUNKED;
      }
	
      if(s.len)
	return http_parser_consume(parser, s.data, s.len);
    }

    key = http_parser_string_trim(http_parser_string_chop_by_delim(&line, ':'));
    value = http_parser_string_trim(line);

    if(parser->header_callback) {
      if(!parser->header_callback(parser->userdata, key, value)) {
	HTTP_PARSER_LOG("Failure because 'header_callback' return false");
	return HTTP_PARSER_RET_ABORT;
      }
    }

    if(parser->state == HTTP_PARSER_STATE_IN_HEADER_CONTENT_LENGTH) {
      if( http_parser_string_eq(key, http_parser_string_cstr_transfer_encoding) &&
	  http_parser_string_eq(value, http_parser_string_cstr_chunked)) {
	// invalid state. content length + encoding chunked
	HTTP_PARSER_LOG("The Response supplied 'content-length' and 'trasnfer-encoding: chunked'");
	return HTTP_PARSER_RET_ABORT;
      }      
    } else {
      if( http_parser_string_eq(key, http_parser_string_cstr_content_length)) {
	HTTP_PARSER_LOG("The Response supplied 'content-length' and 'trasnfer-encoding: chunked'");
	// invalid state. content length + encoding chunked
	return HTTP_PARSER_RET_ABORT;
      }
    }
      
  }
  return HTTP_PARSER_RET_CONTINUE;
}

HTTP_PARSER_DEF bool http_parser_dump(void *userdata, Http_Parser_String key, Http_Parser_String value) {
  (void) userdata;
  fprintf(stderr, "%.*s: %.*s\n", (int) key.len, key.data, (int) value.len, value.data); fflush(stderr);
  return true;
}

// TODO: Maybe fix this

// For simplicity this functions expects that the headers are provided via one
// consume-call.

// TODO: There is some duplicate code
HTTP_PARSER_DEF Http_Parser_Ret http_parser_consume(Http_Parser *parser, const char *data, size_t size) {

 consume:
  switch(parser->state) {
  case HTTP_PARSER_STATE_IDLE: {
    size_t http_start_len = strlen(http_parser_string_cstr_http1);

    if(size < http_start_len) {
      HTTP_PARSER_LOG("http/1.1-prefix is not present");
      return HTTP_PARSER_RET_ABORT;
    }      

    if(memcmp(data, http_parser_string_cstr_http1, http_start_len) != 0) {
      HTTP_PARSER_LOG("http/1.1-prefix is not present");
      return HTTP_PARSER_RET_ABORT;
    }

    data += http_start_len;
    size -= http_start_len;

    Http_Parser_String s = { .data = data, .len = size};
    int64_t code;
    if(!http_parser_string_chop_int64_t(&s, &code)) {
      HTTP_PARSER_LOG("can not parse responeCode");
      return HTTP_PARSER_RET_ABORT;
    }
      
    parser->response_code = (int) code;
	
    data = s.data;
    size = s.len;
    parser->state = HTTP_PARSER_STATE_IN_HEADER;
    if(size) goto consume;
    return HTTP_PARSER_RET_CONTINUE;
  }break;
  case HTTP_PARSER_STATE_IN_HEADER: {
    Http_Parser_String s = { .data = data, .len = size};
    Http_Parser_String line, key, value;
    while(s.len) {
      line = http_parser_string_chop_by_delim(&s, '\n');
      if(line.len && line.data[0] == '\r') {
	// in this case neither content-length nor transfer encoding was supplied
	HTTP_PARSER_LOG("Nor 'content-length' or 'transfer-encoding' was supplied");
	return HTTP_PARSER_RET_ABORT;	
      }

      key = http_parser_string_trim(http_parser_string_chop_by_delim(&line, ':'));
      value = http_parser_string_trim(line);

      if(parser->header_callback) {
	if(!parser->header_callback(parser->userdata, key, value)) {
	  HTTP_PARSER_LOG("Failure because 'header_callback' return false");
	  return HTTP_PARSER_RET_ABORT;
	}
      }

      // Try to parse content-length
      if(http_parser_string_eq(key, http_parser_string_cstr_content_length) ) {	
	if(!http_parser_string_chop_int64_t(&value, &parser->content_length)) {
	  HTTP_PARSER_LOG("Can not parse supplied content-length: '%.*s'", (int) value.len, value.data);
	  return HTTP_PARSER_RET_ABORT;
	}
	parser->bytes_to_read = parser->content_length;
	parser->state = HTTP_PARSER_STATE_IN_HEADER_CONTENT_LENGTH;

	if(s.len) {
	  data = s.data;
	  size = s.len;
	  goto consume;
	}
		    
      }

      // Try to detect Transfer-Encoding chunked
      if( http_parser_string_eq(key, http_parser_string_cstr_transfer_encoding) &&
	  http_parser_string_eq(value, http_parser_string_cstr_chunked) ) {
	// change state, return?

	parser->bytes_to_read = 0;
	parser->state = HTTP_PARSER_STATE_IN_HEADER_CHUNKED;
	
	if(s.len) {
	  data = s.data;
	  size = s.len;
	  goto consume;
	}
      }           
    }

    return HTTP_PARSER_RET_CONTINUE;
  } break;
  case HTTP_PARSER_STATE_IN_HEADER_CONTENT_LENGTH: {
    Http_Parser_String s = { .data = data, .len = size};
    return http_parser_consume_headers(parser, s);
  } break;
  case HTTP_PARSER_STATE_CONTENT_LENGTH: {	
    int64_t _size = (int64_t) size;
    
    if(_size > parser->bytes_to_read) {
      // if more is provided then needed
      HTTP_PARSER_LOG("More bytes than 'content-length' were consumed");
      return HTTP_PARSER_RET_ABORT;
    }	
	
    Http_Parser_Ret ret = parser->callback(parser->userdata, data, size);
    if(ret == HTTP_PARSER_RET_ABORT) {
      HTTP_PARSER_LOG("Failure because 'callback' returned HTTP_PARSER_RET_ABORT");
      return HTTP_PARSER_RET_ABORT;
    } else if(ret == HTTP_PARSER_RET_SUCCESS) {
      return HTTP_PARSER_RET_SUCCESS;
    }
    
    if( _size == parser->bytes_to_read) {
      // if everything was read
      return HTTP_PARSER_RET_SUCCESS;
    } else {
      parser->bytes_to_read -= _size;
    }
    
    return HTTP_PARSER_RET_CONTINUE;
  } break;
  case HTTP_PARSER_STATE_IN_HEADER_CHUNKED: {
    Http_Parser_String s = { .data = data, .len = size};
    return http_parser_consume_headers(parser, s);
  } break;
  case HTTP_PARSER_STATE_CHUNKED: {
    bool found = false;
    size_t i=0;
    for(;i<size;i++) {
      if(data[i] != '\r') continue;
      if(i < size - 1 && data[i+1] == '\n') {
	found = true;
	break;
      }
    }
    if(!found || i == 0) {
      return HTTP_PARSER_RET_CONTINUE;
    }
    Http_Parser_String s = {.data = data, .len = i};
    if(i > 4 || !http_parser_string_chop_hex(&s, &parser->bytes_to_read) || s.len) {
      // either the hexstring is too big, or it is a hexstring
      HTTP_PARSER_LOG("Failed to parse 'chunk-size' in 'chunked-encoding': '%.*s'\n", (int) s.len, s.data);
      return HTTP_PARSER_RET_ABORT;
    }
    if(parser->bytes_to_read == 0) {
      // if the size is zero, the request has succeeded
      return HTTP_PARSER_RET_SUCCESS;
    }
    parser->state = HTTP_PARSER_STATE_CHUNKED_CONSUME;
    if(i < size) {
      data += i;
      size -= i;
      goto consume;
    }

    return HTTP_PARSER_RET_CONTINUE;
  } break;
  case HTTP_PARSER_STATE_CHUNKED_CONSUME: {

    bool found = false;
    size_t i=0;
    for(;i<size;i++) {
      if(data[i] != '\r') continue;
      if(i < size - 1 && data[i+1] == '\n') {
	found = true;
	break;	
      }
    }
    if(i==0) {
      data += 2;
      size -= 2;
      goto consume;
    }
    
    Http_Parser_String s = {.data = data, .len = i};
    
    int64_t len = (int64_t) s.len;
    if(len > parser->bytes_to_read) {
      // too many bytes supplied
      HTTP_PARSER_LOG("More bytes than 'chunk-size' were consumed");
      return HTTP_PARSER_RET_ABORT;
    }

    if(!parser->callback) {
      return HTTP_PARSER_RET_SUCCESS;
    }

    Http_Parser_Ret ret = parser->callback(parser->userdata, data, size);
    if(ret == HTTP_PARSER_RET_ABORT) {
      HTTP_PARSER_LOG("Failure because 'callback' returned HTTP_PARSER_RET_ABORT");
      return HTTP_PARSER_RET_ABORT;
    } else if(ret == HTTP_PARSER_RET_SUCCESS) {
      return HTTP_PARSER_RET_SUCCESS;
    }

    parser->bytes_to_read -= len;
    parser->content_length += len;
    if(parser->bytes_to_read == 0) {
      // chunk is finished
      parser->state = HTTP_PARSER_STATE_CHUNKED;
    }    

    int off = found ? 2 : 0;
    if(i + off < size) {
      // keep consuming, if enough data
      data += i + off;
      size -= i + off;
      goto consume;
    }

    return HTTP_PARSER_RET_CONTINUE;    
  } break;
  default: {
    HTTP_PARSER_LOG("Unreachable state in switch case was reached");
    return HTTP_PARSER_RET_ABORT;
  } break;
  }
}

///////////////////////////////////////////////////////////////////////////////////

HTTP_PARSER_DEF Http_Parser_String http_parser_string_chop_by_delim(Http_Parser_String *s, char delim) {
  size_t i = 0;
  while(i < s->len && s->data[i]!=delim) {
    i+=1;
  }
  
  Http_Parser_String result = { .data = s->data, .len = i};
  
  if(i < s->len) {
    s->len -= i+1;
    s->data += i+1;
  }
  else {
    s->len -= i;
    s->data += i;
  }

  return result;
}

HTTP_PARSER_DEF Http_Parser_String http_parser_string_trim(Http_Parser_String s) {
  // trim left
  {
    size_t i = 0;
    while(i<s.len && isspace(s.data[i])) {
      i++;
    }
    s = (Http_Parser_String) { .data = s.data + i, .len = s.len - i };
  }

  // trim right
  size_t i = 0;
  while(i<s.len && isspace(s.data[s.len - 1 - i])) {
    i++;
  }
  return (Http_Parser_String) { .data = s.data, .len = s.len - i};
}

HTTP_PARSER_DEF bool http_parser_string_chop_int64_t(Http_Parser_String *s, int64_t *n) {
  size_t i=0;
  int64_t sum = 0;
  int negative = 0;
  if(s->len && s->data[0]=='-') {
    negative = 1;
    i++;
  }
  while(i<s->len && '0' <= s->data[i] && s->data[i] <= '9') {
    sum*=10;
    int digit = (s->data[i] - '0');
    sum+=digit;
    i++;
  }

  s->data+=i;
  s->len-=i;

  if(negative) sum*=-1;
  if(n) *n = sum;

  return i>0;
}

HTTP_PARSER_DEF bool http_parser_string_chop_hex(Http_Parser_String *s, int64_t *n) {
  size_t i=0;
  int64_t sum = 0;

  while(true) {
    if(i>=s->len) break;
    bool isDigit = '0' <= s->data[i] && s->data[i] <= '9';
    bool isAlphaSmall = 'a' <= s->data[i] && s->data[i] <= 'f';
    bool isAlpha = 'A' <= s->data[i] && s->data[i] <= 'F';

    if(isDigit) {
      sum*=16;
      int digit = (s->data[i] - '0');
      sum+=digit;
    } else if(isAlphaSmall) {
      sum*=16;
      int digit = (s->data[i] - 'W');
      sum+=digit;
    } else if(isAlpha) {
      sum*=16;
      int digit = (s->data[i] - '7');
      sum+=digit;
    } else {
      break;
    }

    i++;
  }

  s->data+=i;
  s->len-=i;

  if(n) *n = sum;
  
  return i>0;
}

#endif //HTTP_PARSER_IMPLEMENTATION

#endif //HTTP_PARSER_H

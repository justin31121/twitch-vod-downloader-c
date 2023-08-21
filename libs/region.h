#ifndef REGION_H
#define REGION_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#if !defined(REGION_PADDED) && !defined(REGION_LINEAR)
#  define REGION_LINEAR
#endif

#if !defined(REGION_DYNAMIC) && !defined(REGION_STATIC)
#  define REGION_DYNAMIC
#endif

#ifndef REGION_DEF
#  define REGION_DEF static inline
#endif //REGION_DEF

#define REGION_WORD_SIZE sizeof(uintptr_t)

typedef struct{
#if   defined(REGION_PADDED)
    uintptr_t *data;
#elif defined(REGION_LINEAR)
    unsigned char *data;
#endif                 //             REGION_PADDED/REGION_LINEAR
    uint64_t capacity; // Capacity in words        /bytes 
    uint64_t length;   // Length   in words        /bytes
}Region;

typedef struct{
  Region  *region;  //           REGION_PADDED/REGION_LINEAR
  uint64_t offset;  // Offset in bytes
}Region_Ptr;

// Public
REGION_DEF bool region_init(Region *region, uint64_t capacity_bytes);
REGION_DEF bool region_alloc(Region_Ptr *ptr, Region *region, uint64_t size_bytes);
REGION_DEF void region_free(Region *region);

// 'Constant' Ptrs
void *region_base(Region region);
Region_Ptr region_current(Region *region);

void region_flush(Region *region);
void region_rewind(Region *region, Region_Ptr ptr);

void *region_deref(Region_Ptr ptr);

////////////////////////////////////////////////////////////////

#ifndef REGION_NO_STRING

#include <string.h>
#include <stdarg.h>
#include <stdio.h>

typedef struct{
  Region_Ptr data;
  size_t len;    
}string;

#define str_fmt "%.*s"
#define str_arg(s) (int) (s).len, (char *) region_deref((s).data)

typedef bool (*string_map_func)(const char *input, size_t input_size, char *buffer, size_t buffer_size, size_t *output_size);

// Public
REGION_DEF bool string_alloc(string *s, Region *region, const char *cstr);
REGION_DEF bool string_alloc2(string *s, Region *region, const char *cstr, size_t cstr_len);
REGION_DEF bool string_cstr_alloc(const char **cstr, Region *region, string s);
REGION_DEF bool string_copy(string *s, Region *region, string t);
REGION_DEF bool string_snprintf(string *s, Region *region, const char *fmt, ...);
REGION_DEF bool string_map(string *s, Region *region, string input, string_map_func map_func);
REGION_DEF bool string_map_cstr(string *s, Region *region, const char *cstr, string_map_func map_func);
REGION_DEF bool string_map_impl(string *s, Region *regon, const char *cstr, size_t cstr_len, string_map_func map_fun);

REGION_DEF int string_index_of(string s, const char *needle);
REGION_DEF int string_last_index_of(string s, const char *needle);
REGION_DEF int string_index_of_off(string s, size_t off, const char *needle);
REGION_DEF bool string_substring(string s, size_t start, size_t len, string *d);

REGION_DEF bool string_chop_by(string *s, const char *delim, string *d);

REGION_DEF bool string_eq(string s, const char* cstr);

//MACROS
const char *string_to_cstr(string s);
string string_from_cstr(const char* cstr);
bool str_empty(string s);

#endif //REGION_NO_STRING

#ifdef REGION_IMPLEMENTATION

#define region_base(region) ( (region)->data )
#define region_deref(ptr) ( (*(unsigned char **) ((ptr).region) ) + (ptr).offset )
#define region_rewind(region, ptr) (region)->length = (ptr).offset
#define region_flush(region) (region)->length = 0
#define region_current(r) (Region_Ptr) { .region = (r), .offset = (r)->length }

REGION_DEF bool region_init(Region *region, uint64_t capacity_bytes) {
#if   defined(REGION_PADDED)
    
    size_t capacity_words = (capacity_bytes + REGION_WORD_SIZE - 1) / REGION_WORD_SIZE;

    uintptr_t *data = (uintptr_t *) malloc(capacity_words * REGION_WORD_SIZE);
    if(!data) {
	return false;
    }

    region->data    =  data;
    region->length   = 0;
    region->capacity = capacity_words;
    
    return true;
    
#elif defined(REGION_LINEAR)
    
    unsigned char *data = (unsigned char *) malloc(capacity_bytes);
    if(!data) {
	return false;
    }

    region->data    =  data;
    region->length   = 0;
    region->capacity = capacity_bytes;
    
    return true;
#else
    
    (void) region;
    (void) capacity_bytes;
    return false;
    
#endif    
}

REGION_DEF bool region_alloc(Region_Ptr *ptr, Region *region, uint64_t size_bytes) {
#if   defined(REGION_PADDED)
    size_t size_words = (size_bytes + REGION_WORD_SIZE - 1) / REGION_WORD_SIZE;
    
    size_t needed_capacity = region->length + size_words;
    // Realloc words if necessary
    if(needed_capacity > region->capacity) {
#if   defined(REGION_DYNAMIC)
	size_t new_capacity = region->capacity * 2;
	while( new_capacity < needed_capacity ) new_capacity *= 2;
	region->capacity = new_capacity;
	region->data = realloc(region->data, region->capacity * REGION_WORD_SIZE);
	if(!region->data) {
	    return false;
	}
#elif defined(REGION_STATIC)
	return false;
#else	
	return false;
#endif
    }

    ptr->region = region;
    ptr->offset = sizeof(*region->data) * region->length;
    
    region->length += size_words;

    return true;
    
#elif defined(REGION_LINEAR)

    size_t needed_capacity = region->length + size_bytes;
    // Realloc words if necessary
    if(needed_capacity > region->capacity) {
#if   defined(REGION_DYNAMIC)
	size_t new_capacity = region->capacity * 2;
	while( new_capacity < needed_capacity ) new_capacity *= 2;
	region->capacity = new_capacity;
	region->data = realloc(region->data, region->capacity);
	if(!region->data) {
	    return false;
	}
#elif defined(REGION_STATIC)
	return false;
#else
	return false;
#endif
    }

    ptr->region = region;
    ptr->offset = region->length;
    
    region->length += size_bytes;

    return true;
    
#else

    (void) ptr;
    (void) region;
    (void) size_bytes;
    return false;
    
#endif
}

REGION_DEF void region_free(Region *region) {
    free(region->data);
}

//////////////////////////////////////////////////////////

#ifndef REGION_NO_STRING

#define string_from_cstr(cstr) (string) { (Region_Ptr) { (Region *) &(cstr), 0}, strlen((cstr)) }
#define string_to_cstr(s) ((char *) (memcpy(memset(_alloca(s.len + 1), 0, s.len + 1), region_deref(s.data), s.len)) )
#define string_substring_impl(s, start, len) (string) { .data = (Region_Ptr) { .region = s.data.region, .offset = s.data.offset + start}, .len = len}
#define str_empty(s) ((s).len == 0)

REGION_DEF bool string_alloc(string *s, Region *region, const char *cstr) {
  s->len = strlen(cstr);
  if(!region_alloc(&s->data, region, s->len)) return false;
  memcpy( region_deref(s->data), cstr, s->len);
  return true;
}

REGION_DEF bool string_snprintf(string *s, Region *region, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
#ifdef linux
  va_list args_copy;
  va_copy(args_copy, args);
#else
  va_list args_copy = args;
#endif
  s->len = vsnprintf(NULL, 0, fmt, args) + 1;
  va_end(args);
  if(!region_alloc(&s->data, region, s->len)) return false;
  vsnprintf( (char *const) region_deref(s->data), s->len, fmt, args_copy);
  if(s->len) s->len--;
  return true;
}

REGION_DEF bool string_map_impl(string *s, Region *region,
			       const char *cstr, size_t cstr_len,
			       string_map_func map_func) {
  s->len = cstr_len;
  if(!region_alloc(&s->data, region, s->len)) return false;
  size_t output_size;
  bool map_success = map_func( cstr, cstr_len, (char *) region_deref(s->data), s->len, &output_size);
  while(!map_success) {
    s->len *= 2;
    region_rewind(region, s->data);
    if(!region_alloc(&s->data, region, s->len)) return false;
    map_success = map_func( cstr, cstr_len, (char *) region_deref(s->data), s->len, &output_size);
  }  
  s->len = output_size;
  region_rewind(region, s->data);
  if(!region_alloc(&s->data, region, s->len)) return false;
  return true;  
}

static int string_index_of_impl(const char *haystack, size_t haystack_size, const char* needle, size_t needle_size) {
  if(needle_size > haystack_size) {
    return -1;
  }
  haystack_size -= needle_size;
  size_t i, j;
  for(i=0;i<=haystack_size;i++) {
    for(j=0;j<needle_size;j++) {
      if(haystack[i+j] != needle[j]) {
	break;
      }
    }
    if(j == needle_size) {
      return (int) i;
    }
  }
  return -1;

}

REGION_DEF int string_index_of(string s, const char *needle) {

  const char *haystack = (const char *) region_deref(s.data);
  size_t haystack_size = s.len;

  return string_index_of_impl(haystack, haystack_size, needle, strlen(needle));
}

REGION_DEF int string_index_of_off(string s, size_t off, const char *needle) {

  if(off > s.len) {
    return -1;
  }

  const char *haystack = (const char *) region_deref(s.data);
  size_t haystack_size = s.len;
  
  int pos = string_index_of_impl(haystack + off, haystack_size - off, needle, strlen(needle));
  if(pos < 0) {
    return -1;
  }

  return pos + (int) off;
}

static int string_last_index_of_impl(const char *haystack, size_t haystack_size, const char* needle, size_t needle_size) {

  if(needle_size > haystack_size) {
    return -1;
  }
  
  int i;

  for(i=haystack_size - needle_size - 1;i>=0;i--) {
    size_t j;
    for(j=0;j<needle_size;j++) {
      if(haystack[i+j] != needle[j]) {
	break;
      }
    }
    if(j == needle_size) {
      return i;
    }
  }
  
  return -1;
}

REGION_DEF int string_last_index_of(string s, const char *needle) {
  const char *haystack = (const char *) region_deref(s.data);
  size_t haystack_size = s.len;

  return string_last_index_of_impl(haystack, haystack_size, needle, strlen(needle));
}

REGION_DEF bool string_substring(string s, size_t start, size_t len, string *d) {

  if(start > s.len) {
    return false;
  }

  if(start + len > s.len) {
    return false;
  }

  *d = string_substring_impl(s, start, len);
  
  return true;
}

REGION_DEF bool string_chop_by(string *s, const char *delim, string *d) {
  if(!s->len) return false;
  
  int pos = string_index_of(*s, delim);
  if(pos < 0) pos = (int) s->len;
    
  if(d && !string_substring(*s, 0, pos, d))
    return false;

  if(pos == (int) s->len) {
    s->len = 0;
    return false;
  } else {
    return string_substring(*s, pos + 1, s->len - pos - 1, s);
  }

}

REGION_DEF bool string_map(string *s, Region *region, string input, string_map_func map_func) {
  return string_map_impl(s, region, (const char *) region_deref(input.data), input.len, map_func);
}

REGION_DEF bool string_map_cstr(string *s, Region *region, const char *cstr, string_map_func map_func) {
  return string_map_impl(s, region, cstr, strlen(cstr), map_func); 
}

REGION_DEF bool string_alloc2(string *s, Region *region, const char *cstr, size_t cstr_len) {
    s->len = cstr_len;
    if(!region_alloc(&s->data, region, s->len)) return false;
    memcpy( region_deref(s->data), cstr, s->len);
    return true;
}

REGION_DEF bool string_cstr_alloc(const char **cstr, Region *region, string s) {
  Region_Ptr ptr;
  if(!region_alloc(&ptr, region, s.len + 1)) return false;
  unsigned char *data = region_deref(ptr);
  memcpy( data, region_deref(s.data), s.len);
  data[s.len] = 0;
  *cstr = (const char *) data;
  return true;
}

REGION_DEF bool string_copy(string *s, Region *region, string t) {
    s->len = t.len;
    if(!region_alloc(&s->data, region, s->len)) return false;
    memcpy( region_deref(s->data), region_deref(t.data), s->len);
    return true;  
}

REGION_DEF bool string_eq(string s, const char* cstr) {
  size_t cstr_len = strlen(cstr);
  if(s.len != cstr_len) return false;
  return memcmp( region_deref(s.data), cstr, cstr_len) == 0;
  
}

#endif //REGION_NO_STRING

#endif // REGION_IMPLEMENTATION


#endif //REGION_H

#ifndef JSON_PARSER_H
#define JSON_PARSER_H

#include <stdbool.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

//https://www.json.org/json-de.html

#ifndef JSON_PARSER_DEF
#define JSON_PARSER_DEF static inline
#endif //JSON_PARSER_DEF

#ifdef JSON_PARSER_VERBOSE
#  include <stdio.h>
#  define JSON_PARSER_LOG(...) do{ fflush(stdout); fprintf(stderr, "JSON_PARSER: " __VA_ARGS__); fprintf(stderr, "\n"); fflush(stderr); } while(0)
#else
#  define JSON_PARSER_LOG(...)
#endif //JSON_PARSER_VERBOSE


typedef enum{
  JSON_PARSER_CONST_TRUE = 0,
  JSON_PARSER_CONST_FALSE,
  JSON_PARSER_CONST_NULL,
  JSON_PARSER_CONST_COUNT
}Json_Parser_Const;

typedef enum{
  JSON_PARSER_RET_ABORT = 0,
  JSON_PARSER_RET_CONTINUE = 1,
  JSON_PARSER_RET_SUCCESS = 2,
}Json_Parser_Ret;

typedef enum{
  JSON_PARSER_STATE_IDLE = 0,

  // true, false, null
  JSON_PARSER_STATE_CONST,
  
  // object
  JSON_PARSER_STATE_OBJECT,
  JSON_PARSER_STATE_OBJECT_DOTS,
  JSON_PARSER_STATE_OBJECT_COMMA,
  JSON_PARSER_STATE_OBJECT_KEY,

  // array
  JSON_PARSER_STATE_ARRAY,
  JSON_PARSER_STATE_ARRAY_COMMA,

  // string
  JSON_PARSER_STATE_STRING,

  // number
  JSON_PARSER_STATE_NUMBER,
  JSON_PARSER_STATE_NUMBER_DOT,
  
}Json_Parser_State;

typedef enum{
  JSON_PARSER_TYPE_NULL,
  JSON_PARSER_TYPE_TRUE,
  JSON_PARSER_TYPE_FALSE,
  JSON_PARSER_TYPE_NUMBER,
  JSON_PARSER_TYPE_STRING,
  JSON_PARSER_TYPE_OBJECT,
  JSON_PARSER_TYPE_ARRAY
}Json_Parser_Type;

JSON_PARSER_DEF const char *json_parser_type_name(Json_Parser_Type type) {
  switch(type) {
  case JSON_PARSER_TYPE_NULL:
    return "JSON_PARSER_TYPE_NULL";
  case JSON_PARSER_TYPE_TRUE:
    return "JSON_PARSER_TYPE_TRUE";
  case JSON_PARSER_TYPE_FALSE:
    return "JSON_PARSER_TYPE_FALSE";
  case JSON_PARSER_TYPE_NUMBER:
    return "JSON_PARSER_TYPE_NUMBER";
  case JSON_PARSER_TYPE_STRING:
    return "JSON_PARSER_TYPE_STRING";
  case JSON_PARSER_TYPE_OBJECT:
    return "JSON_PARSER_TYPE_OBJECT";
  case JSON_PARSER_TYPE_ARRAY:
    return "JSON_PARSER_TYPE_ARRAY";
  default:
    return "UNKNOWN";	
  }
}

#ifndef JSON_PARSER_STACK_CAP
#  define JSON_PARSER_STACK_CAP 1024
#endif //JSON_PARSER_STACK_CAP

#ifndef JSON_PARSER_BUFFER_CAP
#  define JSON_PARSER_BUFFER_CAP 1024
#endif //JSON_PARSER_BUFFER_CAP

#define JSON_PARSER_BUFFER 0
#define JSON_PARSER_KEY_BUFFER 1

typedef bool (*Json_Parser_On_Elem)(Json_Parser_Type type, const char *content, size_t content_size, void *arg, void **elem);
typedef bool (*Json_Parser_On_Object_Elem)(void *object, const char *key_data, size_t key_size, void *elem, void *arg);
typedef bool (*Json_Parser_On_Array_Elem)(void *array, void *elem, void *arg);

typedef struct{
  Json_Parser_On_Elem on_elem;
  Json_Parser_On_Object_Elem on_object_elem;
  Json_Parser_On_Array_Elem on_array_elem;
  void *arg;

  Json_Parser_State state;

  Json_Parser_State stack[JSON_PARSER_STACK_CAP];
  size_t stack_size;

  void *parent_stack[JSON_PARSER_STACK_CAP];
  size_t parent_stack_size;

  char buffer[2][JSON_PARSER_BUFFER_CAP];
  size_t buffer_size[2];

  size_t konst_index;
  Json_Parser_Const konst;
}Json_Parser;

// Public
JSON_PARSER_DEF Json_Parser json_parser(Json_Parser_On_Elem on_elem, Json_Parser_On_Object_Elem on_object_elem, Json_Parser_On_Array_Elem on_array_elem, void *arg);
JSON_PARSER_DEF Json_Parser_Ret json_parser_consume(Json_Parser *parser, const char *data, size_t size);

// Private
JSON_PARSER_DEF bool json_parser_on_parent(Json_Parser *parser, void *elem);

#ifdef JSON_PARSER_IMPLEMENTATION

static char *json_parser_const_cstrs[JSON_PARSER_CONST_COUNT] = {
  [JSON_PARSER_CONST_TRUE] = "true",
  [JSON_PARSER_CONST_FALSE] = "false",
  [JSON_PARSER_CONST_NULL] = "null",
};

JSON_PARSER_DEF Json_Parser json_parser(Json_Parser_On_Elem on_elem, Json_Parser_On_Object_Elem on_object_elem, Json_Parser_On_Array_Elem on_array_elem, void *arg) {
  Json_Parser parser = {0};
  parser.state = JSON_PARSER_STATE_IDLE;
  parser.on_elem = on_elem;
  parser.on_object_elem = on_object_elem;
  parser.on_array_elem = on_array_elem;
  parser.stack_size = 0;
  parser.arg = arg;
  return parser;
}

JSON_PARSER_DEF Json_Parser_Ret json_parser_consume(Json_Parser *parser, const char *data, size_t size) {    
  size_t konst_len;

 consume:  
  switch(parser->state) {
  case JSON_PARSER_STATE_IDLE: {
    idle:
    if(!size)
      return JSON_PARSER_RET_CONTINUE;

    if(isspace(data[0])) {      
      data++;
      size--;
      if(size) goto idle;
    } else if(data[0] == '{') {

      assert(parser->parent_stack_size < JSON_PARSER_STACK_CAP);
      void **elem = &parser->parent_stack[parser->parent_stack_size];
      if(parser->on_elem) {
	if(!parser->on_elem(JSON_PARSER_TYPE_OBJECT, NULL, 0, parser->arg, elem)) {
	  JSON_PARSER_LOG("Failure because 'on_elem' returned false");
	  return JSON_PARSER_RET_ABORT;
	}
      }
      if(!json_parser_on_parent(parser, *elem)) {
	return JSON_PARSER_RET_ABORT;
      }
      parser->parent_stack_size++;
	    
      parser->state = JSON_PARSER_STATE_OBJECT;
      data++;
      size--;
      if(size) goto consume;
    } else if(data[0] == '[') {

      assert(parser->parent_stack_size < JSON_PARSER_STACK_CAP);
      void **elem = &parser->parent_stack[parser->parent_stack_size];
      if(parser->on_elem) {
	if(!parser->on_elem(JSON_PARSER_TYPE_ARRAY, NULL, 0, parser->arg, elem)) {
	  JSON_PARSER_LOG("Failure because 'on_elem' returned false");
	  return JSON_PARSER_RET_ABORT;
	}
      }
      if(!json_parser_on_parent(parser, *elem)) {
	return JSON_PARSER_RET_ABORT;
      }
      parser->parent_stack_size++;

	    
      parser->state = JSON_PARSER_STATE_ARRAY;
      data++;
      size--;
      if(size) goto consume;
    } else if(data[0] == '\"') {
      parser->buffer_size[JSON_PARSER_BUFFER] = 0;
      parser->state = JSON_PARSER_STATE_STRING;
      data++;
      size--;
      if(size) goto consume;
    } else if( isdigit(data[0]) ) {
      parser->buffer_size[JSON_PARSER_BUFFER] = 0;
      parser->state = JSON_PARSER_STATE_NUMBER;
      goto consume;      
    } else if( data[0] == '-' ) {
      parser->buffer_size[JSON_PARSER_BUFFER] = 0;
      assert(parser->buffer_size[JSON_PARSER_BUFFER] < JSON_PARSER_BUFFER_CAP);
      parser->buffer[JSON_PARSER_BUFFER][parser->buffer_size[JSON_PARSER_BUFFER]++] = data[0];
      parser->state = JSON_PARSER_STATE_NUMBER;
      data++;
      size--;
      if(size) goto consume;
    } else if( data[0] == 't') {
      parser->state = JSON_PARSER_STATE_CONST;
      parser->konst = JSON_PARSER_CONST_TRUE;
      parser->konst_index = 1;      
      data++;
      size--;
      if(size) goto consume;
    } else if( data[0] == 'f') {
      parser->state = JSON_PARSER_STATE_CONST;
      parser->konst = JSON_PARSER_CONST_FALSE;
      parser->konst_index = 1;      
      data++;
      size--;
      if(size) goto consume;
    } else if( data[0] == 'n') {
      parser->state = JSON_PARSER_STATE_CONST;
      parser->konst = JSON_PARSER_CONST_NULL;
      parser->konst_index = 1;      
      data++;
      size--;
      if(size) goto consume;
    } else {
      JSON_PARSER_LOG("Expected JsonValue but found: '%c'", data[0]);
      return JSON_PARSER_RET_ABORT;
    }

    return JSON_PARSER_RET_CONTINUE;
  } break;
  case JSON_PARSER_STATE_OBJECT: {
    object:
    
    if(!size)
      return JSON_PARSER_RET_CONTINUE;
    
    if( isspace(data[0]) ) {
      data++;
      size--;
      if(size) goto object;
    } else if( data[0] == '\"') {
      assert(parser->stack_size < JSON_PARSER_STACK_CAP);
      parser->stack[parser->stack_size++] = JSON_PARSER_STATE_OBJECT_DOTS;

      parser->buffer_size[JSON_PARSER_BUFFER] = 0;
      parser->buffer_size[JSON_PARSER_KEY_BUFFER] = 0;
      parser->state = JSON_PARSER_STATE_STRING;

      data++;
      size--;
      if(size) goto consume;
    } else if(data[0] == '}') {

      parser->parent_stack_size--;
	    
      if(parser->stack_size) {
	parser->state = parser->stack[parser->stack_size-- - 1];

	data++;
	size--;
	if(size) goto consume;
	return JSON_PARSER_RET_CONTINUE;
      }
      
      return JSON_PARSER_RET_SUCCESS;
    } else {
      JSON_PARSER_LOG("Expected termination of JsonObject or a JsonString: '%c'", data[0]);
      return JSON_PARSER_RET_ABORT;
    }

    return JSON_PARSER_RET_CONTINUE;
  } break;
  case JSON_PARSER_STATE_OBJECT_DOTS: {
    object_dots:

    if(!size)
      return JSON_PARSER_RET_CONTINUE;

    if( isspace(data[0]) ) {
      data++;
      size--;
      if(size) goto object_dots;
    } else if( data[0] == ':' ) {
      assert(parser->stack_size < JSON_PARSER_STACK_CAP);
      parser->stack[parser->stack_size++] = JSON_PARSER_STATE_OBJECT_COMMA;
      
      parser->state = JSON_PARSER_STATE_IDLE;

      data++;
      size--;
      if(size) goto consume;
    } else {
      JSON_PARSER_LOG("Expected ':' between JsonString and JsonValue but found: '%c'", data[0]);
      return JSON_PARSER_RET_ABORT;
    }

    return JSON_PARSER_RET_CONTINUE;
  } break;
  case JSON_PARSER_STATE_OBJECT_COMMA: {
    object_comma:

    if(!size)
      return JSON_PARSER_RET_CONTINUE;

    if( isspace(data[0])) {
      data++;
      size--;
      if(size) goto object_comma;
    } else if( data[0] == ',' ) {
      parser->state = JSON_PARSER_STATE_OBJECT_KEY;
     
      data++;
      size--;
      if(size) goto consume;
    } else if( data[0] == '}') {

      parser->parent_stack_size--;
		    
      if(parser->stack_size) {
	parser->state = parser->stack[parser->stack_size-- - 1];
	data++;
	size--;
	if(size) goto consume;
	return JSON_PARSER_RET_CONTINUE;
      }
      
      return JSON_PARSER_RET_SUCCESS;
    } else {
      JSON_PARSER_LOG("Expected ',' or the termination of JsonObject but found: '%c'", data[0]);
      return JSON_PARSER_RET_ABORT;
    }
    
    return JSON_PARSER_RET_CONTINUE;
  } break;
  case JSON_PARSER_STATE_OBJECT_KEY: {
    object_key:

    if(!size)
      return JSON_PARSER_RET_CONTINUE;

    if( isspace(data[0]) ) {
      data++;
      size--;
      if(size) goto object_key;
    } else if( data[0] != '\"') {
      JSON_PARSER_LOG("Expected JsonString but found: '%c'", data[0]);
      return JSON_PARSER_RET_ABORT;
    } else {
      assert(parser->stack_size < JSON_PARSER_STACK_CAP);
      parser->stack[parser->stack_size++] = JSON_PARSER_STATE_OBJECT_DOTS;
      parser->buffer_size[JSON_PARSER_BUFFER] = 0;
      parser->buffer_size[JSON_PARSER_KEY_BUFFER] = 0;
      parser->state = JSON_PARSER_STATE_STRING;
      
      data++;
      size--;
      if(size) goto consume;
    }

    return JSON_PARSER_RET_CONTINUE;
  } break;
  case JSON_PARSER_STATE_ARRAY: {
    array:

    if(!size)
      return JSON_PARSER_RET_CONTINUE;

    if( isspace(data[0]) ) {
      data++;
      size--;
      if(size) goto array;
    } else if( data[0] == ']') {

      parser->parent_stack_size--;
		    
      if(parser->stack_size) {
	parser->state = parser->stack[parser->stack_size-- - 1];
	data++;
	size--;
	if(size) goto consume;
	return JSON_PARSER_RET_CONTINUE;
      }
	    
      return JSON_PARSER_RET_SUCCESS;
    } else {
      assert(parser->stack_size < JSON_PARSER_STACK_CAP);
      parser->stack[parser->stack_size++] = JSON_PARSER_STATE_ARRAY_COMMA;
      parser->state = JSON_PARSER_STATE_IDLE;
      
      if(size) goto consume;
    }

    return JSON_PARSER_RET_CONTINUE;
  } break;
  case JSON_PARSER_STATE_ARRAY_COMMA: {
    array_comma:

    if(!size)
      return JSON_PARSER_RET_CONTINUE;

    if( isspace(data[0]) ) {
      data++;
      size--;
      if(size) goto array_comma;
    } else if(data[0] == ',') {
      assert(parser->stack_size < JSON_PARSER_STACK_CAP);
      parser->stack[parser->stack_size++] = JSON_PARSER_STATE_ARRAY_COMMA;
      parser->state = JSON_PARSER_STATE_IDLE;
      
      data++;
      size--;
      if(size) goto consume;
    } else if(data[0] == ']') {

      parser->parent_stack_size--;
	    
      if(parser->stack_size) {
	parser->state = parser->stack[parser->stack_size-- - 1];
	data++;
	size--;
	if(size) goto consume;
	return JSON_PARSER_RET_CONTINUE;
      }

      return JSON_PARSER_RET_SUCCESS;
    } else {
      JSON_PARSER_LOG("Expected ',' or the termination of JsonArray but found: '%c'", data[0]);
      return JSON_PARSER_RET_ABORT;
    }
    return JSON_PARSER_RET_CONTINUE;
  } break;
  case JSON_PARSER_STATE_NUMBER: {
    number:
    
    if(!size)
      return JSON_PARSER_RET_CONTINUE;

    if( isdigit(data[0]) ) {
      assert(parser->buffer_size[JSON_PARSER_BUFFER] < JSON_PARSER_BUFFER_CAP);
      parser->buffer[JSON_PARSER_BUFFER][parser->buffer_size[JSON_PARSER_BUFFER]++] = data[0];	    
      data++;
      size--;
      if(size) goto number;
    } else if( data[0] == '.') {
      assert(parser->buffer_size[JSON_PARSER_BUFFER] < JSON_PARSER_BUFFER_CAP);
      parser->buffer[JSON_PARSER_BUFFER][parser->buffer_size[JSON_PARSER_BUFFER]++] = data[0];
      parser->state = JSON_PARSER_STATE_NUMBER_DOT;
      data++;
      size--;
      if(size) goto consume;
    } else {

      void *elem = NULL;
      if(parser->on_elem) {
	if(!parser->on_elem(JSON_PARSER_TYPE_NUMBER, parser->buffer[JSON_PARSER_BUFFER], parser->buffer_size[JSON_PARSER_BUFFER], parser->arg, &elem)) {
	  JSON_PARSER_LOG("Failure because 'on_elem' returned false");
	  return JSON_PARSER_RET_ABORT;
	}	
      }
      if(!json_parser_on_parent(parser, elem)) {
	return JSON_PARSER_RET_ABORT;
      }

      if(parser->stack_size) {
	parser->state = parser->stack[parser->stack_size-- - 1];

	if(size) goto consume;
	return JSON_PARSER_RET_CONTINUE;
      }
      
      return JSON_PARSER_RET_SUCCESS;
    }

    return JSON_PARSER_RET_CONTINUE;
  } break;
  case JSON_PARSER_STATE_NUMBER_DOT: {
    number_dot:

    if(!size)
      return JSON_PARSER_RET_CONTINUE;

    if( isspace(data[0]) ) {
      assert(parser->buffer_size[JSON_PARSER_BUFFER] < JSON_PARSER_BUFFER_CAP);
      parser->buffer[JSON_PARSER_BUFFER][parser->buffer_size[JSON_PARSER_BUFFER]++] = data[0];
      data++;
      size--;
      if(size) goto number_dot;
    } else if( isdigit(data[0])) {
      assert(parser->buffer_size[JSON_PARSER_BUFFER] < JSON_PARSER_BUFFER_CAP);
      parser->buffer[JSON_PARSER_BUFFER][parser->buffer_size[JSON_PARSER_BUFFER]++] = data[0];
      data++;
      size--;
      if(size) goto number_dot;
    } else {

      void *elem = NULL;
      if(parser->on_elem) {
	if(!parser->on_elem(JSON_PARSER_TYPE_NUMBER, parser->buffer[JSON_PARSER_BUFFER], parser->buffer_size[JSON_PARSER_BUFFER], parser->arg, &elem)) {
	  JSON_PARSER_LOG("Failure because 'on_elem' returned false");
	  return JSON_PARSER_RET_ABORT;
	}
      }
      if(!json_parser_on_parent(parser, elem)) {
	return JSON_PARSER_RET_ABORT;
      }

      if(parser->stack_size) {
	parser->state = parser->stack[parser->stack_size-- - 1];

	if(size) goto consume;
	return JSON_PARSER_RET_CONTINUE;
      }
      
      return JSON_PARSER_RET_SUCCESS;
    }

    return JSON_PARSER_RET_CONTINUE;
  } break;
  case JSON_PARSER_STATE_STRING: {
    _string:

    if(!size)
      return JSON_PARSER_RET_CONTINUE;

    if( data[0] == '\"') {

      void *elem = NULL;
      if(parser->on_elem ) {
	if(!parser->stack_size ||
	   (parser->stack[parser->stack_size-1] !=
	    JSON_PARSER_STATE_OBJECT_DOTS)) {
	  if(!parser->on_elem(JSON_PARSER_TYPE_STRING, parser->buffer[JSON_PARSER_BUFFER], parser->buffer_size[JSON_PARSER_BUFFER], parser->arg, &elem)) {
	    JSON_PARSER_LOG("Failure because 'on_elem' returned false");
	    return JSON_PARSER_RET_ABORT;
	  }
	  
	}
      }
      if(!json_parser_on_parent(parser, elem)) {
	return JSON_PARSER_RET_ABORT;
      }
	    
      if(parser->stack_size) {
	parser->state = parser->stack[parser->stack_size-- - 1];

	data++;
	size--;
	if(size) goto consume;
	return JSON_PARSER_RET_CONTINUE;
      }
	    
      return JSON_PARSER_RET_SUCCESS;
    } else if(data[0] == '\\') {
      
      data++;
      size--;
      
      if(!size) {
	JSON_PARSER_LOG("Expected escaped character in JsonString but found: eof");
	return JSON_PARSER_RET_ABORT;
      }

      // TODO: add support for '\u0012'

      char c = data[0];

      if(c == '\"') c = '\"';
      else if(c == '\\') c = '\\';
      else if(c == '/') c = '/';
      else if(c == 'b') c = '\b';
      else if(c == 'f') c = '\f';
      else if(c == 'n') c = '\n';
      else if(c == 'r') c = '\r';
      else if(c == 't') c = 't';
      else {
	JSON_PARSER_LOG("Escape-haracter: '%c' is not supported in JsonString", c);
	return JSON_PARSER_RET_ABORT;
      }

      assert(parser->buffer_size[JSON_PARSER_BUFFER] < JSON_PARSER_BUFFER_CAP);
      parser->buffer[JSON_PARSER_BUFFER][parser->buffer_size[JSON_PARSER_BUFFER]++] = c;

      if(parser->stack_size &&
	 parser->stack[parser->stack_size-1] == JSON_PARSER_STATE_OBJECT_DOTS) {
	assert(parser->buffer_size[JSON_PARSER_KEY_BUFFER] < JSON_PARSER_BUFFER_CAP);
	parser->buffer[JSON_PARSER_KEY_BUFFER][parser->buffer_size[JSON_PARSER_KEY_BUFFER]++] = c;
      }
	    
      data++;
      size--;
      if(size) goto _string;
      
    } else if( data[0] != '\\') {
	  
      assert(parser->buffer_size[JSON_PARSER_BUFFER] < JSON_PARSER_BUFFER_CAP);
      parser->buffer[JSON_PARSER_BUFFER][parser->buffer_size[JSON_PARSER_BUFFER]++] = data[0];

      if(parser->stack_size &&
	 parser->stack[parser->stack_size-1] == JSON_PARSER_STATE_OBJECT_DOTS) {
	assert(parser->buffer_size[JSON_PARSER_KEY_BUFFER] < JSON_PARSER_BUFFER_CAP);
	parser->buffer[JSON_PARSER_KEY_BUFFER][parser->buffer_size[JSON_PARSER_KEY_BUFFER]++] = data[0];
      }
	    
      data++;
      size--;
      if(size) goto _string;
    } else {
      JSON_PARSER_LOG("Expected termination of JsonString but found: '%c'", data[0]);
      return JSON_PARSER_RET_ABORT;
    }

    return JSON_PARSER_RET_CONTINUE;
  } break;
  case JSON_PARSER_STATE_CONST: {
    konst:
    konst_len = strlen(json_parser_const_cstrs[parser->konst]);

    if(!size)
      return JSON_PARSER_RET_CONTINUE;

    if(parser->konst_index == konst_len) {

      void *elem = NULL;
      if(parser->on_elem) {
	Json_Parser_Type type;
	if(parser->konst == JSON_PARSER_CONST_TRUE) {
	  type = JSON_PARSER_TYPE_TRUE;
	} else if(parser->konst == JSON_PARSER_CONST_FALSE) {
	  type = JSON_PARSER_TYPE_FALSE;
	} else {
	  type = JSON_PARSER_TYPE_NULL;
	}

	if(!parser->on_elem(type, NULL, 0, parser->arg, &elem)) {
	  JSON_PARSER_LOG("Failure because 'on_elem' returned false");
	  return JSON_PARSER_RET_ABORT;
	}
      }
      if(!json_parser_on_parent(parser, elem)) {
	return JSON_PARSER_RET_ABORT;
      }

      if(parser->stack_size) {
	parser->state = parser->stack[parser->stack_size-- - 1];

	if(size) goto consume;
	return JSON_PARSER_RET_CONTINUE;
      }
	    
      return JSON_PARSER_RET_SUCCESS;
    }

    if( data[0] == json_parser_const_cstrs[parser->konst][parser->konst_index] ) {	    
      data++;
      size--;
      parser->konst_index++;
      if(size) goto konst;
    } else {
      JSON_PARSER_LOG("Expected 'true', 'false' or 'null'. The string was not terminated correctly with: '%c'.\n"
	      "       Correct would be '%c'.", data[0], json_parser_const_cstrs[parser->konst][parser->konst_index]);
      return JSON_PARSER_RET_ABORT;
    }

    return JSON_PARSER_RET_CONTINUE;
  } break;
  default: {
    JSON_PARSER_LOG("unknown state in json_parser_consume");
    return JSON_PARSER_RET_ABORT;
  } break;
  }
}

JSON_PARSER_DEF bool json_parser_on_parent(Json_Parser *parser, void *elem) {
    
  void *parent = NULL;
  if(parser->parent_stack_size) {
    parent = parser->parent_stack[parser->parent_stack_size - 1];
  } 

  if(!parser->stack_size)
    return true;

  Json_Parser_State state = parser->stack[parser->stack_size - 1];
    
  if((state == JSON_PARSER_STATE_OBJECT ||
      //state == JSON_PARSER_STATE_OBJECT_DOTS ||
      state == JSON_PARSER_STATE_OBJECT_COMMA ||
      state == JSON_PARSER_STATE_OBJECT_KEY) &&
     parser->on_object_elem) {	
    if(!parser->on_object_elem(parent, parser->buffer[JSON_PARSER_KEY_BUFFER], parser->buffer_size[JSON_PARSER_KEY_BUFFER], elem, parser->arg)) {
      JSON_PARSER_LOG("Failure because 'on_object_elem' returned false");
      return false;
      
    }
	
  } else if( (state == JSON_PARSER_STATE_ARRAY ||
	      state == JSON_PARSER_STATE_ARRAY_COMMA) &&
	     parser->on_array_elem) {	
    if(!parser->on_array_elem(parent, elem, parser->arg)) {
      JSON_PARSER_LOG("Failure because 'on_array_elem' returned false");
      return false;      
    }
  }

  return true;
}

#endif //JSON_PARSER_IMPLEMENTATION

#endif //JSON_PARSER_H

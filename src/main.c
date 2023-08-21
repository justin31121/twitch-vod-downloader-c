#include <stdio.h>

#define HTTP_IMPLEMENTATION
#define HTTP_VERBOSE
#include "..\libs\http.h"

#define IO_IMPLEMENTATION
#include "..\libs\io.h"

#define HTTP_PARSER_IMPLEMENTATION
#include "..\libs\http_parser.h"

#define REGION_IMPLEMENTATION
#define REGION_DYNAMIC
#define REGION_LINEAR
#include "..\libs\region.h"

#define JSON_PARSER_IMPLEMENTATION
#include "..\libs\json_parser.h"

#define TWITCH_VOD_PREFIX "https://www.twitch.tv/videos/"
#define TWITCH_VOD_PREFIX_LEN (sizeof(TWITCH_VOD_PREFIX) - 1)

#define TWITCH_CLIENT_ID "kimne78kx3ncx6brgo4mv6wki5h1ko"

Http_Parser_Ret get_callback(void *userdata, const char *data, size_t size) {
  Region *region = userdata;

  Region_Ptr ptr;
  if(!region_alloc(&ptr, region, size)) {
    return HTTP_PARSER_RET_ABORT;
  }
  memcpy(region_deref(ptr), data, size);

  return HTTP_PARSER_RET_CONTINUE;
}
bool parse_url(string url, string *hostname, string *route) {
  if(string_index_of(url, "https://") != 0) {
    return false;
  }

  int pos = string_index_of_off(url, 8, "/");

  if(!string_substring(url, 8, pos - 8, hostname)) {
    return false;
  }

  if(!string_substring(url, pos, url.len - pos, route)) {
    return false;
  }

  return true;
}

bool get(Region *region, string url, string *content) {

  string hostname, route;
  if(!parse_url(url, &hostname, &route)) {
    return false;
  }

  Http http;

  if(!http_init(&http, string_to_cstr(hostname), HTTPS_PORT, true)) {
    return false;
  }

  Region_Ptr ptr = region_current(region);

  Http_Parser parser = http_parser(get_callback, NULL, region);

  bool result = true;
  if(http_request(&http, string_to_cstr(route), "GET",
		  NULL, -1,
		  (Http_Write_Callback) http_parser_consume, &parser,
		  NULL) != HTTP_RET_SUCCESS) {
    result = false;
  }

  http_free(&http);
  
  *content = (string) { ptr, parser.content_length };
  return result;
}

bool escape_qoutes(const char *input, size_t input_size, char *buffer, size_t buffer_size, size_t *output_size) {

  size_t j = 0;
  
  for(size_t i=0;i<input_size;i++) {
    char c = input[i];
    if(c == '\"') {
      if(j >= buffer_size) return false;
      buffer[j++] = '\\';
      if(j >= buffer_size) return false;
      buffer[j++] = '\"';
    } else {
      if(j >= buffer_size) return false;
      buffer[j++] = c;
    }
    
  }

  *output_size = j;

  return true;
}
const char *next(int *argc, char ***argv) {
  if((*argc) == 0) return NULL;
  char *res = *argv[0];
  (*argc)--;
  (*argv)++;
  return res;
}

typedef struct{
  Http http;  
  string content_copy;
  string content;
  string prefix;
}M3u8;

bool index_formats(string content, int index, string *out) {

  const char *magic = "#EXTM3U\n";
  size_t magic_len = strlen(magic);
  if(string_index_of(content, magic) != 0)
    return false;
  
  if(!string_substring(content, magic_len, content.len - magic_len, &content))
    return false;
  
  const char *twitch_prefix = "#EXT-X-TWITCH-INFO";
  if(string_index_of(content, twitch_prefix) == 0  &&
     !string_chop_by(&content, "\n", NULL)) {
    return false;
  }

  int i = 0;
  string line;
  while( string_chop_by(&content, "\n", &line) ) {
    
    if( string_index_of(line, "http") == 0) {
      if(index <0) {
	printf("[%d]: "str_fmt"\n", i, str_arg(line) );
      } else  {
	if(index == i) {
	  *out = line;
	  return true;	  
	}
      }
      i++;    
    }

  }

  if(index >= 0) return false;
  
  return true;
}
bool m3u8_init(Region *region, string m3u8_url, M3u8* m) {

  string hostname, route;
  if(!parse_url(m3u8_url, &hostname, &route))
    return false;

  int last = string_last_index_of(route, "/");
  if(last < 0)
    return false;

  if(!string_substring(route, 0, last + 1, &m->prefix))
 false;

  if(!http_init(&m->http, string_to_cstr(hostname), HTTPS_PORT, true))
    return false;

  // GET
  Region_Ptr ptr = region_current(region);
  Http_Parser parser = http_parser(get_callback, NULL, region);
  if(http_request(&m->http, string_to_cstr(route), "GET",
		  NULL, -1,
		  (Http_Write_Callback) http_parser_consume, &parser,
		  NULL) != HTTP_RET_SUCCESS) {
    return false;
  }  
  m->content = (string) { ptr, parser.content_length };
  
  const char *magic = "#EXTM3U\n";
  if(string_index_of(m->content, magic) != 0)
    return false;
  
  const char* identifier = "#EXTINF";
  int identifier_pos = string_index_of(m->content, identifier);
  if(identifier_pos < 0)
    return false;

  if(!string_substring(m->content, identifier_pos, m->content.len - identifier_pos, &m->content))
    return false;

  m->content_copy = m->content;

  return true;
}
bool m3u8_next(M3u8 *m, string *url) {

  //printf( str_fmt, str_arg(m->content) );

  const char* identifier = "#EXTINF";

  if(string_index_of(m->content, identifier) != 0)
    return false;

  int line_end = string_index_of(m->content, "\n");
  if(line_end < 0)
    return false;

  int line_end_2 = string_index_of_off(m->content, line_end + 1, "\n");

  size_t len = line_end_2 - line_end - 1;
  if(line_end_2 < 0) len = m->content.len - line_end;

  if(!len)
    return false;

  if(!string_substring(m->content, line_end + 1, len, url))
    return false;

  size_t off = line_end + len;
  if(line_end_2 >= 0) off+=2;
  if(!string_substring(m->content, off, m->content.len - off, &m->content))
    return false;
  
  return true;
}
void m3u8_free(M3u8* m) {
  http_free(&m->http);
}

bool download_m3u8_video(Region *region, string m3u8_url, const char *output) {
  M3u8 m3u8;
  if(!m3u8_init(region, m3u8_url, &m3u8)) {
    return false;
  }

  FILE *f = fopen(output, "wb");
  if(!f) {
    return false;
  }
  bool result = true;

  Region_Ptr snapshot = region_current(region);

  string suffix;
  string route;
  while(m3u8_next(&m3u8, &suffix)) {

    if(!string_snprintf(&route, region,
		       str_fmt str_fmt,
			str_arg(m3u8.prefix), str_arg(suffix) )) {
      result = false;
      break;
    }

    printf( str_fmt"\n", str_arg(route) );

    Http_Parser parser = http_parser((Http_Parser_Write_Callback) http_fwrite, NULL, f);
    if(http_request(&m3u8.http, string_to_cstr(route), "GET",
		    NULL, -1,
		    (Http_Write_Callback) http_parser_consume, &parser,
		    NULL) != HTTP_RET_SUCCESS) {
      result = false;
      break;
    }  
    
    region_rewind(region, snapshot);
  }

  fclose(f);

  return result;
}

typedef struct{
  Region *region;
  Region_Ptr snapshot;
  string prev;
  string signature;
  string value;
}Twitch_Gql;
bool on_elem(Json_Parser_Type type, const char *content, size_t content_size, void *arg, void **elem) {
  (void) elem;
  Twitch_Gql *g = arg;

  if(type != JSON_PARSER_TYPE_STRING) {
    return true;
  }

  if(!string_alloc2(&g->prev, g->region, content, content_size)) {
    return false;
  }
  
  return true;
}
bool on_object_elem(void *object, const char *key_data, size_t key_size, void *elem, void *arg) {
  (void) object;
  (void) elem;
  Twitch_Gql *g = arg;

  if(key_size == 5 &&
     strncmp("value", key_data, 5) == 0) {
    g->value = g->prev;
    g->snapshot = region_current(g->region);
  } else if(key_size == 9 &&
	    strncmp("signature", key_data, 9) == 0) {
    g->signature = g->prev;
    g->snapshot = region_current(g->region);
  } else {
    region_rewind(g->region, g->snapshot);
  }
  return true;
}

//Method and Client-ID taken by: https://github.com/ytdl-org/youtube-dl/blob/master/youtube_dl/extractor/twitch.py
bool stream_from_id(Region *region, string id, string *url) {

  const char *token_kind = "video";
  const char *param_name = "id";

  Region_Ptr snapshot = region_current(region);    

  string query_value;
  if(!string_snprintf(&query_value, region, "[{\"query\":\"{\\n%sPlaybackAccessToken(\\n%s: \\\""str_fmt"\\\",\\nparams: {platform: \\\"web\\\",\\nplayerBackend: \\\"mediaplayer\\\", \\nplayerType: \\\"site\\\"\\n}\\n)\\n{value\\nsignature\\n}\\n}\"}]",
		      token_kind, param_name, str_arg(id) ))
      return false;
  
  string client_id_extra;
  if(!string_snprintf(&client_id_extra, region, "Client-ID: %s\r\n", TWITCH_CLIENT_ID))
    return false;

  Http http;
  if(!http_init(&http, "gql.twitch.tv", HTTPS_PORT, true))
    return false;

  Twitch_Gql gql = {0};
  gql.region = region;
  gql.snapshot = snapshot;
  
  Json_Parser jparser = json_parser(on_elem, on_object_elem, NULL, &gql);
  Http_Parser parser = http_parser((Http_Parser_Write_Callback) json_parser_consume, NULL, &jparser);
  if(!http_request(&http, "/gql", "POST",
		   region_deref(query_value.data), (int) query_value.len,
		   (Http_Write_Callback) http_parser_consume, &parser,
		   string_to_cstr(client_id_extra)) )
    return false;

  http_free(&http);

  if(!gql.signature.len || !gql.value.len)
    return false;

  if(!string_snprintf(url, region,
		      "https://usher.ttvnw.net/vod/"str_fmt".m3u8?nauthsig="str_fmt"&allow_spectre=true&playlist_include_framerate=true&allow_audio_only=true&nauth="str_fmt"&allow_source=true&player=twitchweb", str_arg(id), str_arg(gql.signature), str_arg(gql.value) ))
    return false;

  return true;
}

int main(int argc, char **argv) {

  const char *program = next(&argc, &argv);
  
  const char *in = next(&argc, &argv);
  
  if(!in) {
    fprintf(stderr, "ERROR: Please provide enough arguments!\n");
    fprintf(stderr, "USAGE: %s [ -f <stream-index> / -s ] <vod-url/vod-id> <output> \n", program);
    return 1;
  }

  int index = -1;
  if(strcmp(in, "-f") == 0) {
    const char *index_cstr = next(&argc, &argv);
    index = atoi(index_cstr);
    in = next(&argc, &argv);
  }

  if(!in) {
      fprintf(stderr, "ERROR: Please provide a vod!\n");
      fprintf(stderr, "USAGE: %s [ -f <stream-index> / -s ] <vod-url/vod-id> <output> \n", program);
      return 1;
  }

  bool show = false;
  if(strcmp(in, "-s") == 0) {
    if(index > 0) {
      fprintf(stderr, "ERROR: Please either provide '-f <stream-index>' or '-s'\n");
      fprintf(stderr, "USAGE: %s [ -f <stream-index> / -s ] <vod-url/vod-id> <output> \n", program);
      return 1;
    } else {
      show = true;      
    }
    in = next(&argc, &argv);
  }
  
  string vod = string_from_cstr(in);
  if(string_index_of(vod, TWITCH_VOD_PREFIX) == 0) {
    if(!string_substring(vod, TWITCH_VOD_PREFIX_LEN, vod.len - TWITCH_VOD_PREFIX_LEN, &vod)) {
      fprintf(stderr, "ERROR: Please provide a valid vod!\n");
      return 1;
    }
  }

  const char *output = NULL;
  if(index >= 0) {
    output = next(&argc, &argv);

    if(!output) {
      fprintf(stderr, "ERROR: Please provide an output!\n");
      fprintf(stderr, "USAGE: %s [ -f <stream-index> / -s ] <vod-url/vod-id> <output> \n", program);
      return 1;
    }
  }

  //Allocate some initial memory
  Region region;
  if(!region_init(&region, 1024 * 1024)) {
    fprintf(stderr, "ERROR: Can not allocate enough memory\n");
    return 1;
  }
  
  string m3u8_master_url;
  if(!stream_from_id(&region, vod, &m3u8_master_url)) {
    fprintf(stderr, "ERROR: Can not find the vod with the id: '"str_fmt"'\n", str_arg(vod));
    return 1;
  }

  if(!show && index < 0) {
    printf( str_fmt"\n", str_arg(m3u8_master_url) );
    return 0;
  }

  string content;
  if(!get(&region, m3u8_master_url, &content)) {
    fprintf(stderr, "ERROR: Can not query information about vod\n");
    return 1;
  }

  string stream;
  if(!index_formats(content, index, &stream)) {
    fprintf(stderr, "ERROR: Can not iterate formats of vod\n");
    return 1;    
  }

  if(index >= 0 && !download_m3u8_video(&region, stream, output)) {
    fprintf(stderr, "ERROR: Can not download stream: '"str_fmt"'\n", str_arg(stream) );
    return 1;        
  }
  
  return 0;
}


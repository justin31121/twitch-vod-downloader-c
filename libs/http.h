#ifndef HTTP_H
#define HTTP_H

//TODO: Implement posting of 'chunked' data

///////////////////////////////////////////////////////////////////////////

// Define either HTTP_OPEN_SSL or HTTP_WIN32_SSL to use 'https://'. If neither of them is
// defined http_init with ssl=true, will just return false. In order to use OPENSSL, you
// need to first install it.

// Provide the following flags to compile on windows:
//
// DEFAULT:
//    msvc : ws2_32.lib
//    mingw: -lws2_32
// HTTP_WIN32_SSL:
//    msvc : ws2_32.lib secur32.lib
//    mingw: -lws2_32 -lsecur32
// HTTP_OPEN_SSL:
//    msvc : ws2_32.lib crypt32.lib advapi32.lib user32.lib libsslMD.lib libcryptoMD.lib
//    mingw: -lws2_32 -lssl -lcrypto

#ifndef HTTP_DEF
#  define HTTP_DEF static inline
#endif //HTTP_DEF

#ifdef HTTP_VERBOSE
#  include <stdio.h>
#  define HTTP_LOG(...) do{ fflush(stdout); fprintf(stderr, "HTTP: " __VA_ARGS__); fprintf(stderr, "\n"); fflush(stderr); } while(0)
#else
#  define HTTP_LOG(...)
#endif //HTTP_VERBOSE

#define HTTP_PORT 80
#define HTTPS_PORT 443

#ifdef _WIN32
#  include <ws2tcpip.h>
#  include <windows.h>
#elif linux
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <netdb.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>

#ifdef HTTP_OPEN_SSL
#  include <openssl/ssl.h>
#  include <openssl/err.h>
#endif //HTTP_OPEN_SSL

// The implementation for HTTP_WIN32_SLL and therefore for 'http_win32_tls_socket',
// is taken from this example: 'https://gist.github.com/mmozeiko/c0dfcc8fec527a90a02145d2cc0bfb6d'.
#ifdef HTTP_WIN32_SSL
#  define SECURITY_WIN32
#  include <security.h>
#  include <schannel.h>
#  include <shlwapi.h>
#  define TLS_MAX_PACKET_SIZE (16384+512)

typedef struct {
  SOCKET sock;
  CredHandle handle;
  CtxtHandle context;
  SecPkgContext_StreamSizes sizes;
  int received;    // byte count in incoming buffer (ciphertext)
  int used;        // byte count used from incoming buffer to decrypt current packet
  int available;   // byte count available for decrypted bytes
  char* decrypted; // points to incoming buffer where data is decrypted inplace
  char incoming[TLS_MAX_PACKET_SIZE];
} http_win32_tls_socket;

#endif //HTTP_WIN32SLL

#ifndef HTTP_BUFFER_SIZE
#define HTTP_BUFFER_SIZE 8192
#endif //HTTP_BUFFER_SIZE

typedef enum{
  HTTP_RET_ABORT = 0,
  HTTP_RET_CONTINUE = 1,
  HTTP_RET_SUCCESS = 2,
}Http_Ret;

typedef struct{

#ifdef _WIN32
  SOCKET socket;
#else
  int socket;
#endif
  const char *hostname;
#ifdef HTTP_OPEN_SSL
  SSL *conn;  
#elif defined(HTTP_WIN32_SSL)
  http_win32_tls_socket win32_socket;  
#endif //HTTP_OPEN_SSL
  
}Http;

typedef bool (*Http_Sendf_Callback)(const char *data, size_t size, void *userdata);

typedef Http_Ret (*Http_Write_Callback)(void *userdata, const char *data, size_t size);

typedef struct{
  Http_Sendf_Callback send_callback;
  char *buffer;
  size_t buffer_cap;
  void *userdata;
  bool last;
}Http_Sendf_Context;

//  Public
HTTP_DEF bool http_init(Http *http, const char* hostname, uint16_t port, bool use_ssl);
//    Non-Nullable: http, route, method
//    Nullable    : body, body_len, write_callback, userdata, headers_extra
//    Note        : Each header in headers-extra, needs to be terminated by: "\r\n"
HTTP_DEF Http_Ret http_request(Http *http, const char *route, const char *method,
			       const unsigned char *body, int body_len,
			       Http_Write_Callback write_callback, void *userdata,
			       const char *headers_extra);
HTTP_DEF void http_free(Http *http);

HTTP_DEF Http_Ret http_fwrite(void *f, const char *buffer, size_t buffer_size);

// Protected
HTTP_DEF bool http_maybe_init_external_libs();
HTTP_DEF void http_free_external_libs();

//  Private
HTTP_DEF bool http_socket_write(const char *data, size_t size, void *http);
HTTP_DEF bool http_socket_read(char *data, size_t size, void *http, size_t *read);

HTTP_DEF bool http_socket_write_plain(const char *data, size_t size, void *http);
HTTP_DEF bool http_socket_read_plain(char *data, size_t size, void *http, size_t *read);
HTTP_DEF bool http_socket_connect_tls(Http *http, const char *hostname);
HTTP_DEF bool http_socket_connect_plain(Http *http, const char *hostname, uint16_t port);


HTTP_DEF bool http_sendf(Http_Sendf_Callback send_callback, void *userdata,
			 char *buffer, size_t buffer_cap, const char *format, ...);
HTTP_DEF bool http_sendf_impl(Http_Sendf_Callback send_callback, void *userdata,
			      char *buffer, size_t buffer_cap, const char *format, va_list args);
HTTP_DEF size_t http_sendf_impl_send(Http_Sendf_Context *context, size_t *buffer_size, const char *cstr, size_t cstr_len);
HTTP_DEF size_t http_sendf_impl_copy(Http_Sendf_Context *context, size_t buffer_size,
				     const char *cstr, size_t cstr_len, size_t *cstr_off);

#ifdef HTTP_IMPLEMENTATION

#ifdef _WIN32
static bool http_global_wsa_startup = false;
#endif //_WIN32

#ifdef HTTP_OPEN_SSL
static SSL_CTX *http_global_ssl_context = NULL;
#endif //HTTP_OPEN_SSL

bool http_init(Http *http, const char* hostname, uint16_t port, bool use_ssl) {

  size_t hostname_len = strlen(hostname);
  http->hostname = malloc(hostname_len + 1);
  if(!http->hostname) {
    return false;
  }
  memcpy((char *) http->hostname, hostname, hostname_len + 1);

  if(!http_maybe_init_external_libs()) {
    return false;
  }

#ifdef _WIN32
  http->socket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
  if( http->socket == INVALID_SOCKET ) {
    HTTP_LOG("Failed to initialize socket");
    return false;
  }
#elif linux
  http->socket = socket(AF_INET, SOCK_STREAM, 0);
  if( http->socket == -1) {
    HTTP_LOG("Failed to initialize socket");
    return false;
  }    
#endif

  if(!http_socket_connect_plain(http, hostname, port)) {
    HTTP_LOG("Can not connect to '%s:%u", hostname, port);
    return false;
  }

#if defined(HTTP_OPEN_SSL)
  http->conn = NULL;
  
  if(use_ssl) {
    http->conn = SSL_new(http_global_ssl_context);
    if(!http->conn) {
      HTTP_LOG("Fatal error using OPEN_SSL");
      return false;
    }
    SSL_set_fd(http->conn, (int) http->socket); // TODO: maybe check this cast

    SSL_set_connect_state(http->conn);
    SSL_set_tlsext_host_name(http->conn, hostname);
    if(SSL_connect(http->conn) != 1) {
      HTTP_LOG("Can not connect to '%s:%u' via SSL (OPEN_SSL)", hostname, port);
      return false;
    }    
  }
#elif defined(HTTP_WIN32_SSL)
  http->win32_socket.sock = INVALID_SOCKET;
  if(use_ssl) {
    http->win32_socket.sock = http->socket;
  
    if(!http_socket_connect_tls(http, hostname)) {
      HTTP_LOG("Can not connect to '%s:%u' via SSL (WIN32_SSL)", hostname, port);
      return false;
    }
  }
#else
  if(use_ssl) {
    HTTP_LOG("Neither HTTP_OPEN_SSL nor HTTP_WIN32_SSL is defined. Define either to be able to use SSL.");
    return false;    
  }
#endif //HTTP_OPEN_SSL
  
  return true;
}

HTTP_DEF bool http_socket_connect_plain(Http *http, const char *hostname, uint16_t port) {

#ifdef _WIN32
  struct addrinfo hints;
  struct addrinfo* result = NULL;

  ZeroMemory(&hints, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  char port_cstr[6];
  snprintf(port_cstr, sizeof(port_cstr), "%u", port);

  if(getaddrinfo(hostname, port_cstr, &hints, &result) != 0) {
    freeaddrinfo(result);
    return false;
  }

  if(connect(http->socket, result->ai_addr, (int) result->ai_addrlen) != 0) {
    freeaddrinfo(result);
    return false;
  }
  
  freeaddrinfo(result);

  return true;
#elif linux
  struct sockaddr_in addr = {0};

  struct hostent *hostent = gethostbyname(hostname);
  if(!hostent) {
    return false;
  }

  in_addr_t in_addr = inet_addr(inet_ntoa(*(struct in_addr*)*(hostent->h_addr_list)));
  if(in_addr == (in_addr_t) -1) {
    return false;
  }
  addr.sin_addr.s_addr = in_addr;

  addr.sin_family = AF_INET;
  addr.sin_port = htons((u_short) port);
  if(connect(http->socket, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
    return false;
  }

  return true;
#else

  HTTP_LOG("Unsupported platform. Implement: http_socket_connect_plain");
  
  (void) http;
  (void) hostname;
  (void) port;
  return false;
#endif
}

//https://gist.github.com/mmozeiko/c0dfcc8fec527a90a02145d2cc0bfb6d
HTTP_DEF bool http_socket_connect_tls(Http *http, const char *hostname) {
#ifdef HTTP_WIN32_SSL
 
  http_win32_tls_socket *s = &http->win32_socket;

  // initialize schannel
  {
    SCHANNEL_CRED cred =
      {
	.dwVersion = SCHANNEL_CRED_VERSION,
	.dwFlags = SCH_USE_STRONG_CRYPTO          // use only strong crypto alogorithms
	| SCH_CRED_AUTO_CRED_VALIDATION  // automatically validate server certificate
	| SCH_CRED_NO_DEFAULT_CREDS,     // no client certificate authentication
	.grbitEnabledProtocols = SP_PROT_TLS1_2,  // allow only TLS v1.2
      };

    if (AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &s->handle, NULL) != SEC_E_OK) {
      return false;
    }
  }

  s->received = s->used = s->available = 0;
  s->decrypted = NULL;

  // perform tls handshake
  // 1) call InitializeSecurityContext to create/update schannel context
  // 2) when it returns SEC_E_OK - tls handshake completed
  // 3) when it returns SEC_I_INCOMPLETE_CREDENTIALS - server requests client certificate (not supported here)
  // 4) when it returns SEC_I_CONTINUE_NEEDED - send token to server and read data
  // 5) when it returns SEC_E_INCOMPLETE_MESSAGE - need to read more data from server
  // 6) otherwise read data from server and go to step 1

  CtxtHandle* context = NULL;
  int result = 0;
  for (;;) {
    SecBuffer inbuffers[2] = { 0 };
    inbuffers[0].BufferType = SECBUFFER_TOKEN;
    inbuffers[0].pvBuffer = s->incoming;
    inbuffers[0].cbBuffer = s->received;
    inbuffers[1].BufferType = SECBUFFER_EMPTY;

    SecBuffer outbuffers[1] = { 0 };
    outbuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
    SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

    DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    SECURITY_STATUS sec = InitializeSecurityContextA(
						     &s->handle,
						     context,
						     context ? NULL : (SEC_CHAR*)hostname,
						     flags,
						     0,
						     0,
						     context ? &indesc : NULL,
						     0,
						     context ? NULL : &s->context,
						     &outdesc,
						     &flags,
						     NULL);

    // after first call to InitializeSecurityContext context is available and should be reused for next calls
    context = &s->context;

    if (inbuffers[1].BufferType == SECBUFFER_EXTRA) {
      MoveMemory(s->incoming, s->incoming + (s->received - inbuffers[1].cbBuffer), inbuffers[1].cbBuffer);
      s->received = inbuffers[1].cbBuffer;
    } else {
      s->received = 0;
    }

    if (sec == SEC_E_OK) {
      // tls handshake completed
      break;
    } else if (sec == SEC_I_INCOMPLETE_CREDENTIALS) {
      // server asked for client certificate, not supported here
      result = -1;
      break;
    } else if (sec == SEC_I_CONTINUE_NEEDED) {
      // need to send data to server
      char* buffer = outbuffers[0].pvBuffer;
      int size = outbuffers[0].cbBuffer;

      while (size != 0) {
	int d = send(s->sock, buffer, size, 0);
	if (d <= 0)
	  {
	    break;
	  }
	size -= d;
	buffer += d;
      }
      FreeContextBuffer(outbuffers[0].pvBuffer);
      if (size != 0) {
	// failed to fully send data to server
	result = -1;
	break;
      }
    } else if (sec != SEC_E_INCOMPLETE_MESSAGE) {
      // SEC_E_CERT_EXPIRED - certificate expired or revoked
      // SEC_E_WRONG_PRINCIPAL - bad hostname
      // SEC_E_UNTRUSTED_ROOT - cannot vertify CA chain
      // SEC_E_ILLEGAL_MESSAGE / SEC_E_ALGORITHM_MISMATCH - cannot negotiate crypto algorithms
      result = -1;
      break;
    }
    // read more data from server when possible
    if (s->received == sizeof(s->incoming)) {
      // server is sending too much data instead of proper handshake?
      result = -1;
      break;
    }
    int r = recv(s->sock, s->incoming + s->received, sizeof(s->incoming) - s->received, 0);
    if (r == 0) {
      // server disconnected socket
      return true;
    } else if (r < 0) {
      // socket error
      result = -1;
      break;
    }
    s->received += r;
  }

  if (result != 0) {
    DeleteSecurityContext(context);
    FreeCredentialsHandle(&s->handle);
    return false;
  }

  QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &s->sizes);
  
  return true;
#else
  (void) http;
  (void) hostname;
  return false;
#endif
}

#ifdef HTTP_OPEN_SSL
#  define HTTP_WRITE_FUNC http_socket_write
#elif defined(HTTP_WIN32_SSL)
#  define HTTP_WRITE_FUNC http_socket_write
#else
#  define HTTP_WRITE_FUNC http_socket_write_plain
#endif //HTTP_OPEN_SSL

HTTP_DEF Http_Ret http_request(Http *http, const char *route, const char *method,
			       const unsigned char *body, int body_len,
			       Http_Write_Callback write_callback, void *userdata,
			       const char *headers) {
  // WRITE
  char buffer[HTTP_BUFFER_SIZE];
  if(body) {
    if(!http_sendf(HTTP_WRITE_FUNC, http, buffer, sizeof(buffer),
		   "%s %s HTTP/1.1\r\n"
		   "Host: %s\r\n"
		   "%s"
		   "Content-Length: %d\r\n"
		   "\r\n"
		   "%.*s", method, route, http->hostname, headers ? headers : "", body_len , body_len, (char *) body)) {
      HTTP_LOG("Failed to send http-request");
      return false;
    }        
  } else {
    if(!http_sendf(HTTP_WRITE_FUNC, http, buffer, sizeof(buffer),
		   "%s %s HTTP/1.1\r\n"
		   "Host: %s\r\n"
		   "%s"
		   "\r\n", method, route, http->hostname, headers ? headers : "")) {
      HTTP_LOG("Failed to send http-request");
      return false;
    }    
  }

  // READ
  size_t read;
  while(http_socket_read(buffer, sizeof(buffer), http, &read)) {
    
    if(read == 0)
      return true;
    
    if(write_callback) {
      
      Http_Ret ret = write_callback(userdata, buffer, read);
      if( ret == HTTP_RET_ABORT )
	return HTTP_RET_ABORT;
      else if( ret == HTTP_RET_SUCCESS )
	return HTTP_RET_SUCCESS;
      
    }
  }
  
  return HTTP_RET_CONTINUE;
}

HTTP_DEF Http_Ret http_fwrite(void *f, const char *buffer, size_t buffer_size) {
  fwrite(buffer, buffer_size, 1, (FILE *) f);
  return HTTP_RET_CONTINUE;
}

void http_free(Http *http) {
  
#ifdef HTTP_OPEN_SSL
  if(http->conn) {
    SSL_set_shutdown(http->conn, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
    SSL_shutdown(http->conn);
    SSL_free(http->conn);
  }
#elif defined(HTTP_WIN32_SSL)

  if(http->win32_socket.sock != INVALID_SOCKET) {

    http_win32_tls_socket *s = &http->win32_socket;
    DWORD type = SCHANNEL_SHUTDOWN;

    SecBuffer inbuffers[1];
    inbuffers[0].BufferType = SECBUFFER_TOKEN;
    inbuffers[0].pvBuffer = &type;
    inbuffers[0].cbBuffer = sizeof(type);

    SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
    ApplyControlToken(&s->context, &indesc);

    SecBuffer outbuffers[1];
    outbuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };
    DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    if (InitializeSecurityContextA(&s->handle, &s->context, NULL, flags, 0, 0, &outdesc, 0, NULL, &outdesc, &flags, NULL) == SEC_E_OK)
      {
	char* buffer = outbuffers[0].pvBuffer;
	int size = outbuffers[0].cbBuffer;
	while (size != 0)
	  {
	    int d = send(s->sock, buffer, size, 0);
	    if (d <= 0)
	      {
		// ignore any failures socket will be closed anyway
		break;
	      }
	    buffer += d;
	    size -= d;
	  }
	FreeContextBuffer(outbuffers[0].pvBuffer);
      }
    shutdown(s->sock, SD_BOTH);

    DeleteSecurityContext(&s->context);
    FreeCredentialsHandle(&s->handle);
  }
    
#endif //HTTP_OPEN_SSL

#ifdef _WIN32
  closesocket(http->socket);
  free((char *) http->hostname);
#elif linux
  close(http->socket);
#endif
}

HTTP_DEF bool http_maybe_init_external_libs() {

#if defined(HTTP_OPEN_SSL)
  if(!http_global_ssl_context) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    http_global_ssl_context = SSL_CTX_new(TLS_client_method());
    if(!http_global_ssl_context) {
      HTTP_LOG("Failed to initialize SSL (openssl.lib, crypto.lib)\n");
      return false;
    }    
  }
#endif //HTTP_OPEN_SSL

#ifdef _WIN32
  if(!http_global_wsa_startup) {
    
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
      HTTP_LOG("Failed to initialize WSA (ws2_32.lib)\n");
      return false;
    }
    
    http_global_wsa_startup = true;
  }
#endif //_WIN32

  return true;
}

HTTP_DEF void http_free_external_libs() {
  
#ifdef HTTP_OPEN_SSL
  SSL_CTX_free(http_global_ssl_context);
#endif //HTTP_OPEN_SSLs

#ifdef _WIN32
  WSACleanup();
#endif //_WIN32
}

HTTP_DEF bool http_socket_write_plain(const char *data, size_t size, void *_http) {

  Http *http = (Http *) _http;

#ifdef _WIN32
  int ret = send(http->socket, data, (int) size, 0);
  if(ret == SOCKET_ERROR) {
    
    // send error
    return false;
  } else if(ret == 0) {
    
    // connection was closed
    return false;
  } else {
    
    // send success
    return true;
  }
#elif linux

  int ret = send(http->socket, data, (int) size, 0);
  if(ret < 0) {
    // TODO: check if this is the right error
    if(errno == ECONNRESET) {

      // connection was closed
      return false;
    } else {

      // send error
      return false;
    }      
  } else {

    // send success
    return true;
  }
#else
  return false;
#endif 
}

HTTP_DEF bool http_socket_write(const char *data, size_t size, void *_http) {
  Http *http = (Http *) _http;

#ifdef HTTP_OPEN_SSL

  if(!http->conn)
    return http_socket_write_plain(data, size, http);

  // This loop is needed, for the case that SSL_write returns the error: SSL_ERROR_WANT_WRITE.
  // If the write fails, because of any error, but we should continue trying to write.
  
  do{
    int ret = SSL_write(http->conn, data, (int) size);
    if(ret <= 0) {

      int error = SSL_get_error(http->conn, ret);

      if( error == SSL_ERROR_ZERO_RETURN ) {

	// connection was closed
	return false;
      } else if( error == SSL_ERROR_WANT_READ ) {

	// try again calling SSL_write
	continue;
      } else {

	// ssl_write error
	// TODO: maybe handle other errors
	return false;	
      }
    } else {

      // ssl_write success
      return true;
    } 

  }while(1);
#elif defined(HTTP_WIN32_SSL)

  //https://gist.github.com/mmozeiko/c0dfcc8fec527a90a02145d2cc0bfb6d
  if( http->win32_socket.sock == INVALID_SOCKET )
    return http_socket_write_plain(data, size, http);

  while (size != 0) {
    size_t use = min(size, http->win32_socket.sizes.cbMaximumMessage);

    char wbuffer[TLS_MAX_PACKET_SIZE];

    // was an assertion
    if(http->win32_socket.sizes.cbHeader + http->win32_socket.sizes.cbMaximumMessage + http->win32_socket.sizes.cbTrailer > sizeof(wbuffer)) {
      return false;
    }

    SecBuffer buffers[3];
    buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    buffers[0].pvBuffer = wbuffer;
    buffers[0].cbBuffer = http->win32_socket.sizes.cbHeader;
    buffers[1].BufferType = SECBUFFER_DATA;
    buffers[1].pvBuffer = wbuffer + http->win32_socket.sizes.cbHeader;
    buffers[1].cbBuffer = (unsigned long) use;
    buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    buffers[2].pvBuffer = wbuffer + http->win32_socket.sizes.cbHeader + use;
    buffers[2].cbBuffer = http->win32_socket.sizes.cbTrailer;

    CopyMemory(buffers[1].pvBuffer, data, use);

    SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
    SECURITY_STATUS sec = EncryptMessage(&http->win32_socket.context, 0, &desc, 0);
    if (sec != SEC_E_OK) {
      // this should not happen, but just in case check it
      return false;
    }

    int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
    int sent = 0;
    while (sent != total) {
      int d = send(http->win32_socket.sock, wbuffer + sent, total - sent, 0);
      if (d <= 0) {
	// error sending data to socket, or server disconnected
	return false;
      }
      sent += d;
    }

    data = (char*)data + use;
    size -= use;
  }

  return true;
  
#else
  return http_socket_write_plain(data, size, http);
#endif //HTTP_OPEN_SSL
}

HTTP_DEF bool http_socket_read_plain(char *buffer, size_t buffer_size, void *_http, size_t *read) {

  Http *http = (Http *) _http;

#ifdef _WIN32
  int ret = recv(http->socket, buffer, (int) buffer_size, 0);
  if(ret == SOCKET_ERROR) {
      
    // recv error
    return false;
  } else if(ret == 0) {

    // connection was closed
    *read = 0;
    return true;
  } else {

    // recv success
    *read = (size_t) ret;
    return true;
  }
#elif linux

  int ret = recv(http->socket, buffer, (int) buffer_size, 0);
  if(ret < 0) {

    // recv error
    return false;
  } else if(ret == 0) {

    // connection was closed
    *read = 0;
    return true;
  } else {

    *read = (size_t) ret; 
    return true;
  }
#else
  return false;
#endif 
}

HTTP_DEF bool http_socket_read(char *buffer, size_t buffer_size, void *_http, size_t *read) {
  Http *http = (Http *) _http;

#ifdef HTTP_OPEN_SSL

  if(!http->conn)
    return http_socket_read_plain(buffer, buffer_size, http, read);

  // This loop is needed, for the case that SSL_read returns the error: SSL_ERROR_WANT_READ.
  // In this case we should not close the connection which would be indicated by returning
  // a read of 0. And we should not return false, because there is still data that wants to
  // be read.
  do{

    int ret = SSL_read(http->conn, buffer, (int) buffer_size);
    if(ret < 0) {
      int error = SSL_get_error(http->conn, ret);

      if( error == SSL_ERROR_ZERO_RETURN ) {

	// connection was closed
	*read = 0;
	return false;
      } else if( error == SSL_ERROR_WANT_READ ) {

	// try again calling SSL_read
	continue;
      } else {

	// ssl_read error
	// TODO: maybe handle other errors
	return false;	
      }
    } else {

      // ssl_read success
      *read = (size_t) ret;
      return true;
    }

    break;
  }while(1);
#elif defined(HTTP_WIN32_SSL)
  
  if( http->win32_socket.sock == INVALID_SOCKET )
    return http_socket_read_plain(buffer, buffer_size, http, read);

  int result = 0;

  while (buffer_size != 0) {
    if (http->win32_socket.decrypted) {
      // if there is decrypted data available, then use it as much as possible
      size_t use = min(buffer_size, http->win32_socket.available);
      CopyMemory(buffer, http->win32_socket.decrypted, use);
      buffer = (char*)buffer + use;
      buffer_size -= use;
      result += (int) use;

      if ((int) use == http->win32_socket.available) {
	// all decrypted data is used, remove ciphertext from incoming buffer so next time it starts from beginning
	MoveMemory(http->win32_socket.incoming, http->win32_socket.incoming + http->win32_socket.used, http->win32_socket.received - http->win32_socket.used);
	http->win32_socket.received -= http->win32_socket.used;
	http->win32_socket.used = 0;
	http->win32_socket.available = 0;
	http->win32_socket.decrypted = NULL;
      }
      else {
	http->win32_socket.available -= (int) use;
	http->win32_socket.decrypted += (int) use;
      }
    } else {
      // if any ciphertext data available then try to decrypt it
      if (http->win32_socket.received != 0)
	{
	  SecBuffer buffers[4];
		
	  //was an assertion
	  if(http->win32_socket.sizes.cBuffers != ARRAYSIZE(buffers)) {
	    return false;
	  }

	  buffers[0].BufferType = SECBUFFER_DATA;
	  buffers[0].pvBuffer = http->win32_socket.incoming;
	  buffers[0].cbBuffer = http->win32_socket.received;
	  buffers[1].BufferType = SECBUFFER_EMPTY;
	  buffers[2].BufferType = SECBUFFER_EMPTY;
	  buffers[3].BufferType = SECBUFFER_EMPTY;

	  SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };

	  SECURITY_STATUS sec = DecryptMessage(&http->win32_socket.context, &desc, 0, NULL);
	  if (sec == SEC_E_OK) {

	    //was assertion
	    if(buffers[0].BufferType != SECBUFFER_STREAM_HEADER) return false;
	    //was assertion
	    if(buffers[1].BufferType != SECBUFFER_DATA) return false;
	    //was assertion		    
	    if(buffers[2].BufferType != SECBUFFER_STREAM_TRAILER) return false;

	    http->win32_socket.decrypted = buffers[1].pvBuffer;
	    http->win32_socket.available = buffers[1].cbBuffer;
	    http->win32_socket.used = http->win32_socket.received - (buffers[3].BufferType == SECBUFFER_EXTRA ? buffers[3].cbBuffer : 0);

	    // data is now decrypted, go back to beginning of loop to copy memory to output buffer
	    continue;
	  } else if (sec == SEC_I_CONTEXT_EXPIRED) {
	    // server closed TLS connection (but socket is still open)
	    http->win32_socket.received = 0;
	    if(result == 0) {
	      *read = 0;
	      return true;
	    } else  if(result < 0) {
	      return false;
	    } else {
	      *read =result;
	      return true;
	    }
	  } else if (sec == SEC_I_RENEGOTIATE) {
	    // server wants to renegotiate TLS connection, not implemented here
	    return false;
	  } else if (sec != SEC_E_INCOMPLETE_MESSAGE) {
	    // some other schannel or TLS protocol error
	    return false;
	  }
	  // otherwise sec == SEC_E_INCOMPLETE_MESSAGE which means need to read more data
	}
      // otherwise not enough data received to decrypt

      if (result != 0) {
	// some data is already copied to output buffer, so return that before blocking with recv
	break;
      }

      if (http->win32_socket.received == sizeof(http->win32_socket.incoming)) {
	// server is sending too much garbage data instead of proper TLS packet
	return false;
      }

      // wait for more ciphertext data from server
      int r = recv(http->win32_socket.sock, http->win32_socket.incoming + http->win32_socket.received, sizeof(http->win32_socket.incoming) - http->win32_socket.received, 0);
      if (r == 0) {
	// server disconnected socket
	return 0;
      } else if (r < 0) {
	// error receiving data from socket
	result = -1;
	break;
      }
      http->win32_socket.received += r;
    }
  }

  if(result == 0) {
    *read = 0;
    return true;
  } else  if(result < 0) {
    return false;
  } else {
    *read = result;
    return true;
  }
  
#else

  return http_socket_read_plain(buffer, buffer_size, http, read);

#endif //HTTP_OPEN_SSL
}

////////////////////////////////////////////////////////////////////

HTTP_DEF bool http_sendf(Http_Sendf_Callback send_callback, void *userdata,
			 char *buffer, size_t buffer_cap, const char *format, ...) {
  va_list va;
  va_start(va, format);
  bool result = http_sendf_impl(send_callback, userdata, buffer, buffer_cap, format, va);
  va_end(va);
  return result;

}

HTTP_DEF bool http_sendf_impl(Http_Sendf_Callback send_callback, void *userdata,
			      char *buffer, size_t buffer_cap, const char *format, va_list va) {
  Http_Sendf_Context context = {0};
  context.send_callback = send_callback;
  context.buffer = buffer;
  context.buffer_cap = buffer_cap;
  context.userdata = userdata;
  context.last = false;

  size_t buffer_size = 0;
  size_t format_len = strlen(format);
  size_t format_last = 0;

  for(size_t i=0;i<format_len;i++) {
    if(format[i]=='%' && i+1 < format_len) {
      if(!http_sendf_impl_send(&context, &buffer_size, format + format_last, i - format_last)) {
	return false;
      }
      if (format[i+1] == 'c') { // %c
	char c = (char) va_arg(va, int);
	if(!http_sendf_impl_send(&context, &buffer_size, &c, 1)) {
	  return false;
	}

	format_last = i+2;
	i++;
      } else if(format[i+1]=='s') { // %
	const char *argument_cstr = va_arg(va, char *);
	if(!http_sendf_impl_send(&context, &buffer_size, argument_cstr, strlen(argument_cstr))) {
	  return false;
	}

	format_last = i+2;
	i++;
      } else if(format[i+1]=='d') { // %d
	int n = va_arg(va, int);

	if(n == 0) {
	  const char *zero = "0";
	  if(!http_sendf_impl_send(&context, &buffer_size, zero, strlen(zero))) {
	    return false;
	  }	  
	} else {
#define HTTP_SENDF_DIGIT_BUFFER_CAP 32
	  static char digit_buffer[HTTP_SENDF_DIGIT_BUFFER_CAP ];
	  size_t digit_buffer_count = 0;
	  bool was_negative = false;
	  if(n < 0) {
	    was_negative = true;
	    n *= -1;
	  }
	  while(n > 0) {
	    int m = n % 10;
	    digit_buffer[HTTP_SENDF_DIGIT_BUFFER_CAP - digit_buffer_count++ - 1] = (char) m + '0';
	    n = n / 10;
	  }
	  if(was_negative) {
	    digit_buffer[HTTP_SENDF_DIGIT_BUFFER_CAP - digit_buffer_count++ - 1] = '-';
	  }
	  if(!http_sendf_impl_send(&context, &buffer_size,
				   digit_buffer + (HTTP_SENDF_DIGIT_BUFFER_CAP - digit_buffer_count), digit_buffer_count)) {
	    return false;
	  }
	}	

	format_last = i+2;
	i++;
      } else if(format[i+1] == '.' && i+3 < format_len &&
		format[i+2] == '*' && format[i+3] == 's') { //%.*s

	int argument_cstr_len = va_arg(va, int);
	const char *argument_cstr = va_arg(va, char *);

	if(!http_sendf_impl_send(&context, &buffer_size, argument_cstr, (size_t) argument_cstr_len)) {
	  return false;
	}

	format_last = i+4;
	i+=3;
      }
    }
  }

  context.last = true;
  if(!http_sendf_impl_send(&context, &buffer_size, format + format_last, format_len - format_last)) {
    return false;
  }


  return true;
}

HTTP_DEF size_t http_sendf_impl_send(Http_Sendf_Context *context, size_t *buffer_size, const char *cstr, size_t cstr_len) {
  size_t cstr_off = 0;
  while(true) {
    *buffer_size = http_sendf_impl_copy(context, *buffer_size, cstr, cstr_len, &cstr_off);
    if(*buffer_size == context->buffer_cap || (context->last && *buffer_size != 0)) {
      if(!context->send_callback(context->buffer, *buffer_size, context->userdata)) {
	return false;
      }
    }
    if(*buffer_size < context->buffer_cap) break;
    *buffer_size = 0;
  }

  return true;
}

HTTP_DEF size_t http_sendf_impl_copy(Http_Sendf_Context *context, size_t buffer_size,
				     const char *cstr, size_t cstr_len, size_t *cstr_off) {
  size_t diff = cstr_len - *cstr_off;

  if(buffer_size + diff < context->buffer_cap) {
    memcpy(context->buffer + buffer_size, cstr + *cstr_off, diff);

    *cstr_off = 0;
    return buffer_size + diff;
  } else{
    size_t buffer_diff = context->buffer_cap - buffer_size;
    memcpy(context->buffer + buffer_size, cstr + *cstr_off, buffer_diff);
    
    (*cstr_off) += buffer_diff;
    return buffer_size + buffer_diff;
  }  

}

#endif //HTTP_IMPLEMENTATION

#endif //HTTP_H

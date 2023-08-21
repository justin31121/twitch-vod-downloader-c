#ifndef IO_H_H
#define IO_H_H

// TODO: Somehow distinguish between reads/writes in the file-apis

#include <stdbool.h>
#include <stdio.h>

#ifdef _WIN32
# include <windows.h>
# include <stdio.h>
#endif //_WIN32

#ifdef linux
# include <limits.h>
# include <dirent.h>
# include <sys/stat.h>
# include <string.h>
# include <stdlib.h>
#endif //linux

#ifndef IO_DEF
#define IO_DEF static inline
#endif //IO_DEF

typedef struct{
#ifdef _WIN32
    WIN32_FIND_DATAW file_data;
    HANDLE handle;
    bool stop;
#endif //_WIN32

#ifdef linux
    struct dirent *ent;
    DIR *handle;
#endif //linux

    const char *name;
}Io_Dir;

typedef struct{
    bool is_dir;
#ifdef _WIN32
    HANDLE handle;
    DWORD size;
    DWORD pos;
    char abs_name[MAX_PATH];
#elif linux
    FILE *f;
    char abs_name[PATH_MAX];
#endif //_WIN32
    char *name;
}Io_File;

IO_DEF bool io_dir_open(Io_Dir *dir, const char *dir_path);
IO_DEF bool io_dir_next(Io_Dir *dir, Io_File *file);
IO_DEF void io_dir_close(Io_Dir *dir);

IO_DEF bool io_exists(const char *file_path, bool *is_file);
IO_DEF bool io_delete(const char *file_path);
IO_DEF bool io_mkdir(const char *file_path);

IO_DEF bool io_file_open(Io_File *file, const char *file_path);
IO_DEF bool io_file_close(Io_File *file);
IO_DEF size_t io_file_fread(void *ptr, size_t size, size_t count, Io_File *file);
IO_DEF int io_file_ferror(Io_File *file);
IO_DEF int io_file_feof(Io_File *file);
IO_DEF int io_file_fseek(Io_File *file, long offset, int whence);
IO_DEF long io_file_ftell(Io_File *file);

IO_DEF bool io_getenv(const char *name, char *buffer, size_t buffer_cap);

IO_DEF bool io_slurp_file(const char *name, char **bufer, size_t *buffer_size);
IO_DEF bool io_write_file_len(const char *name, char *bufer, size_t buffer_size);

typedef void (*io_visit_function)(const char* name, bool is_dir, void *arg);

IO_DEF bool io_visit_files(const char *dir_path, bool recursive, io_visit_function io_visit, void *arg);

#ifdef IO_IMPLEMENTATION

#ifdef linux

IO_DEF bool io_dir_open(Io_Dir *dir, const char *dir_path) {

    dir->handle = opendir(dir_path);
    if(dir->handle == NULL) {
	return false;
    }  

    dir->name = dir_path;  
    return true;
}

IO_DEF bool io_dir_next(Io_Dir *dir, Io_File *file) {

    dir->ent = readdir(dir->handle);
    if(dir->ent == NULL) {
	return false;
    }

    file->is_dir = (dir->ent->d_type == DT_DIR) != 0;
  
    file->name = dir->ent->d_name + 1;
    int len = strlen(dir->name);
    memcpy(file->abs_name, dir->name, len);
    int len2 = strlen(dir->ent->d_name);
    memcpy(file->abs_name + len, dir->ent->d_name, len2);
    file->abs_name[len2 + len] = 0;
  
    return true;
}

IO_DEF void io_dir_close(Io_Dir *dir) {
    closedir(dir->handle);
}

IO_DEF bool io_exists(const char *file_path, bool *is_file) {
    struct stat file_info;
    if(stat(file_path, &file_info) == 0) {        
	bool file = S_ISREG(file_info.st_mode) != 0;
	if(is_file) *is_file = file;
    
	return file || S_ISDIR(file_info.st_mode) != 0;
    }

    return false;
}

IO_DEF bool io_mkdir(const char *file_path) {
  return mkdir(file_path, 0777) == 0;
}

IO_DEF bool io_file_open(Io_File *file, const char *file_path) {
  file->f = fopen(file_path, "rb");
  if(file->f == NULL) {
    return false;
  }

  return true;
}

IO_DEF bool io_file_close(Io_File *file) {
  fclose(file->f);
  return true;
}

IO_DEF size_t io_file_fread(void *ptr, size_t size, size_t count, Io_File *file) {
  return fread(ptr, size, count, file->f);
}

IO_DEF int io_file_ferror(Io_File *file) {
  return ferror(file->f);
}

IO_DEF int io_file_feof(Io_File *file) {
  return feof(file->f);
}

IO_DEF int io_file_fseek(Io_File *file, long offset, int whence) {
  return fseek(file->f, offset, whence);
}

IO_DEF long io_file_ftell(Io_File *file) {
  return ftell(file->f);
}

IO_DEF bool io_getenv(const char *name, char *buffer, size_t buffer_cap) {
  char *value = getenv(name);
  if(value == NULL) {
    return false;
  }

  size_t value_len = strlen(value);
  if(value_len > buffer_cap - 1) {
    return false;
  }

  memcpy(buffer, value, value_len+1);
  return true;
}

IO_DEF bool io_slurp_file(const char *name, char **buffer, size_t *buffer_size) {  
  FILE *f = fopen(name, "rb");
  if(!f) {
    return false;
  }

  if(fseek(f, 0, SEEK_END) < 0) {
    fclose(f);
    return false;
  }

  long m = ftell(f);
  if(m < 0) {
    fclose(f);
    return false;
  }  

  if(fseek(f, 0, SEEK_SET) < 0) {
    fclose(f);
    return false;
  }

  *buffer = (char *) malloc((size_t) m + 1);
  if(!(*buffer)) {
    fclose(f);
    return false;
  }

  size_t _m = (size_t) m;
  size_t n = fread(*buffer, 1, _m, f);
  if(n != _m) {
    fclose(f);
    exit(1);    
  }
  (*buffer)[n] = 0;

  *buffer_size = n;

  fclose(f);
  return true;
}

IO_DEF bool io_write_file_len(const char *name, char *buffer, size_t buffer_size) {
  FILE *f = fopen(name, "wb");
  if(!f) {
    return false;
  }

  fwrite(buffer, buffer_size, 1, f);
  if(ferror(f)) {
    fclose(f);
    return false;
  }

  fclose(f);
  return true;
}

#endif //linux

#ifdef _WIN32
IO_DEF bool io_dir_open(Io_Dir *dir, const char *dir_path) {
    int num_wchars = MultiByteToWideChar(CP_UTF8, 0, dir_path, -1, NULL, 0); 
    wchar_t *my_wstring = (wchar_t *)malloc((num_wchars+1) * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, dir_path, -1, my_wstring, num_wchars);
    my_wstring[num_wchars-1] = '*';
    my_wstring[num_wchars] = 0;

    // Use my_wstring as a const wchar_t *
    dir->handle = FindFirstFileExW(my_wstring, FindExInfoStandard, &dir->file_data, FindExSearchNameMatch, NULL, 0);
    if(dir->handle == INVALID_HANDLE_VALUE) {
	free(my_wstring);
	return false;
    }

    bool is_dir = (dir->file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) > 0;
    if(!is_dir) {
	free(my_wstring);
	return false;
    }

    dir->name = dir_path;
    dir->stop = false;

    free(my_wstring);
    return true;
}

IO_DEF bool io_dir_next(Io_Dir *dir, Io_File *file) {

    if(dir->stop) {
	return false;
    }

    file->is_dir = (dir->file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) > 0;
    file->name = (char *) dir->file_data.cFileName;

    size_t len = strlen(dir->name);
    memcpy(file->abs_name, dir->name, len);
    int len2 = WideCharToMultiByte(CP_ACP, 0, dir->file_data.cFileName, -1, NULL, 0, NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, dir->file_data.cFileName, -1, file->abs_name + len, len2, NULL, NULL);

    //WHAT IS THIS
    if(file->is_dir) {
	file->abs_name[len + len2-1] = '\\';
	file->abs_name[len + len2] = 0;       
    } else {
	file->abs_name[len + len2-1] = 0;       
    }


    if(FindNextFileW(dir->handle, &dir->file_data) == 0) {
	dir->stop = true;
    }

    return true;
}

IO_DEF void io_dir_close(Io_Dir *dir) {
    FindClose(dir->handle);
}

IO_DEF bool io_exists(const char *file_path, bool *is_file) {
    DWORD attribs = GetFileAttributes(file_path);
    if(is_file) *is_file = !(attribs & FILE_ATTRIBUTE_DIRECTORY);
    return attribs != INVALID_FILE_ATTRIBUTES;
}

IO_DEF bool io_getenv(const char *name, char *buffer, size_t buffer_cap) {
  buffer_cap -= 1;
  DWORD buffer_size = GetEnvironmentVariable(name, NULL, 0);
  if(buffer_size == 0) {
    return false;
  }

  if(buffer_size > buffer_cap) {
    return false;
  }

  DWORD result = GetEnvironmentVariable(name, buffer, (DWORD) buffer_cap);
  if(result == 0) {
    return false;
  }

  buffer[buffer_size] = 0;
  
  return true;
}

IO_DEF bool io_slurp_file(const char *name, char **buffer, size_t *buffer_size) {
    HANDLE handle = CreateFile(
	name,                     // File name
	GENERIC_READ,                 // Desired access (read-only in this case)
	FILE_SHARE_READ,              // Share mode (other processes can read the file)
	NULL,                         // Security attributes
	OPEN_EXISTING,                // Creation disposition (open existing file)
	FILE_ATTRIBUTE_NORMAL,        // File attributes
	NULL                          // Template file handle
	);
    if(handle == INVALID_HANDLE_VALUE) {
	return false;
    }

    DWORD size = GetFileSize(handle, NULL);
    if(size == INVALID_FILE_SIZE) {
	CloseHandle(handle);
	return false;
    }

    char *data = (char *) malloc(sizeof(char) * (size + 1));
    if(!data) {
	CloseHandle(handle);
	return false;
    }

    DWORD bytes_read;
    if(!ReadFile(handle, data, size, &bytes_read, NULL)) {
	free(data);
	CloseHandle(handle);
	return false;
    }

    if(size != bytes_read) {
	free(data);
	CloseHandle(handle);
	return false;
    }

    data[size] = 0;

    *buffer = data;
    *buffer_size = (size_t) size;

    CloseHandle(handle);
    return true;
}

IO_DEF bool io_write_file_len(const char *name, char *buffer, size_t buffer_size) {
    HANDLE handle = CreateFile(name,
			       GENERIC_WRITE, 0, NULL,
			       CREATE_ALWAYS,
			       FILE_ATTRIBUTE_NORMAL,
			       NULL);
    if(handle == INVALID_HANDLE_VALUE) {
	return false;
    }

    bool result = true;
    DWORD written;
    if(!WriteFile(handle, buffer, (DWORD) buffer_size, &written, NULL)) {
	result = false;
    }

    CloseHandle(handle);  
    return result;}


IO_DEF bool io_file_open(Io_File *file, const char *file_path) {

    file->handle = CreateFile(
	file_path,                     // File name
	GENERIC_READ,                 // Desired access (read-only in this case)
	FILE_SHARE_READ,              // Share mode (other processes can read the file)
	NULL,                         // Security attributes
	OPEN_EXISTING,                // Creation disposition (open existing file)
	FILE_ATTRIBUTE_NORMAL,        // File attributes
	NULL                          // Template file handle
	);
    if(file->handle == INVALID_HANDLE_VALUE) {
	return false;
    }

    file->size = GetFileSize(file->handle, NULL);
    if(file->size == INVALID_FILE_SIZE) {
	CloseHandle(file->handle);
	return false;
    }
    file->pos = 0;
  
    return true;
}

IO_DEF bool io_file_close(Io_File *file) {
    CloseHandle(file->handle);
    return false;
}

IO_DEF size_t io_file_fread(void *ptr, size_t size, size_t count, Io_File *file) {
    DWORD bytes_read;
    DWORD bytes_to_read = (DWORD) (size * count);

    if(!ReadFile(file->handle, ptr, bytes_to_read, &bytes_read, NULL)) {
	return 0;
    }
    file->pos += bytes_read;

    return (size_t) bytes_read / size;
}

IO_DEF int io_file_ferror(Io_File *file) {
    (void) file;
    DWORD lastError = GetLastError();
    return (file->handle == INVALID_HANDLE_VALUE) || (lastError != ERROR_SUCCESS);
}

IO_DEF int io_file_feof(Io_File *file) {
    return file->pos == file->size;
}

IO_DEF int io_file_fseek(Io_File *file, long offset, int whence) {
    DWORD moveMethod;

    switch (whence) {
    case SEEK_SET:
	moveMethod = FILE_BEGIN;
	break;

    case SEEK_CUR:
	moveMethod = FILE_CURRENT;
	break;

    case SEEK_END:
	moveMethod = FILE_END;
	break;

    default:
	return -1;  // Invalid origin
    }

    file->pos = SetFilePointer(file->handle, offset, NULL, moveMethod);
    return !(file->pos != INVALID_SET_FILE_POINTER);
}

IO_DEF long io_file_ftell(Io_File *file) {
    return file->pos;
}

IO_DEF bool io_mkdir(const char *file_path) {
  return CreateDirectoryA(file_path, NULL);
}

#endif //_WIN32

IO_DEF bool io_visit_files(const char *dir_path, bool recursive, io_visit_function io_visit, void *arg) {
    Io_Dir dir;
    if(!io_dir_open(&dir, dir_path)) {
	return false;
    }
    size_t len = strlen(dir_path);

    Io_File file;
    while(io_dir_next(&dir, &file)) {
	if(file.abs_name[len] == '.') continue;
	io_visit(file.abs_name, file.is_dir, arg);
	if(recursive && file.is_dir) {
	    if(!io_visit_files(file.abs_name, recursive, io_visit, arg)) {
		return false;
	    }
	}
    }

    io_dir_close(&dir);
    return true;
}

IO_DEF bool io_delete(const char *file_path) {
    return remove(file_path) == 0;
}

#endif //IO_IMPLEMENTATION

#endif //_IO_H_

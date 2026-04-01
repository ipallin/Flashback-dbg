"""
Common C library function signatures for extern call reconstruction.

Each entry: function_name -> {
    ret_type:  C return type string
    args:      list of (c_type, abi_reg) — abi_reg is the SysV AMD64 register
               holding this argument (rdi, rsi, rdx, rcx, r8, r9), or None for variadic
    variadic:  True if function is variadic (printf-family)
    headers:   list of #include strings required
    proto:     human-readable prototype for comments
}
"""

# fmt: off
LIBC_SIGNATURES: dict = {

    # ── stdio.h ────────────────────────────────────────────────────────────────
    "printf": {
        "ret_type": "int", "variadic": True,
        "args": [("const char*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "int printf(const char *format, ...)",
    },
    "fprintf": {
        "ret_type": "int", "variadic": True,
        "args": [("FILE*", "rdi"), ("const char*", "rsi")],
        "headers": ["<stdio.h>"],
        "proto": "int fprintf(FILE *stream, const char *format, ...)",
    },
    "sprintf": {
        "ret_type": "int", "variadic": True,
        "args": [("char*", "rdi"), ("const char*", "rsi")],
        "headers": ["<stdio.h>"],
        "proto": "int sprintf(char *str, const char *format, ...)",
    },
    "snprintf": {
        "ret_type": "int", "variadic": True,
        "args": [("char*", "rdi"), ("size_t", "rsi"), ("const char*", "rdx")],
        "headers": ["<stdio.h>"],
        "proto": "int snprintf(char *str, size_t size, const char *format, ...)",
    },
    "vprintf": {
        "ret_type": "int",
        "args": [("const char*", "rdi"), ("va_list", "rsi")],
        "headers": ["<stdio.h>"],
        "proto": "int vprintf(const char *format, va_list ap)",
    },
    "vfprintf": {
        "ret_type": "int",
        "args": [("FILE*", "rdi"), ("const char*", "rsi"), ("va_list", "rdx")],
        "headers": ["<stdio.h>"],
        "proto": "int vfprintf(FILE *stream, const char *format, va_list ap)",
    },
    "vsprintf": {
        "ret_type": "int",
        "args": [("char*", "rdi"), ("const char*", "rsi"), ("va_list", "rdx")],
        "headers": ["<stdio.h>"],
        "proto": "int vsprintf(char *str, const char *format, va_list ap)",
    },
    "vsnprintf": {
        "ret_type": "int",
        "args": [("char*", "rdi"), ("size_t", "rsi"), ("const char*", "rdx"), ("va_list", "rcx")],
        "headers": ["<stdio.h>"],
        "proto": "int vsnprintf(char *str, size_t size, const char *format, va_list ap)",
    },
    "scanf": {
        "ret_type": "int", "variadic": True,
        "args": [("const char*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "int scanf(const char *format, ...)",
    },
    "sscanf": {
        "ret_type": "int", "variadic": True,
        "args": [("const char*", "rdi"), ("const char*", "rsi")],
        "headers": ["<stdio.h>"],
        "proto": "int sscanf(const char *str, const char *format, ...)",
    },
    "fscanf": {
        "ret_type": "int", "variadic": True,
        "args": [("FILE*", "rdi"), ("const char*", "rsi")],
        "headers": ["<stdio.h>"],
        "proto": "int fscanf(FILE *stream, const char *format, ...)",
    },
    "puts": {
        "ret_type": "int",
        "args": [("const char*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "int puts(const char *s)",
    },
    "fputs": {
        "ret_type": "int",
        "args": [("const char*", "rdi"), ("FILE*", "rsi")],
        "headers": ["<stdio.h>"],
        "proto": "int fputs(const char *s, FILE *stream)",
    },
    "putchar": {
        "ret_type": "int",
        "args": [("int", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "int putchar(int c)",
    },
    "fputc": {
        "ret_type": "int",
        "args": [("int", "rdi"), ("FILE*", "rsi")],
        "headers": ["<stdio.h>"],
        "proto": "int fputc(int c, FILE *stream)",
    },
    "gets": {
        "ret_type": "char*",
        "args": [("char*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "char* gets(char *s)",
    },
    "fgets": {
        "ret_type": "char*",
        "args": [("char*", "rdi"), ("int", "rsi"), ("FILE*", "rdx")],
        "headers": ["<stdio.h>"],
        "proto": "char* fgets(char *s, int size, FILE *stream)",
    },
    "getchar": {
        "ret_type": "int",
        "args": [],
        "headers": ["<stdio.h>"],
        "proto": "int getchar(void)",
    },
    "fgetc": {
        "ret_type": "int",
        "args": [("FILE*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "int fgetc(FILE *stream)",
    },
    "getc": {
        "ret_type": "int",
        "args": [("FILE*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "int getc(FILE *stream)",
    },
    "ungetc": {
        "ret_type": "int",
        "args": [("int", "rdi"), ("FILE*", "rsi")],
        "headers": ["<stdio.h>"],
        "proto": "int ungetc(int c, FILE *stream)",
    },
    "fopen": {
        "ret_type": "FILE*",
        "args": [("const char*", "rdi"), ("const char*", "rsi")],
        "headers": ["<stdio.h>"],
        "proto": "FILE* fopen(const char *pathname, const char *mode)",
    },
    "fclose": {
        "ret_type": "int",
        "args": [("FILE*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "int fclose(FILE *stream)",
    },
    "fread": {
        "ret_type": "size_t",
        "args": [("void*", "rdi"), ("size_t", "rsi"), ("size_t", "rdx"), ("FILE*", "rcx")],
        "headers": ["<stdio.h>"],
        "proto": "size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)",
    },
    "fwrite": {
        "ret_type": "size_t",
        "args": [("const void*", "rdi"), ("size_t", "rsi"), ("size_t", "rdx"), ("FILE*", "rcx")],
        "headers": ["<stdio.h>"],
        "proto": "size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)",
    },
    "fseek": {
        "ret_type": "int",
        "args": [("FILE*", "rdi"), ("long", "rsi"), ("int", "rdx")],
        "headers": ["<stdio.h>"],
        "proto": "int fseek(FILE *stream, long offset, int whence)",
    },
    "ftell": {
        "ret_type": "long",
        "args": [("FILE*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "long ftell(FILE *stream)",
    },
    "rewind": {
        "ret_type": "void",
        "args": [("FILE*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "void rewind(FILE *stream)",
    },
    "fflush": {
        "ret_type": "int",
        "args": [("FILE*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "int fflush(FILE *stream)",
    },
    "feof": {
        "ret_type": "int",
        "args": [("FILE*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "int feof(FILE *stream)",
    },
    "ferror": {
        "ret_type": "int",
        "args": [("FILE*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "int ferror(FILE *stream)",
    },
    "perror": {
        "ret_type": "void",
        "args": [("const char*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "void perror(const char *s)",
    },
    "remove": {
        "ret_type": "int",
        "args": [("const char*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "int remove(const char *pathname)",
    },
    "rename": {
        "ret_type": "int",
        "args": [("const char*", "rdi"), ("const char*", "rsi")],
        "headers": ["<stdio.h>"],
        "proto": "int rename(const char *oldpath, const char *newpath)",
    },
    "tmpfile": {
        "ret_type": "FILE*",
        "args": [],
        "headers": ["<stdio.h>"],
        "proto": "FILE* tmpfile(void)",
    },
    "fileno": {
        "ret_type": "int",
        "args": [("FILE*", "rdi")],
        "headers": ["<stdio.h>"],
        "proto": "int fileno(FILE *stream)",
    },

    # ── stdlib.h ───────────────────────────────────────────────────────────────
    "malloc": {
        "ret_type": "void*",
        "args": [("size_t", "rdi")],
        "headers": ["<stdlib.h>"],
        "proto": "void* malloc(size_t size)",
    },
    "calloc": {
        "ret_type": "void*",
        "args": [("size_t", "rdi"), ("size_t", "rsi")],
        "headers": ["<stdlib.h>"],
        "proto": "void* calloc(size_t nmemb, size_t size)",
    },
    "realloc": {
        "ret_type": "void*",
        "args": [("void*", "rdi"), ("size_t", "rsi")],
        "headers": ["<stdlib.h>"],
        "proto": "void* realloc(void *ptr, size_t size)",
    },
    "free": {
        "ret_type": "void",
        "args": [("void*", "rdi")],
        "headers": ["<stdlib.h>"],
        "proto": "void free(void *ptr)",
    },
    "exit": {
        "ret_type": "void",
        "args": [("int", "rdi")],
        "headers": ["<stdlib.h>"],
        "proto": "void exit(int status)",
    },
    "_exit": {
        "ret_type": "void",
        "args": [("int", "rdi")],
        "headers": ["<unistd.h>"],
        "proto": "void _exit(int status)",
    },
    "abort": {
        "ret_type": "void",
        "args": [],
        "headers": ["<stdlib.h>"],
        "proto": "void abort(void)",
    },
    "atexit": {
        "ret_type": "int",
        "args": [("void(*)(void)", "rdi")],
        "headers": ["<stdlib.h>"],
        "proto": "int atexit(void (*func)(void))",
    },
    "getenv": {
        "ret_type": "char*",
        "args": [("const char*", "rdi")],
        "headers": ["<stdlib.h>"],
        "proto": "char* getenv(const char *name)",
    },
    "putenv": {
        "ret_type": "int",
        "args": [("char*", "rdi")],
        "headers": ["<stdlib.h>"],
        "proto": "int putenv(char *string)",
    },
    "setenv": {
        "ret_type": "int",
        "args": [("const char*", "rdi"), ("const char*", "rsi"), ("int", "rdx")],
        "headers": ["<stdlib.h>"],
        "proto": "int setenv(const char *name, const char *value, int overwrite)",
    },
    "unsetenv": {
        "ret_type": "int",
        "args": [("const char*", "rdi")],
        "headers": ["<stdlib.h>"],
        "proto": "int unsetenv(const char *name)",
    },
    "system": {
        "ret_type": "int",
        "args": [("const char*", "rdi")],
        "headers": ["<stdlib.h>"],
        "proto": "int system(const char *command)",
    },
    "atoi": {
        "ret_type": "int",
        "args": [("const char*", "rdi")],
        "headers": ["<stdlib.h>"],
        "proto": "int atoi(const char *nptr)",
    },
    "atol": {
        "ret_type": "long",
        "args": [("const char*", "rdi")],
        "headers": ["<stdlib.h>"],
        "proto": "long atol(const char *nptr)",
    },
    "atoll": {
        "ret_type": "long long",
        "args": [("const char*", "rdi")],
        "headers": ["<stdlib.h>"],
        "proto": "long long atoll(const char *nptr)",
    },
    "strtol": {
        "ret_type": "long",
        "args": [("const char*", "rdi"), ("char**", "rsi"), ("int", "rdx")],
        "headers": ["<stdlib.h>"],
        "proto": "long strtol(const char *nptr, char **endptr, int base)",
    },
    "strtoul": {
        "ret_type": "unsigned long",
        "args": [("const char*", "rdi"), ("char**", "rsi"), ("int", "rdx")],
        "headers": ["<stdlib.h>"],
        "proto": "unsigned long strtoul(const char *nptr, char **endptr, int base)",
    },
    "strtoll": {
        "ret_type": "long long",
        "args": [("const char*", "rdi"), ("char**", "rsi"), ("int", "rdx")],
        "headers": ["<stdlib.h>"],
        "proto": "long long strtoll(const char *nptr, char **endptr, int base)",
    },
    "strtoull": {
        "ret_type": "unsigned long long",
        "args": [("const char*", "rdi"), ("char**", "rsi"), ("int", "rdx")],
        "headers": ["<stdlib.h>"],
        "proto": "unsigned long long strtoull(const char *nptr, char **endptr, int base)",
    },
    "strtod": {
        "ret_type": "double",
        "args": [("const char*", "rdi"), ("char**", "rsi")],
        "headers": ["<stdlib.h>"],
        "proto": "double strtod(const char *nptr, char **endptr)",
    },
    "abs": {
        "ret_type": "int",
        "args": [("int", "rdi")],
        "headers": ["<stdlib.h>"],
        "proto": "int abs(int j)",
    },
    "labs": {
        "ret_type": "long",
        "args": [("long", "rdi")],
        "headers": ["<stdlib.h>"],
        "proto": "long labs(long j)",
    },
    "rand": {
        "ret_type": "int",
        "args": [],
        "headers": ["<stdlib.h>"],
        "proto": "int rand(void)",
    },
    "srand": {
        "ret_type": "void",
        "args": [("unsigned int", "rdi")],
        "headers": ["<stdlib.h>"],
        "proto": "void srand(unsigned int seed)",
    },
    "qsort": {
        "ret_type": "void",
        "args": [("void*", "rdi"), ("size_t", "rsi"), ("size_t", "rdx"), ("int(*)(const void*, const void*)", "rcx")],
        "headers": ["<stdlib.h>"],
        "proto": "void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void*, const void*))",
    },
    "bsearch": {
        "ret_type": "void*",
        "args": [("const void*", "rdi"), ("const void*", "rsi"), ("size_t", "rdx"),
                 ("size_t", "rcx"), ("int(*)(const void*, const void*)", "r8")],
        "headers": ["<stdlib.h>"],
        "proto": "void* bsearch(const void *key, const void *base, size_t nmemb, size_t size, int (*compar)(const void*, const void*))",
    },

    # ── string.h ───────────────────────────────────────────────────────────────
    "strlen": {
        "ret_type": "size_t",
        "args": [("const char*", "rdi")],
        "headers": ["<string.h>"],
        "proto": "size_t strlen(const char *s)",
    },
    "strnlen": {
        "ret_type": "size_t",
        "args": [("const char*", "rdi"), ("size_t", "rsi")],
        "headers": ["<string.h>"],
        "proto": "size_t strnlen(const char *s, size_t maxlen)",
    },
    "strcpy": {
        "ret_type": "char*",
        "args": [("char*", "rdi"), ("const char*", "rsi")],
        "headers": ["<string.h>"],
        "proto": "char* strcpy(char *dest, const char *src)",
    },
    "strncpy": {
        "ret_type": "char*",
        "args": [("char*", "rdi"), ("const char*", "rsi"), ("size_t", "rdx")],
        "headers": ["<string.h>"],
        "proto": "char* strncpy(char *dest, const char *src, size_t n)",
    },
    "strcat": {
        "ret_type": "char*",
        "args": [("char*", "rdi"), ("const char*", "rsi")],
        "headers": ["<string.h>"],
        "proto": "char* strcat(char *dest, const char *src)",
    },
    "strncat": {
        "ret_type": "char*",
        "args": [("char*", "rdi"), ("const char*", "rsi"), ("size_t", "rdx")],
        "headers": ["<string.h>"],
        "proto": "char* strncat(char *dest, const char *src, size_t n)",
    },
    "strcmp": {
        "ret_type": "int",
        "args": [("const char*", "rdi"), ("const char*", "rsi")],
        "headers": ["<string.h>"],
        "proto": "int strcmp(const char *s1, const char *s2)",
    },
    "strncmp": {
        "ret_type": "int",
        "args": [("const char*", "rdi"), ("const char*", "rsi"), ("size_t", "rdx")],
        "headers": ["<string.h>"],
        "proto": "int strncmp(const char *s1, const char *s2, size_t n)",
    },
    "strcasecmp": {
        "ret_type": "int",
        "args": [("const char*", "rdi"), ("const char*", "rsi")],
        "headers": ["<string.h>"],
        "proto": "int strcasecmp(const char *s1, const char *s2)",
    },
    "strncasecmp": {
        "ret_type": "int",
        "args": [("const char*", "rdi"), ("const char*", "rsi"), ("size_t", "rdx")],
        "headers": ["<string.h>"],
        "proto": "int strncasecmp(const char *s1, const char *s2, size_t n)",
    },
    "strchr": {
        "ret_type": "char*",
        "args": [("const char*", "rdi"), ("int", "rsi")],
        "headers": ["<string.h>"],
        "proto": "char* strchr(const char *s, int c)",
    },
    "strrchr": {
        "ret_type": "char*",
        "args": [("const char*", "rdi"), ("int", "rsi")],
        "headers": ["<string.h>"],
        "proto": "char* strrchr(const char *s, int c)",
    },
    "strstr": {
        "ret_type": "char*",
        "args": [("const char*", "rdi"), ("const char*", "rsi")],
        "headers": ["<string.h>"],
        "proto": "char* strstr(const char *haystack, const char *needle)",
    },
    "strtok": {
        "ret_type": "char*",
        "args": [("char*", "rdi"), ("const char*", "rsi")],
        "headers": ["<string.h>"],
        "proto": "char* strtok(char *str, const char *delim)",
    },
    "strtok_r": {
        "ret_type": "char*",
        "args": [("char*", "rdi"), ("const char*", "rsi"), ("char**", "rdx")],
        "headers": ["<string.h>"],
        "proto": "char* strtok_r(char *str, const char *delim, char **saveptr)",
    },
    "strdup": {
        "ret_type": "char*",
        "args": [("const char*", "rdi")],
        "headers": ["<string.h>"],
        "proto": "char* strdup(const char *s)",
    },
    "strndup": {
        "ret_type": "char*",
        "args": [("const char*", "rdi"), ("size_t", "rsi")],
        "headers": ["<string.h>"],
        "proto": "char* strndup(const char *s, size_t n)",
    },
    "strerror": {
        "ret_type": "char*",
        "args": [("int", "rdi")],
        "headers": ["<string.h>"],
        "proto": "char* strerror(int errnum)",
    },
    "memcpy": {
        "ret_type": "void*",
        "args": [("void*", "rdi"), ("const void*", "rsi"), ("size_t", "rdx")],
        "headers": ["<string.h>"],
        "proto": "void* memcpy(void *dest, const void *src, size_t n)",
    },
    "memmove": {
        "ret_type": "void*",
        "args": [("void*", "rdi"), ("const void*", "rsi"), ("size_t", "rdx")],
        "headers": ["<string.h>"],
        "proto": "void* memmove(void *dest, const void *src, size_t n)",
    },
    "memset": {
        "ret_type": "void*",
        "args": [("void*", "rdi"), ("int", "rsi"), ("size_t", "rdx")],
        "headers": ["<string.h>"],
        "proto": "void* memset(void *s, int c, size_t n)",
    },
    "memcmp": {
        "ret_type": "int",
        "args": [("const void*", "rdi"), ("const void*", "rsi"), ("size_t", "rdx")],
        "headers": ["<string.h>"],
        "proto": "int memcmp(const void *s1, const void *s2, size_t n)",
    },
    "memchr": {
        "ret_type": "void*",
        "args": [("const void*", "rdi"), ("int", "rsi"), ("size_t", "rdx")],
        "headers": ["<string.h>"],
        "proto": "void* memchr(const void *s, int c, size_t n)",
    },
    "bzero": {
        "ret_type": "void",
        "args": [("void*", "rdi"), ("size_t", "rsi")],
        "headers": ["<strings.h>"],
        "proto": "void bzero(void *s, size_t n)",
    },
    "bcopy": {
        "ret_type": "void",
        "args": [("const void*", "rdi"), ("void*", "rsi"), ("size_t", "rdx")],
        "headers": ["<strings.h>"],
        "proto": "void bcopy(const void *src, void *dest, size_t n)",
    },

    # ── unistd.h ───────────────────────────────────────────────────────────────
    "read": {
        "ret_type": "ssize_t",
        "args": [("int", "rdi"), ("void*", "rsi"), ("size_t", "rdx")],
        "headers": ["<unistd.h>"],
        "proto": "ssize_t read(int fd, void *buf, size_t count)",
    },
    "write": {
        "ret_type": "ssize_t",
        "args": [("int", "rdi"), ("const void*", "rsi"), ("size_t", "rdx")],
        "headers": ["<unistd.h>"],
        "proto": "ssize_t write(int fd, const void *buf, size_t count)",
    },
    "open": {
        "ret_type": "int", "variadic": True,
        "args": [("const char*", "rdi"), ("int", "rsi")],
        "headers": ["<fcntl.h>"],
        "proto": "int open(const char *pathname, int flags, ...)",
    },
    "close": {
        "ret_type": "int",
        "args": [("int", "rdi")],
        "headers": ["<unistd.h>"],
        "proto": "int close(int fd)",
    },
    "lseek": {
        "ret_type": "off_t",
        "args": [("int", "rdi"), ("off_t", "rsi"), ("int", "rdx")],
        "headers": ["<unistd.h>"],
        "proto": "off_t lseek(int fd, off_t offset, int whence)",
    },
    "sleep": {
        "ret_type": "unsigned int",
        "args": [("unsigned int", "rdi")],
        "headers": ["<unistd.h>"],
        "proto": "unsigned int sleep(unsigned int seconds)",
    },
    "usleep": {
        "ret_type": "int",
        "args": [("useconds_t", "rdi")],
        "headers": ["<unistd.h>"],
        "proto": "int usleep(useconds_t usec)",
    },
    "getpid": {
        "ret_type": "pid_t",
        "args": [],
        "headers": ["<unistd.h>"],
        "proto": "pid_t getpid(void)",
    },
    "getppid": {
        "ret_type": "pid_t",
        "args": [],
        "headers": ["<unistd.h>"],
        "proto": "pid_t getppid(void)",
    },
    "getuid": {
        "ret_type": "uid_t",
        "args": [],
        "headers": ["<unistd.h>"],
        "proto": "uid_t getuid(void)",
    },
    "geteuid": {
        "ret_type": "uid_t",
        "args": [],
        "headers": ["<unistd.h>"],
        "proto": "uid_t geteuid(void)",
    },
    "getgid": {
        "ret_type": "gid_t",
        "args": [],
        "headers": ["<unistd.h>"],
        "proto": "gid_t getgid(void)",
    },
    "getegid": {
        "ret_type": "gid_t",
        "args": [],
        "headers": ["<unistd.h>"],
        "proto": "gid_t getegid(void)",
    },
    "fork": {
        "ret_type": "pid_t",
        "args": [],
        "headers": ["<unistd.h>"],
        "proto": "pid_t fork(void)",
    },
    "execve": {
        "ret_type": "int",
        "args": [("const char*", "rdi"), ("char* const*", "rsi"), ("char* const*", "rdx")],
        "headers": ["<unistd.h>"],
        "proto": "int execve(const char *pathname, char *const argv[], char *const envp[])",
    },
    "pipe": {
        "ret_type": "int",
        "args": [("int*", "rdi")],
        "headers": ["<unistd.h>"],
        "proto": "int pipe(int pipefd[2])",
    },
    "dup": {
        "ret_type": "int",
        "args": [("int", "rdi")],
        "headers": ["<unistd.h>"],
        "proto": "int dup(int oldfd)",
    },
    "dup2": {
        "ret_type": "int",
        "args": [("int", "rdi"), ("int", "rsi")],
        "headers": ["<unistd.h>"],
        "proto": "int dup2(int oldfd, int newfd)",
    },
    "getcwd": {
        "ret_type": "char*",
        "args": [("char*", "rdi"), ("size_t", "rsi")],
        "headers": ["<unistd.h>"],
        "proto": "char* getcwd(char *buf, size_t size)",
    },
    "chdir": {
        "ret_type": "int",
        "args": [("const char*", "rdi")],
        "headers": ["<unistd.h>"],
        "proto": "int chdir(const char *path)",
    },
    "access": {
        "ret_type": "int",
        "args": [("const char*", "rdi"), ("int", "rsi")],
        "headers": ["<unistd.h>"],
        "proto": "int access(const char *pathname, int mode)",
    },
    "unlink": {
        "ret_type": "int",
        "args": [("const char*", "rdi")],
        "headers": ["<unistd.h>"],
        "proto": "int unlink(const char *pathname)",
    },

    # ── math.h ─────────────────────────────────────────────────────────────────
    "sqrt": {
        "ret_type": "double",
        "args": [("double", "xmm0")],
        "headers": ["<math.h>"],
        "proto": "double sqrt(double x)",
    },
    "pow": {
        "ret_type": "double",
        "args": [("double", "xmm0"), ("double", "xmm1")],
        "headers": ["<math.h>"],
        "proto": "double pow(double x, double y)",
    },
    "fabs": {
        "ret_type": "double",
        "args": [("double", "xmm0")],
        "headers": ["<math.h>"],
        "proto": "double fabs(double x)",
    },

    # ── sys/socket.h ───────────────────────────────────────────────────────────
    "socket": {
        "ret_type": "int",
        "args": [("int", "rdi"), ("int", "rsi"), ("int", "rdx")],
        "headers": ["<sys/socket.h>"],
        "proto": "int socket(int domain, int type, int protocol)",
    },
    "connect": {
        "ret_type": "int",
        "args": [("int", "rdi"), ("const struct sockaddr*", "rsi"), ("socklen_t", "rdx")],
        "headers": ["<sys/socket.h>"],
        "proto": "int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)",
    },
    "bind": {
        "ret_type": "int",
        "args": [("int", "rdi"), ("const struct sockaddr*", "rsi"), ("socklen_t", "rdx")],
        "headers": ["<sys/socket.h>"],
        "proto": "int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)",
    },
    "listen": {
        "ret_type": "int",
        "args": [("int", "rdi"), ("int", "rsi")],
        "headers": ["<sys/socket.h>"],
        "proto": "int listen(int sockfd, int backlog)",
    },
    "accept": {
        "ret_type": "int",
        "args": [("int", "rdi"), ("struct sockaddr*", "rsi"), ("socklen_t*", "rdx")],
        "headers": ["<sys/socket.h>"],
        "proto": "int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)",
    },
    "send": {
        "ret_type": "ssize_t",
        "args": [("int", "rdi"), ("const void*", "rsi"), ("size_t", "rdx"), ("int", "rcx")],
        "headers": ["<sys/socket.h>"],
        "proto": "ssize_t send(int sockfd, const void *buf, size_t len, int flags)",
    },
    "recv": {
        "ret_type": "ssize_t",
        "args": [("int", "rdi"), ("void*", "rsi"), ("size_t", "rdx"), ("int", "rcx")],
        "headers": ["<sys/socket.h>"],
        "proto": "ssize_t recv(int sockfd, void *buf, size_t len, int flags)",
    },
    "setsockopt": {
        "ret_type": "int",
        "args": [("int", "rdi"), ("int", "rsi"), ("int", "rdx"),
                 ("const void*", "rcx"), ("socklen_t", "r8")],
        "headers": ["<sys/socket.h>"],
        "proto": "int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)",
    },
    "getsockopt": {
        "ret_type": "int",
        "args": [("int", "rdi"), ("int", "rsi"), ("int", "rdx"),
                 ("void*", "rcx"), ("socklen_t*", "r8")],
        "headers": ["<sys/socket.h>"],
        "proto": "int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)",
    },

    # ── time.h ─────────────────────────────────────────────────────────────────
    "time": {
        "ret_type": "time_t",
        "args": [("time_t*", "rdi")],
        "headers": ["<time.h>"],
        "proto": "time_t time(time_t *tloc)",
    },
    "clock": {
        "ret_type": "clock_t",
        "args": [],
        "headers": ["<time.h>"],
        "proto": "clock_t clock(void)",
    },
    "gmtime": {
        "ret_type": "struct tm*",
        "args": [("const time_t*", "rdi")],
        "headers": ["<time.h>"],
        "proto": "struct tm* gmtime(const time_t *timep)",
    },
    "localtime": {
        "ret_type": "struct tm*",
        "args": [("const time_t*", "rdi")],
        "headers": ["<time.h>"],
        "proto": "struct tm* localtime(const time_t *timep)",
    },
    "mktime": {
        "ret_type": "time_t",
        "args": [("struct tm*", "rdi")],
        "headers": ["<time.h>"],
        "proto": "time_t mktime(struct tm *tm)",
    },
    "strftime": {
        "ret_type": "size_t",
        "args": [("char*", "rdi"), ("size_t", "rsi"), ("const char*", "rdx"), ("const struct tm*", "rcx")],
        "headers": ["<time.h>"],
        "proto": "size_t strftime(char *s, size_t max, const char *format, const struct tm *tm)",
    },
    "nanosleep": {
        "ret_type": "int",
        "args": [("const struct timespec*", "rdi"), ("struct timespec*", "rsi")],
        "headers": ["<time.h>"],
        "proto": "int nanosleep(const struct timespec *req, struct timespec *rem)",
    },
    "clock_gettime": {
        "ret_type": "int",
        "args": [("clockid_t", "rdi"), ("struct timespec*", "rsi")],
        "headers": ["<time.h>"],
        "proto": "int clock_gettime(clockid_t clk_id, struct timespec *tp)",
    },

    # ── pthread ────────────────────────────────────────────────────────────────
    "pthread_create": {
        "ret_type": "int",
        "args": [("pthread_t*", "rdi"), ("const pthread_attr_t*", "rsi"),
                 ("void*(*)(void*)", "rdx"), ("void*", "rcx")],
        "headers": ["<pthread.h>"],
        "proto": "int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg)",
    },
    "pthread_join": {
        "ret_type": "int",
        "args": [("pthread_t", "rdi"), ("void**", "rsi")],
        "headers": ["<pthread.h>"],
        "proto": "int pthread_join(pthread_t thread, void **retval)",
    },
    "pthread_mutex_lock": {
        "ret_type": "int",
        "args": [("pthread_mutex_t*", "rdi")],
        "headers": ["<pthread.h>"],
        "proto": "int pthread_mutex_lock(pthread_mutex_t *mutex)",
    },
    "pthread_mutex_unlock": {
        "ret_type": "int",
        "args": [("pthread_mutex_t*", "rdi")],
        "headers": ["<pthread.h>"],
        "proto": "int pthread_mutex_unlock(pthread_mutex_t *mutex)",
    },
    "pthread_exit": {
        "ret_type": "void",
        "args": [("void*", "rdi")],
        "headers": ["<pthread.h>"],
        "proto": "void pthread_exit(void *retval)",
    },

    # ── errno / error reporting ─────────────────────────────────────────────────
    "__errno_location": {
        "ret_type": "int*",
        "args": [],
        "headers": ["<errno.h>"],
        "proto": "int* __errno_location(void)",
    },
    "__stack_chk_fail": {
        "ret_type": "void",
        "args": [],
        "headers": [],
        "proto": "void __stack_chk_fail(void)",
    },

    # ── ctype.h ────────────────────────────────────────────────────────────────
    "isalpha": {
        "ret_type": "int",
        "args": [("int", "rdi")],
        "headers": ["<ctype.h>"],
        "proto": "int isalpha(int c)",
    },
    "isdigit": {
        "ret_type": "int",
        "args": [("int", "rdi")],
        "headers": ["<ctype.h>"],
        "proto": "int isdigit(int c)",
    },
    "isalnum": {
        "ret_type": "int",
        "args": [("int", "rdi")],
        "headers": ["<ctype.h>"],
        "proto": "int isalnum(int c)",
    },
    "isspace": {
        "ret_type": "int",
        "args": [("int", "rdi")],
        "headers": ["<ctype.h>"],
        "proto": "int isspace(int c)",
    },
    "isupper": {
        "ret_type": "int",
        "args": [("int", "rdi")],
        "headers": ["<ctype.h>"],
        "proto": "int isupper(int c)",
    },
    "islower": {
        "ret_type": "int",
        "args": [("int", "rdi")],
        "headers": ["<ctype.h>"],
        "proto": "int islower(int c)",
    },
    "toupper": {
        "ret_type": "int",
        "args": [("int", "rdi")],
        "headers": ["<ctype.h>"],
        "proto": "int toupper(int c)",
    },
    "tolower": {
        "ret_type": "int",
        "args": [("int", "rdi")],
        "headers": ["<ctype.h>"],
        "proto": "int tolower(int c)",
    },
}
# fmt: on

# Integer argument registers in SysV AMD64 ABI order
ABI_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]


def get_signature(name: str) -> dict | None:
    """Return function signature dict or None if not known."""
    return LIBC_SIGNATURES.get(name)

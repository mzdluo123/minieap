#ifndef TYPES_H
#define TYPES_H
typedef unsigned char *POINTER;
#if defined(_WIN32) && (defined(_WINDEF_) || defined(_WINDEF_H) || defined(_INC_WINDOWS))
/* BYTE/UCHAR/WORD/LONG/DWORD come from windows.h */
#else
typedef unsigned char BYTE;
typedef unsigned char UCHAR;
typedef unsigned short int WORD;
typedef int LONG;
typedef unsigned int DWORD;
#endif
typedef unsigned int UINT4;
#endif

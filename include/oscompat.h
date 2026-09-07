#ifndef MINIEAP_OSCOMPAT_H
#define MINIEAP_OSCOMPAT_H
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#ifndef IFNAMSIZ
#define IFNAMSIZ 256
#endif
#ifndef ETH_P_PAE
#define ETH_P_PAE 0x888e
#endif
#ifndef S_IRUSR
#define S_IRUSR 0
#define S_IWUSR 0
#endif
#ifdef _MSC_VER
#include "getopt.h"
#define strdup _strdup
#else
#include <getopt.h>
#endif
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <getopt.h>
#endif
#endif

#include "getopt.h"

#include <stdio.h>
#include <string.h>

char* optarg;
int optind = 1;
int opterr = 1;
int optopt;

static const char* optcursor;

enum {
    ORDER_PERMUTE = 0,
    ORDER_REQUIRE,
    ORDER_RETURN_IN_ORDER
};

static int g_ordering;
static int g_optstring_parsed;

static int parse_optstring_prefix(const char** poptstring) {
    const char* s = *poptstring;
    int silent = 0;
    g_ordering = ORDER_PERMUTE;
    if (s[0] == '-') {
        g_ordering = ORDER_RETURN_IN_ORDER;
        s++;
    } else if (s[0] == '+') {
        g_ordering = ORDER_REQUIRE;
        s++;
    }
    if (s[0] == ':') {
        silent = 1;
        s++;
    }
    *poptstring = s;
    return silent;
}

static const struct option* find_longopt(const struct option* longopts,
                                         const char* name, size_t namelen,
                                         int* ambiguous) {
    const struct option* match = NULL;
    const struct option* p;
    *ambiguous = 0;
    if (!longopts) {
        return NULL;
    }
    for (p = longopts; p->name; ++p) {
        if (strncmp(p->name, name, namelen) != 0) {
            continue;
        }
        if (p->name[namelen] == '\0') {
            return p;
        }
        if (match) {
            *ambiguous = 1;
        } else {
            match = p;
        }
    }
    return match;
}

static const char* find_shortopt(const char* optstring, int c) {
    const char* p = optstring;
    while (*p) {
        if (*p == c) {
            return p;
        }
        ++p;
    }
    return NULL;
}

int getopt_long(int argc, char* const argv[], const char* optstring,
                const struct option* longopts, int* longindex) {
    int silent;
    const char* os;
    char* arg;

    optarg = NULL;
    if (longindex) {
        *longindex = 0;
    }

    if (optind <= 0) {
        optind = 1;
        optcursor = NULL;
        g_optstring_parsed = 0;
    }

    os = optstring ? optstring : "";
    silent = parse_optstring_prefix(&os);
    if (!g_optstring_parsed) {
        g_optstring_parsed = 1;
    }
    if (opterr == 0) {
        silent = 1;
    }

    if (optcursor && *optcursor == '\0') {
        optcursor = NULL;
    }

    if (!optcursor) {
        if (optind >= argc) {
            g_optstring_parsed = 0;
            return -1;
        }
        arg = argv[optind];
        if (arg[0] != '-' || arg[1] == '\0') {
            if (g_ordering == ORDER_REQUIRE) {
                return -1;
            }
            if (g_ordering == ORDER_RETURN_IN_ORDER) {
                optarg = arg;
                optind++;
                return 1;
            }
            /* GNU permute: keep scanning for options after non-options */
            {
                int i;
                for (i = optind; i < argc; ++i) {
                    if (argv[i][0] == '-' && argv[i][1] != '\0') {
                        optind = i;
                        arg = argv[i];
                        break;
                    }
                }
                if (i >= argc) {
                    return -1;
                }
            }
        }
        if (arg[0] == '-' && arg[1] == '-' && arg[2] == '\0') {
            optind++;
            return -1;
        }
        if (arg[0] == '-' && arg[1] == '-') {
            const char* name = arg + 2;
            const char* eq = strchr(name, '=');
            size_t namelen = eq ? (size_t)(eq - name) : strlen(name);
            int ambiguous = 0;
            const struct option* o = find_longopt(longopts, name, namelen, &ambiguous);
            optind++;
            if (!o || ambiguous) {
                optopt = 0;
                if (!silent) {
                    fprintf(stderr, "%s: %s option '%s'\n",
                            argv[0] ? argv[0] : "",
                            ambiguous ? "ambiguous" : "unrecognized",
                            arg);
                }
                return '?';
            }
            if (longindex) {
                int idx = 0;
                const struct option* p;
                for (p = longopts; p != o; ++p) {
                    ++idx;
                }
                *longindex = idx;
            }
            if (o->has_arg == required_argument) {
                if (eq) {
                    optarg = (char*)eq + 1;
                } else if (optind < argc) {
                    optarg = argv[optind++];
                } else {
                    optopt = o->val;
                    if (!silent) {
                        fprintf(stderr, "%s: option '--%s' requires an argument\n",
                                argv[0] ? argv[0] : "", o->name);
                    }
                    return silent ? ':' : '?';
                }
            } else if (o->has_arg == optional_argument) {
                if (eq) {
                    optarg = (char*)eq + 1;
                }
            } else if (eq) {
                optopt = o->val;
                if (!silent) {
                    fprintf(stderr, "%s: option '--%s' doesn't allow an argument\n",
                            argv[0] ? argv[0] : "", o->name);
                }
                return '?';
            }
            if (o->flag) {
                *o->flag = o->val;
                return 0;
            }
            return o->val;
        }
        optcursor = arg + 1;
        optind++;
    }

    optopt = (unsigned char)*optcursor++;
    {
        const char* so = find_shortopt(os, optopt);
        int has_arg = 0;
        int optional = 0;
        if (!so) {
            if (!silent) {
                fprintf(stderr, "%s: invalid option -- '%c'\n",
                        argv[0] ? argv[0] : "", optopt);
            }
            if (*optcursor == '\0') {
                optcursor = NULL;
            }
            return '?';
        }
        if (so[1] == ':') {
            has_arg = 1;
            if (so[2] == ':') {
                optional = 1;
            }
        }
        if (has_arg) {
            if (*optcursor) {
                optarg = (char*)optcursor;
                optcursor = NULL;
            } else if (optional) {
                optarg = NULL;
                optcursor = NULL;
            } else if (optind < argc) {
                optarg = argv[optind++];
                optcursor = NULL;
            } else {
                optcursor = NULL;
                if (!silent) {
                    fprintf(stderr, "%s: option requires an argument -- '%c'\n",
                            argv[0] ? argv[0] : "", optopt);
                }
                return silent ? ':' : '?';
            }
        } else if (*optcursor == '\0') {
            optcursor = NULL;
        }
        return optopt;
    }
}

int getopt(int argc, char* const argv[], const char* optstring) {
    return getopt_long(argc, argv, optstring, NULL, NULL);
}

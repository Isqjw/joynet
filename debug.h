#ifndef __DEBUG_H
#define __DEBUG_H

#include <stdio.h>
#include <string.h>

#define DEBUG

#ifdef DEBUG
    #define debug_msg(fmt, ...) printf("[%s][%s][%s][%s][%d]:"fmt"\n", __FILE__, __FUNCTION__, __DATE__, __TIME__, __LINE__, ##__VA_ARGS__)
#else
    #include "log/tlog_concise.h"
    #define debug_msg(fmt, ...) clog_info(fmt, ##__VA_ARGS__)
#endif


#endif

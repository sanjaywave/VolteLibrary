
#ifndef LIBQCDM_ERRORS_H
#define LIBQCDM_ERRORS_H

#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>


#define validateLength(x ,y) if(sizeof(x) > y)	\
							{ 	\
								d_warning("length is less than buffer receive \n"); \
								return 0;	\
							}	\

enum {  LOGL_ERR = 1, LOGL_WARN = 2, LOGL_DEBUG = 3 ,LOGL_SUCCESS = 4 };

enum {
	QCDM_LOGL_ERR   = 0x00000001,
	QCDM_LOGL_WARN  = 0x00000002,
	QCDM_LOGL_INFO  = 0x00000004,
	QCDM_LOGL_DEBUG = 0x00000008
};



void Log_Trace(const char *file,int line,const char *func, int level,const char *format, ...);
enum {
    QCDM_SUCCESS = 0,
    QCDM_ERROR_INVALID_ARGUMENTS = 1,
    QCDM_ERROR_SERIAL_CONFIG_FAILED = 2,
    QCDM_ERROR_VALUE_NOT_FOUND = 3,
    QCDM_ERROR_RESPONSE_UNEXPECTED = 4,
    QCDM_ERROR_RESPONSE_BAD_LENGTH = 5,
    QCDM_ERROR_RESPONSE_MALFORMED = 6,
    QCDM_ERROR_RESPONSE_BAD_COMMAND = 7,
    QCDM_ERROR_RESPONSE_BAD_PARAMETER = 8,
    QCDM_ERROR_RESPONSE_NOT_ACCEPTED = 9,
    QCDM_ERROR_RESPONSE_BAD_MODE = 10,
    QCDM_ERROR_NVCMD_FAILED = 11,
    QCDM_ERROR_SPC_LOCKED = 12,
    QCDM_ERROR_NV_ERROR_BUSY = 13,
    QCDM_ERROR_NV_ERROR_BAD_COMMAND = 14,
    QCDM_ERROR_NV_ERROR_MEMORY_FULL = 15,
    QCDM_ERROR_NV_ERROR_FAILED = 16,
    QCDM_ERROR_NV_ERROR_INACTIVE = 17,  /* NV location is not active */
    QCDM_ERROR_NV_ERROR_BAD_PARAMETER = 18,
    QCDM_ERROR_NV_ERROR_READ_ONLY = 19, /* NV location is read-only */
    QCDM_ERROR_RESPONSE_FAILED = 20,    /* command-specific failure */
};

#define qcdm_assert assert
#define qcdm_assert_not_reached() assert(0)

#define qcdm_return_if_fail(e) \
{ \
    if (!(e)) { \
        qcdm_warn (0, "failed: " #e "\n"); \
        return; \
    } \
}

#define qcdm_return_val_if_fail(e, v) \
{ \
    if (!(e)) { \
        qcdm_warn (0, "failed: " #e "\n"); \
        return v; \
    } \
}

#define qcdm_warn_if_fail(e) \
{ \
    if (!(e)) { \
        qcdm_warn (0, "failed: " #e "\n"); \
    } \
}

void _qcdm_log (const char *file,
                int line,
                const char *func,
                int domain,
                int level,
                const char *format,
                ...) __attribute__((__format__ (__printf__, 6, 7)));

#define qcdm_dbg(domain, ...) \
	_qcdm_log (__FILE__, __LINE__, __func__, domain, QCDM_LOGL_DEBUG, ## __VA_ARGS__ )

#define qcdm_warn(domain, ...) \
	_qcdm_log (__FILE__, __LINE__, __func__, domain, QCDM_LOGL_WARN, ## __VA_ARGS__ )

#define qcdm_err(domain, ...) \
	_qcdm_log (__FILE__, __LINE__, __func__, domain, QCDM_LOGL_ERR, ## __VA_ARGS__ )

void Log_Trace(const char *file,int line,const char *func, int level,const char *format, ...);

#ifdef DEBUG
	#define  PHONE_CAPTURE_LOG  d_log_print
	#define d_arraylog  d_arraylog	_print
#else
	#define PHONE_CAPTURE_LOG
	#define d_arraylog
#endif

#endif  /* LIBQCDM_ERRORS_H */


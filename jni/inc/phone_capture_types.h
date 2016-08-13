#ifndef _PHONE_CAPTURE_TYPES_H_
#define _PHONE_CAPTURE_TYPES_H_
/*********************************************************************************
 *  Header File Contents - Start - types.h
 ********************************************************************************/

//#ifdef MS_VC
/* VC++ definitions */
/* VC++ doesn't ship with a complete standard library */
typedef char      S8;
typedef unsigned char      U8;
typedef short     S16;
typedef unsigned short     U16;
typedef int       S32;
typedef unsigned int       U32;
//typedef __int64            S64;
//typedef unsigned __int64   U64;

//#else
/*
   typedef int8_t              S8;
   typedef uint8_t             U8;
   typedef int16_t             S16;
   typedef uint16_t            U16;
   typedef int32_t             S32;
   typedef uint32_t            U32;
   typedef int64_t             S64;
   typedef uint64_t            U64;
 */
//#endif  /* MS_VC */

typedef U32 in_addr_t;

/*********************************************************************************
 *  Header File Contents - End - types.h
 ********************************************************************************/

#endif

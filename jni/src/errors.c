#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "errors.h"


#define LOG_FILE_TYPE ".txt"
#define FILE_NAME_SIZE 200
#define MAX_FILE_SIZE 500000  /*(500KB FILE)*/


static unsigned int current_file_size = 0;
static unsigned int LogFileCounter = 1;
bool make_new_file= false;
FILE *filefdInternal =NULL;
char LogFileName[FILE_NAME_SIZE] ={'\0'};
int  LogFileCreatedFirstTime = 1;

void
_qcdm_log (const char *file,
           int line,
           const char *func,
           int level,
           int domain,
           const char *format,
           ...)
{
    va_list args;
    char *message = NULL;
    int n;
    const char *prefix = "info";

    qcdm_return_if_fail (format != NULL);
    qcdm_return_if_fail (format[0] != '\0');

    /* level & domain ignored for now */

    if (getenv ("QCDM_DEBUG") == NULL)
        return;

    va_start (args, format);
    n = vasprintf (&message, format, args);
    va_end (args);

    if (level & QCDM_LOGL_ERR)
        prefix = "err";
    else if (level & QCDM_LOGL_WARN)
        prefix = "warn";
    else if (level & QCDM_LOGL_DEBUG)
        prefix = "dbg";

    if (n >= 0) {
        fprintf (stderr, "<%s> [%s:%u] %s(): %s\n", prefix, file, line, func, message);
        free (message);
    }
}

void Log_Trace(const char *file,int line,const char *func, int level,const char *format, ...){
    va_list args;
    char *message = NULL;
    int n;
    const char *prefix = "Info";
     va_start (args, format);
    n = vasprintf (&message, format, args);
    va_end (args);
    if (level & LOGL_ERR)
        prefix = "Error";
    else if (level & LOGL_WARN)
        prefix = "Warning";
    else if (level & LOGL_DEBUG)
        prefix = "Debug";
    else if(level & LOGL_SUCCESS)
    	 prefix = "Success";
    if (n >= 0) {
        fprintf (stderr, "< %s > [FileName = %s : Function = %s() : Line no = %u]: %s\n", prefix, file, func,line,message);
        free (message);
    }
}

void makeNewfile(unsigned short count){
   current_file_size += count;
   if(current_file_size > MAX_FILE_SIZE){
      closeLog(); /* close the file writing*/
      enableLog(); /* make a new file */
   }
}

void d_my_log(const char *format, ...)
{
   va_list arg;
   va_start (arg, format);
   if(filefdInternal == NULL)
   	vprintf(format, arg);
   else
  		vfprintf(filefdInternal,format, arg);
   va_end (arg);
}

void d_log_print(const char *format, ...)
{
#ifdef DEBUG
	unsigned int count=0;
	va_list arg;
    va_start (arg, format);
    if(filefdInternal == NULL)
   	vprintf(format, arg);
   else
	   count = vfprintf(filefdInternal,format, arg);
   va_end (arg);
   makeNewfile(count);
#endif
}

void d_arraylog_print(char *buf , int size)
{

#ifdef DEBUG
	int i;
  	d_log(" \n");
  	for (i=0; i<size ;i++)
   	{
        d_log(" %2x " , buf[i]);
        if (i%16==0 && i!=0)
        d_log("\n");
   	}
  	d_log(" \n");
#endif
}



void d_warning(const char *format, ...)
{
   unsigned short count=0;
   va_list arg;
   va_start (arg, format);
   if(filefdInternal ==NULL)
   	vprintf(format, arg);
   else
   count=vfprintf(filefdInternal,format, arg);
   va_end (arg);
   makeNewfile(count);
}

int enableLog(){
  time_t t;
  time(&t);
  current_file_size=0;
  char tempFileName[FILE_NAME_SIZE]={'\0'};
  char LogFileName[]="/mnt/sdcard/diagApp/VoLog";
  strcpy(tempFileName,LogFileName);
  sprintf(tempFileName+strlen(LogFileName),"%03d",LogFileCounter);
  strcat(tempFileName,LOG_FILE_TYPE);
  printf("\nLogFile = %s",tempFileName);
  filefdInternal =fopen(tempFileName,"a");
  if (filefdInternal == 0)
  {
	  Log_Trace (__FILE__,__LINE__,__func__,LOGL_ERR,"Error while making Log file");
	  return -1;
  }
  printf("\nLogfile created");
  fprintf(filefdInternal,"\n //************************************************************// ");
  fprintf(filefdInternal,"\nDate:-%s",ctime(&t));
  LogFileCounter++;
  return 0;
}

int closeLog()
{
  int fclose_status=-1;
  if(filefdInternal != NULL)
	  fclose_status=fclose(filefdInternal);
  if (fclose_status)
   	return -1;
  else
     	return 0;
}


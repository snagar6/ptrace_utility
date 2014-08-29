// Program: Wrapper over the ptrace APIs - For Android POCs only ...
// By: Shreyas 


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>

#define PAGE_SIZE	4096 

const int long_size = sizeof(long);

void usage()
{
    printf("\n[myptrace]: USAGE: myptrace <option> <pid> <address>  \n");
    printf("\t\t    option => write on gva = 1; read from a gva = 2; \n");
    printf("\t\t    pid => Process ID must be  > 0 \n");
    printf("\t\t    address => Virtual Address must be > 0 \n\n");
}


int putdata(pid_t child, long addr,
             char *str, int len)
{
    char *laddr;
    int i, j;
    int ret1 = 0, ret2 = 0;
    union u {
            long val;
            char chars[long_size];
    } data;

    i = 0;
    j = len / long_size;
    laddr = str;

    if( strcmp(str, "0") == 0 )
    {
        laddr = (char *)malloc(PAGE_SIZE * sizeof(char));
	memcpy(laddr, "0", len); 
	laddr[PAGE_SIZE-1] = '\0'; 
    }

    printf("\n>>>>>>> Writing Data on to Code seg (EIP): %s at Address: 0x%lx  Length:%d  \n", laddr, addr, len);

    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ret1 = ptrace(PTRACE_POKEDATA, child, (void *)(addr + i * 4), (void *)(data.val) );

	if(ret1 == -1)
		return (errno+6000+i);

        ++i;
        laddr += long_size;
    }

    j = len % long_size;

    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ret2 = ptrace(PTRACE_POKEDATA, child, (void *)(addr + i * 4), (void *)(data.val) );

	if(ret2 == -1)
                return (errno+8000+j);

    }

    return(ret1|ret2);
}



int getdata(pid_t child, long addr,
             char *str, int len)
{ 
    char *laddr;
    int i, j;
    int ret1 = 0, ret2 = 0;
    union u {
            long val;
            char chars[long_size];
    }data;

    i = 0;
    j = len / long_size;
    laddr = str;

    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA, child, (void *)(addr + i * 4), NULL);

	if(ret1 == -1)
        	return (errno+7000+i);

        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }

    j = len % long_size;
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA, child, (void *)(addr + i * 4), NULL);
	
	if(ret2 == -1)
                return (errno+9000+i);

        memcpy(laddr, data.chars, j);
    }

    str[len] = '\0';
    // printf("\n>>>>>> Peeped into the EIP: %x %x %x at Address: 0x%lx \n", (unsigned int)laddr[0], (unsigned int)laddr[1], (unsigned int)laddr[2], addr);
    
    return(ret1|ret2);
}



int main(int argc, char *argv[])
{
    long gva = 0; int option = 0;
    int ret = 0, retval = 0;
    pid_t pid;
    char retstr[PAGE_SIZE];
    char buf[4];
    int i = 0;
    int num = 0x000000ff;
  
    if(argc <= 2)
    {
	printf("\n[myptrace]: Improper Usage of myptrace! \n");
	usage();	
	return (-1);
    } 

    option = atoi(argv[1]);
    pid = atoi(argv[2]);
    gva = (long)(atoi(argv[3]));

    if( (option == 0) || (pid == 0) || (gva == 0) )
    {
	printf("\n[myptrace]: option/pid/gva is 0!!\n");
	usage();
 	return (-2);	
    }

    if( (option != 1) && (option != 2) && (option != 3) )
    {
	printf("\n[myptrace]: Invalid option: %d \n", option);
	usage();
	return(-3);	
    } 

    // Attaching to the Victim process
    ret = ptrace(PTRACE_ATTACH, (pid_t)pid, NULL, NULL);

    if(ret == -1)
    {
   	printf("\n[myptrace]: ptrace failed - while attaching ... Errno: %d \n\n", errno);
	return (-4);	
    }
    else
	printf("\n[myptrace]: ptrace - process attach success \n\n");

    wait(NULL);

    if(option == 1)
    {
	 // Writing onto the Victim Process Address Space
	 printf("\n[myptrace]: ptrace - Writing onto the Victim process address space ... \n\n");
	 // retval = putdata((pid_t)pid, gva, "0", PAGE_SIZE); 
	 retval = putdata((pid_t)pid, gva, "0", 100);
	 printf("\n[myptrace]: ptrace - Return Value After Writing: %d \n\n", retval);
	 printf("\n[myptrace]: WRITING END !!\n");
    }
    else if (option == 2) 
    {
	 // Reading from the Victim Process Address space 
	 printf("\n[myptrace]: ptrace - Reading Content from the Victim process address space ... \n\n");
	 memset(retstr, '\0', PAGE_SIZE); 
         retval = getdata((pid_t)pid, gva, retstr, PAGE_SIZE);
	 printf("\n[myptrace]: retval: %d \n  Read Contents: \n", retval); 
	 for (i = 0; i < PAGE_SIZE; i++)
	 {
		if(retstr[i])
			printf("%x ", ( num & ((unsigned int)retstr[i]) ) );
	 }
	 printf("\n\n");
	 printf("\n[myptrace]: READING END !!\n");
    }
    else
    {
    	// Reading a few bytes and writing back the same ... onto the Victim process's address space ....
        printf("\n[myptrace]: ptrace - Reading Content from the Victim process address space ... \n\n");
        memset(buf, '\0', 4); 
	retval = getdata((pid_t)pid, gva, buf, 4);	
	printf("\n[myptrace]: retval: %d \n  Read Contents: \n", retval);
        for (i = 0; i < 4; i++)
        {
        	if(buf[i])
               		printf("%x ", ( num & ((unsigned int)buf[i]) ) );
        }
        printf("\n\n");

   	printf("\n[myptrace]: ptrace - Writing onto the Victim process address space ... \n\n");
        retval = putdata((pid_t)pid, gva, buf, 4);
        printf("\n[myptrace]: ptrace - Return Value After Writing: %d \n\n", retval);

    }

    ptrace(PTRACE_DETACH, (pid_t)pid, NULL, NULL);
    printf("\n[myptrace]: ENDING !!\n");
    
    return 0;
}     

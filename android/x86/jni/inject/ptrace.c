
#include "ptrace.h" 

#define LOGD(fmt, ...)  printf(fmt, ##__VA_ARGS__) 


/*
function: ptrace_readdata
param:
	pid: as all known
	src: address where read
	buf: buffer
	size: read bytes num
return:
	return 0
description: 
	read data at specified address
*/ 
int ptrace_readdata(pid_t pid,  uint8_t *src, uint8_t *buf, size_t size)      
{      
    long i, j, remain;      
    uint8_t *laddr;         
    const size_t bytes_width = sizeof(long);  
      
    union u 
	{      
        long val;      
        char chars[bytes_width];      
    }d;      
      
    j = size / bytes_width;      
    remain = size % bytes_width;      
      
    laddr = buf;      
      
    for (i = 0; i < j; i ++) 
	{      
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);      
        memcpy(laddr, d.chars, bytes_width);      
        src += bytes_width;      
        laddr += bytes_width;      
    }      
      
    if(remain > 0) 
	{      
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);      
        memcpy(laddr, d.chars, remain);      
    }      
      
    return 0;      
}      


/*
function: ptrace_writedata
param:
	pid: as all known
	src: address where write
	buf: buffer
	size: write bytes num	
return:
	return 0
description:
	write data at specified address
*/ 
int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size)      
{      
    long i, j, remain;      
    uint8_t *laddr;      
    const size_t bytes_width = sizeof(long);  
    
	union u 
	{      
        long val;      
        char chars[bytes_width];      
    }d;      
      
    j = size / bytes_width;      
    remain = size % bytes_width;      
      
    laddr = data;  
      
	for (i = 0; i < j; i ++) 
	{      
		memcpy(d.chars, laddr, bytes_width);      
		ptrace(PTRACE_POKETEXT, pid, dest, d.val);      
		
		dest  += bytes_width;      
		laddr += bytes_width;      
	}      
      
    if(remain > 0) 
	{  
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);      
        for (i = 0; i < remain; i ++) {      
            d.chars[i] = *laddr ++;      
        }      
      
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);     
    }      
      
    return 0;      
}      
  
  
/*
function: ptrace_call
param:
	pid: as all known
	addr: address where called
	params: param when called
	num_params: param num when called
	pt_regs: current register state
return:
	success return 0, failed return -1
description:
	call specified address
*/
#define max_register_param   4 
#define CPSR_T_MASK	         (1u<<5) 
int ptrace_call(pid_t pid, void* addr, std_width *params, int num_params, struct pt_regs * regs)      
{      
	//x86_64 call in arm
	//note: param transmit by register and stackavail
	//first x0-x3 
	//second stack
	
	int i;
	 
    for (i=0; i<num_params && i<max_register_param; i++) 
	{      
		regs->uregs[i] = params[i];
	} 
	
	if(num_params > max_register_param)
	{
		int stack_params_num = num_params - max_register_param;
		regs->ARM_sp -= (stack_params_num) * sizeof(std_width);      
		ptrace_writedata(pid, (void *)regs->ARM_sp, (uint8_t *)&params[max_register_param], (stack_params_num) * sizeof(std_width));	
	}
    
    //write return address 0 to make process hang up when call finish      
    regs->ARM_lr = 0; //regs->lr         
    
    regs->ARM_pc = addr;
    //arm or thumb
	if (regs->ARM_pc & 1) 
	{      
		//thumb    
		regs->ARM_pc &= (~1u); 
		regs->ARM_cpsr |= CPSR_T_MASK;      
	} else 
	{      
		//arm
		regs->ARM_cpsr &= ~CPSR_T_MASK;      
	} 
    
    if(ptrace_setregs(pid, regs) == -1 || ptrace_continue(pid) == -1) 
	{    
        return -1;      
    }
    
    //wait something ?
    int stat = 0;    
    waitpid(pid, &stat, WUNTRACED);   
	
    while (stat != 0xB7F) 
	{    
        if(ptrace_continue(pid) == -1) 
		{    
            return -1;    
        }    
        waitpid(pid, &stat, WUNTRACED);    
    }    
      
    return 0;      
}   
   
/*
function: ptrace_getregs
param:
	pid: as all known
	pt_regs: current register state		
return:
	success return 0, failed return -1
description:
	get current register state
*/
int ptrace_getregs(pid_t pid, struct pt_regs * regs)      
{
	int regset = NT_PRSTATUS;
	struct iovec ioVec;
	
	ioVec.iov_base = regs;
	ioVec.iov_len = sizeof(*regs);
	
    if(ptrace(PTRACE_GETREGSET, pid, (void*)regset, &ioVec) < 0) 
	{      
        LOGD("ptrace_getregs failed\n");      
        return -1;      
    }      
      
    return 0;    
}      

/*
function: ptrace_setregs
param:
	pid: as all known
	pt_regs: register state	which set	
return:
	success return 0, failed return -1
description:
	get current register state
*/
int ptrace_setregs(pid_t pid, struct pt_regs * regs)      
{       
	int regset = NT_PRSTATUS;
	struct iovec ioVec;
	
	ioVec.iov_base = regs;
	ioVec.iov_len = sizeof(*regs);
	
    if(ptrace(PTRACE_SETREGSET, pid, (void*)regset, &ioVec) < 0) 
	{      
        LOGD("ptrace_setregs failed\n");      
        return -1;      
    }      
      
    return 0;     
}      

/*
function: ptrace_continue
param:
	pid: as all known	
return:
	success return 0, failed return -1
description:
	continue 
*/     
int ptrace_continue(pid_t pid)      
{      
    if(ptrace(PTRACE_CONT, pid, NULL, 0) < 0) 
	{      
        LOGD("ptrace_continute failed\n");      
        return -1;      
    }      
      
    return 0;      
}      
   
/*
function: ptrace_attach
param:
	pid: as all known	
return:
	success return 0, failed return -1
description:
	attach 
*/   
int ptrace_attach(pid_t pid)      
{      
    if(ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) 
	{
        LOGD("ptrace_attach failed\n");      
        return -1;      
    } 
	LOGD("ptrace_attach succesful, pid=%d\n", pid);
	
    int stat = 0;      
	
	//ptrace(PTRACE_SYSCALL,pid);
    //waitpid(pid, &stat , WUNTRACED);      
	//
	//ptrace(PTRACE_SYSCALL,pid);
	waitpid(pid, &stat , WUNTRACED); 
	
	//while (stat != 0xb7f) {    
    //    if(ptrace_continue(pid) == -1) {    
    //        printf("error\n");    
    //        return -1;    
    //    }    
    //    waitpid(pid, &stat, WUNTRACED);    
    //}  
	
    return 0;      
}      
   
/*
function: ptrace_detach
param:
	pid: as all known	
return:
	success return 0, failed return -1
description:
	deattach 
*/
int ptrace_detach(pid_t pid)      
{      
    if(ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) 
	{      
        LOGD("ptrace_detach failed\n");      
        return -1;      
    }      
      
    return 0;      
}  
  
/*
function: ptrace_retval
param:
	regs: register state
return:
	process return value
description:
	return value of register
*/    
std_width ptrace_retval(struct pt_regs *regs)      
{              
    return regs->ARM_r0;	//regs->r0
}      

/*
function: ptrace_pc
param:
	regs: register state
return:
	process implement address
description:
	return process implement address
*/    
std_width ptrace_pc(struct pt_regs *regs)      
{      
    return regs->ARM_pc;
}      

/*
function: ptrace_call_wrapper
param:
	pid: as all known	
	func_name: function name
	addr: address where called
	params: param when called
	num_params: param num when called	
	regs: current register state	
return:
	success return 0, failed return -1
description:
	call address and get return register state
*/
int ptrace_call_wrapper(pid_t pid, const char *func_name, void * addr, std_width * params, int num_param, struct pt_regs * regs)       
{         
    if(ptrace_call(pid, addr, params, num_param, regs) == -1)
	{
		LOGD("ptrace_call_wrapper[%s]: ptrace_call failed\n",func_name);
		return -1;   
	}     
      
    if(ptrace_getregs(pid, regs) == -1)
	{
		LOGD("ptrace_call_wrapper[%s]: ptrace_getregs failed\n",func_name);		
		return -1; 
	}   
    
    //if pc is no zero, call may be failed depend on ptrace_call
    LOGD("ptrace_call_wrapper[%s]: pid=%d return value=%llX, pc=%llX\n", func_name, pid, ptrace_retval(regs), ptrace_pc(regs)); 
	
	if(ptrace_pc(regs) != 0)
		return -1;
	else
    	return 0;      
}      
 

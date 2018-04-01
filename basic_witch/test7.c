#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/kernel.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>
#include <strings.h>
#include <time.h>

#define PEBS_SAMPLE_TYPE PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR | PERF_SAMPLE_CALLCHAIN
#define WATCH_SAMPLE_TYPE PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR | PERF_SAMPLE_CALLCHAIN

#define CHECK(x) ({int err = (x); \
if (err) { \
fprintf(stderr, "%s: Failed with %d on line %d of file %s\n", strerror(errno), err, __LINE__, __FILE__); \
exit(-1); }\
err;})

#define NUM_MMAP_PAGES 8

long long perf_mmap_read( void *our_mmap, int mmap_size,
                        long long prev_head,
                        int sample_type, int read_format, long long reg_mask,
                        struct validate_values *validate,
                        int quiet, int *events_read,
                        int raw_type, long long *addr );

static bool modify_watchpoint(int fd, uintptr_t address, int type, int len);

int processId;

int fd;
int fdPEBS;

static int pgsz;
static char * mmapBuffer;
static char * mmapBufferPEBS;
static int count=0;
static int count2=0;

static inline long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}
static pid_t gettid() {
    return syscall(__NR_gettid);
}

static inline void enable_watchpoint(int fd, int fd2) {
    CHECK(ioctl(fd, PERF_EVENT_IOC_ENABLE, 0));
    CHECK(ioctl(fd2, PERF_EVENT_IOC_ENABLE, 0));
}

static inline void disable_watchpoint(int fd, int fd2) {
    CHECK(ioctl(fd, PERF_EVENT_IOC_DISABLE, 0));
    if(fd2!=NULL)
    CHECK(ioctl(fd2, PERF_EVENT_IOC_DISABLE, 0));
}

static inline void refresh_watchpoint(int fd, int fd2) {
    CHECK(ioctl(fd, PERF_EVENT_IOC_REFRESH, 1));
    CHECK(ioctl(fd2, PERF_EVENT_IOC_REFRESH, 1));
}


static inline char * mmap_wp_buffer(int fd){
    char * buf = mmap(NULL, (1+NUM_MMAP_PAGES) * pgsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
		perror("mmap");
		exit(-1);
    }
    return buf;
}

static inline void unmap_wp_buffer(void * buf){
    CHECK(munmap(buf, (1+NUM_MMAP_PAGES) * pgsz));
}

#define RAW_NONE        0
static long long prev_head;
static void watchpoint_signal_handler(int signum, siginfo_t *info, void *context){
        count++;
	disable_watchpoint(fd, NULL);
	printf("WatchPoint +++++++ \n");
	long long addr = 0;
	prev_head=perf_mmap_read(mmapBuffer, NUM_MMAP_PAGES, prev_head,
                WATCH_SAMPLE_TYPE, 0, 0,
                NULL, 0, NULL, RAW_NONE, &addr);
	printf("WatchPoint -------- \n");
//	refresh_watchpoint(fd, NULL);
	return;
}

static long long prev_headPEBS;

static void pebs_signal_handler(int signum, siginfo_t *info, void *context){
	disable_watchpoint(fd, fdPEBS);
        count2++;
	long long addr = 0;
	printf("PEBS <<<<< \n");
	prev_headPEBS=perf_mmap_read(mmapBufferPEBS, NUM_MMAP_PAGES, prev_headPEBS,
                PEBS_SAMPLE_TYPE, 0, 0,
		NULL, 0, NULL, RAW_NONE, &addr);
	//modify_watchpoint(fd, (uintptr_t) addr, HW_BREAKPOINT_W | HW_BREAKPOINT_R, HW_BREAKPOINT_LEN_1);
	printf("PEBS >>>>\n");
	enable_watchpoint(fd, fdPEBS);
        return;
}

static void InitConfig(){
        
    // Setup the signal handler
    sigset_t block_mask;
    sigfillset(&block_mask);
    // Set a signal handler for SIGUSR1
    struct sigaction sa1 = {
        .sa_sigaction = watchpoint_signal_handler,
        .sa_mask = block_mask,
        .sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER | SA_ONSTACK
    };
    
    if(sigaction(SIGRTMIN + 3,  &sa1, 0) == -1) {
        fprintf(stderr, "Failed to set WHICH_SIG handler: %s\n", strerror(errno));
        exit(-1);
    }

    /* configuring signal for PEBS */
    sigset_t block_mask_pebs;
    sigfillset(&block_mask_pebs);

   // Set a signal handler for SIGUSR1
    struct sigaction sa2 = {
        .sa_sigaction = pebs_signal_handler,
        .sa_mask = block_mask_pebs,
        .sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER | SA_ONSTACK
    };
    
    if(sigaction(SIGRTMIN + 4,  &sa2, 0) == -1) {
        fprintf(stderr, "Failed to set PEBS_SIG handler: %s\n", strerror(errno));
        exit(-1);
    }
        
    pgsz = getpagesize();//sysconf(_SC_PAGESIZE);
    
}

static inline int create_watchpoint(uintptr_t address, int type, int len) {
    // Perf event settings
    struct perf_event_attr pe = {
        .type                   = PERF_TYPE_BREAKPOINT,
        .size                   = sizeof(struct perf_event_attr),
        .bp_type                = type,
        .bp_len                 = len,
	   .bp_addr = (uintptr_t) address,
        .sample_period          = 1,
        .sample_type            = WATCH_SAMPLE_TYPE,
        .exclude_user           = 0,
        .exclude_kernel         = 0,
        .exclude_hv             = 0,
	.exclude_guest		= 0,
        .exclude_host           = 1,
        .disabled               = 0, /* enabled */
	.exclude_callchain_kernel = 0,
    };
        // fresh creation
        // Create the perf_event for this thread on all CPUs with no event group
//        int perf_fd = perf_event_open(&pe, 0, -1, -1 /*group*/, 0);
//	int perf_fd = perf_event_open(&pe, -1, 1, -1 /*group*/, 0);
	int perf_fd = perf_event_open(&pe, processId, -1, -1 /*group*/, 0);
        if (perf_fd == -1) {
            perror("perf_event_open");
		  exit (-1);
        }
	// mmap the file 
        mmapBuffer = mmap_wp_buffer(perf_fd);

        // Set the perf_event file to async mode
        CHECK(fcntl(perf_fd, F_SETFL, fcntl(perf_fd, F_GETFL, 0) | O_ASYNC));
        
        // Tell the file to send a signal when an event occurs
        CHECK(fcntl(perf_fd, F_SETSIG, SIGRTMIN + 3));
        
        // Deliver the signal to this thread
        struct f_owner_ex fown_ex;
        fown_ex.type = F_OWNER_TID;
        fown_ex.pid  = getpid();
        int ret = fcntl(perf_fd, F_SETOWN_EX, &fown_ex);
        if (ret == -1){
            perror("fcntl");
		  exit (-1);
        }        
        return perf_fd;

}

static inline void distroy_watchpoint(int fd){
    unmap_wp_buffer(mmapBuffer);
    mmapBuffer = 0;    
    CHECK(close(fd));
}


static inline bool modify_watchpoint(int fd, uintptr_t address, int type, int len) {
    // Perf event settings
#if 0
    struct perf_event_attr pe = {
        .type                   = PERF_TYPE_BREAKPOINT,
        .size                   = sizeof(struct perf_event_attr),
        .bp_type                = type,
        .bp_len                 = len,
	   .bp_addr = (uintptr_t) address,
        .sample_period          = 1,
        .sample_type            = WATCH_SAMPLE_TYPE,
//        .exclude_user           = 0,
  //      .exclude_kernel         = 1,
    //    .exclude_hv             = 0,
        .disabled               = 0, /* enabled */
    };
#endif

    struct perf_event_attr pe = {
        .type                   = PERF_TYPE_BREAKPOINT,
        .size                   = sizeof(struct perf_event_attr),
        .bp_type                = type,
        .bp_len                 = len,
           .bp_addr = (uintptr_t) address,
        .sample_period          = 1,
        .sample_type            = WATCH_SAMPLE_TYPE,
        .exclude_user           = 0,
        .exclude_kernel         = 0,
        .exclude_hv             = 0,
        .exclude_guest          = 0,
        .exclude_host           = 1,
        .disabled               = 0, /* enabled */
        .exclude_callchain_kernel = 0,
    };
    CHECK(ioctl(fd, PERF_EVENT_IOC_MODIFY_ATTRIBUTES, (unsigned long) (&pe)));
}


static inline void
rmb(void) {
    asm volatile("lfence":::"memory");
}

static inline void ConsumeAllRingBufferData(void  *mbuf) {
    struct perf_event_mmap_page *hdr = (struct perf_event_mmap_page *)mbuf;
    void *data;
    unsigned long tail;
    size_t avail_sz, m, c;
    size_t pgmsk = pgsz - 1;
    /*
     * data points to beginning of buffer payload
     */
    data = ((void *)hdr) + pgsz;
    
    /*
     * position of tail within the buffer payload
     */
    tail = hdr->data_tail & pgmsk;
    
    /*
     * size of what is available
     *
     * data_head, data_tail never wrap around
     */
    avail_sz = hdr->data_head - hdr->data_tail;
    rmb();
#if 0
    if(avail_sz == 0 )
        EMSG("\n avail_sz = %d\n", avail_sz);
    else
        EMSG("\n EEavail_sz = %d\n", avail_sz);
#endif
    // reset tail to head
    hdr->data_tail = hdr->data_head;
}
////////////////*************************************************************************************************
//PEBS
static inline int create_pebsevent() {
    // Perf event settings
    struct perf_event_attr pe = {
        .type                   = PERF_TYPE_RAW,
        .size                   = sizeof(struct perf_event_attr),
        .sample_period          = 1003,
        .sample_type            = PEBS_SAMPLE_TYPE,
        .exclude_user           = 0,
        .exclude_kernel         = 0,
        .exclude_hv             = 0,
        .disabled               = 0, /* enabled */
        .config                 = 0x1cd,
        .config1                = 0x3,
        .precise_ip             = 3,
        .exclude_guest          = 0,
        .exclude_host           = 0,
        .exclude_callchain_kernel = 0,
        .read_format            = PERF_FORMAT_GROUP | PERF_FORMAT_ID,
        .task                   = 1,
    };
        // fresh creation
        // Create the perf_event for this thread on all CPUs with no event group
 //       int perf_fd = perf_event_open(&pe, 0, -1, -1 /*group*/, 0);
//	int perf_fd = perf_event_open(&pe, -1, 1, -1 /*group*/, 0);
	int perf_fd = perf_event_open(&pe, processId, -1, -1 /*group*/, 0);
        if (perf_fd == -1) {
            perror("perf_event_open");
                  exit (-1);
        }

	// mmap the file 
        mmapBufferPEBS = mmap_wp_buffer(perf_fd);

        // Set the perf_event file to async mode
        CHECK(fcntl(perf_fd, F_SETFL, fcntl(perf_fd, F_GETFL, 0) | O_ASYNC));

        // Tell the file to send a signal when an event occurs
        CHECK(fcntl(perf_fd, F_SETSIG, SIGRTMIN + 4));

        // Deliver the signal to this thread
        struct f_owner_ex fown_ex;
        fown_ex.type = F_OWNER_TID;
        fown_ex.pid  = getpid();
        int ret = fcntl(perf_fd, F_SETOWN_EX, &fown_ex);
        if (ret == -1){
            perror("fcntl");
                  exit (-1);
        }
	printf("pebs event created\n");
        return perf_fd;

}

static inline void distroy_pebsevent(int fd){
    unmap_wp_buffer(mmapBufferPEBS);
    mmapBufferPEBS = 0;
    CHECK(close(fd));
}





//**************************************************************************************************************
/* Test example starts */
#define MATRIX_SIZE 512
static double a[MATRIX_SIZE][MATRIX_SIZE];
static double b[MATRIX_SIZE][MATRIX_SIZE];
static double c[MATRIX_SIZE][MATRIX_SIZE];

static void naive_matrix_multiply(int quiet) {

  double s;
  int i,j,k;

  for(i=0;i<MATRIX_SIZE;i++) {
    for(j=0;j<MATRIX_SIZE;j++) {
      a[i][j]=(double)i*(double)j;
      b[i][j]=(double)i/(double)(j+5);
    }
  }
  for(j=0;j<MATRIX_SIZE;j++) {
     for(i=0;i<MATRIX_SIZE;i++) {
        s=0;
        for(k=0;k<MATRIX_SIZE;k++) {
           s+=a[i][k]*b[k][j];
        }
        c[i][j] = s;
     }
  }
  s=0.0;
  for(i=0;i<MATRIX_SIZE;i++) {
    for(j=0;j<MATRIX_SIZE;j++) {
      s+=c[i][j];
    }
  }

  if (!quiet) printf("Matrix multiply sum: s=%lf\n",s);

  return;
}

/*Test example ends*/







//***********************************************************

#define N 10
//(1000000)
char dummy[N+1];
int main(int argc, char *argv[]){
        /* Checks the correctness of changing between read and write accesses */
	if( argc == 2 ) {
	      printf("The argument supplied is %s\n", argv[1]);
   	}
	else
		return 0;

	processId = atoi(argv[1]);
	

        InitConfig();

        count = 0;

	fdPEBS = create_pebsevent();
        fd = create_watchpoint((uintptr_t) &dummy[0], HW_BREAKPOINT_W | HW_BREAKPOINT_R, HW_BREAKPOINT_LEN_1);
	while(true);
	distroy_pebsevent(fdPEBS);
        distroy_watchpoint(fd);

	
	printf("total pebs count %d\n",count2);	

        return 0;
}





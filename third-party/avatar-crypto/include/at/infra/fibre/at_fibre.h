#ifndef HEADER_at_src_util_fibre_at_fibre_h
#define HEADER_at_src_util_fibre_at_fibre_h

#include <ucontext.h>

#include "../at_util.h"

#define AT_FIBRE_ALIGN 128UL

/* definition of the function to be called when starting a new fibre */
typedef void (*at_fibre_fn_t)( void * );

struct at_fibre {
  ucontext_t    ctx;
  void *        stack;
  size_t        stack_sz;
  at_fibre_fn_t fn;
  void *        arg;
  int           done;

  /* schedule parameters */
  long              sched_time;
  struct at_fibre * next;
  int               sentinel;
};
typedef struct at_fibre at_fibre_t;


struct at_fibre_pipe {
  ulong cap;  /* capacity */
  ulong head; /* head index */
  ulong tail; /* tail index */

  at_fibre_t * writer; /* fibre that's currently waiting for a write, if any */
  at_fibre_t * reader; /* fibre that's currently waiting for a read, if any */

  ulong * entries;
};
typedef struct at_fibre_pipe at_fibre_pipe_t;


/* TODO make thread local */
extern at_fibre_t * at_fibre_current;


AT_PROTOTYPES_BEGIN


/* footprint and alignment required for at_fibre_init */
ulong at_fibre_init_footprint( void );
ulong at_fibre_init_align( void );


/* initialize main fibre

   should be called before making any other fibre calls

   creates a new fibre from the current thread, and returns it
   caller should keep the fibre for later freeing

   probably shouldn't run this twice on the same thread

   mem is the memory allocated for this object. Use at_fibre_init{_align,_footprint} to
     obtain the appropriate size and alignment requirements */

at_fibre_t *
at_fibre_init( void * );


/* footprint and alignment required for at_fibre_start */
ulong at_fibre_start_footprint( ulong stack_size );
ulong at_fibre_start_align( void );


/* Start a fibre

   This uses get/setcontext to create a new fibre

   at_fibre_init must be called once before calling this

   The current fibre will continue running, and the other will be
   inactive, and ready to switch to

   This fibre may be started on this or another thread

   mem is the memory used for the fibre. Use at_fibre_start{_align,_footprint}
     to determine the size and alignment required for the memory

   stack_sz is the size of the stack required

   fn is the function entry point to call in the new fibre
   arg is the value to pass to function fn */
at_fibre_t *
at_fibre_start( void * mem, ulong stack_sz, at_fibre_fn_t fn, void * arg );


/* Free a fibre

   This frees up the resources of a fibre

   Only call on a fibre that is not currently running */
void
at_fibre_free( at_fibre_t * fibre );


/* switch execution to a fibre

   Switches execution to "swap_to"
   The global variable `at_fibre_current` is updated with the state
   of the currently running fibre before switching */
void
at_fibre_swap( at_fibre_t * swap_to );


/* at_fibre_abort is called when a fatal error occurs */
#ifndef at_fibre_abort
#  define at_fibre_abort(...) abort( __VA_ARGS__ )
#endif


/* set a clock for scheduler */
void
at_fibre_set_clock( long (*clock)(void) );


/* yield current fibre
   allows other fibres to execute */
void
at_fibre_yield( void );


/* stops running currently executing fibre for a period of time */
void
at_fibre_wait( long wait_ns );


/* stops running currently executing fibre until a particular
   time */
void
at_fibre_wait_until( long resume_time_ns );


/* wakes another fibre */
void
at_fibre_wake( at_fibre_t * fibre );


/* add a fibre to the schedule */
void
at_fibre_schedule( at_fibre_t * fibre );


/* run the current schedule

   returns
     the time of the next ready fibre
     -1 if there are no fibres in the schedule */
long
at_fibre_schedule_run( void );


/* fibre data structures */

/* pipe

   send data from one fibre to another
   wakes receiving fibre on write */

/* pipe footprint and alignment */

ulong
at_fibre_pipe_align( void );

ulong
at_fibre_pipe_footprint( ulong entries );


/* create a new pipe */

at_fibre_pipe_t *
at_fibre_pipe_new( void * mem, ulong entries );


/* write a value into the pipe

   can block if there isn't any free space
   timeout allows the blocking to terminate after a period of time

   pipe        the pipe to write to
   value       the value to write
   timeout     the amount of time to wait for the write to complete

   returns     0 successful
               1 there was no space for the write operation */

int
at_fibre_pipe_write( at_fibre_pipe_t * pipe, ulong value, long timeout );


/* read a value from the pipe

   read can block if there isn't any data in the pipe

   timeout allows the read to terminate without a result after
     a period of time

   pipe        the pipe to write to
   value       a pointer to the ulong to receive the value
   timeout     number of nanoseconds to wait for a value

   returns     0 successfully read a value from the pipe
               1 timed out without receiving data */
int
at_fibre_pipe_read( at_fibre_pipe_t * pipe, ulong *value, long timeout );


AT_PROTOTYPES_END


#endif /* HEADER_at_src_util_fibre_at_fibre_h */
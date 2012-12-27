#include <mach/vm_map.h>
#include <stdio.h>


/**
 * vmmap(1) clone for OS X and iOS
 * -------------------------------
 *
 * This is a simple example of using the mach_vm_region_info APIs in order to 
 * obtain a process' (technically, a task's) virtual memory address space, in a
 * manner akin to /proc/[pid]/maps on Linux.
 *
 * The process is simple - get the task port, then call mach_vm_region_info until
 * you've exhausted the address space (in iOS this happens around 0x40000000, 
 * where the commpage is). On iOS 6, for some peculiar reason the task port is
 * invalidated after each call, so the quick workaround here solves the problem
 * by regetting the port. The actual mach error code to check for is in the header
 * files, though the code simply tries regetting.
 *
 * N.B - For this code to work, you MUST provide the entitlements to allow 
 * task-for-pid to work, else you'll fail with error 5. The entitlements are in 
 * the output in Chapter 3, but for those of you who haven't bought the book, it would be:
 *
--- Cut here 
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
 
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>com.apple.springboard.debugapplications</key>
        <true/>
        <key>get-task-allow</key>
        <true/>
        <key>proc_info-allow</key>
        <true/>
        <key>task_for_pid-allow</key>
        <true/>
        <key>run-unsigned-code</key>
        <true/>
</dict>
</plist>

--- Ok, enough :-)
 *
 *  so - copy the above XML to a file, say, "ent.xml", and be sure to run "ldid -Sent.xml vmmap"
 *  before trying to run this. You can download the binary (already thus signed) if you're lazy
 *  (and trust me, because you *will* need root on your i-Device for this)
 *
 *  As the book clearly states, once you have the task port, the world is your oyster. You can
 *  control the entire virtual memory space, reading and writing it as you please. Stay tuned
 *  for the corrupt tool (which will be provided soon in binary form)
 *
 */

int g_pid = 0; // required in iOS 6 (read below)
char *
behavior_to_text (vm_behavior_t	b)
{

  switch (b)
	{
		case VM_BEHAVIOR_DEFAULT: return("default");
		case VM_BEHAVIOR_RANDOM:  return("random");
		case VM_BEHAVIOR_SEQUENTIAL: return("fwd-seq");
		case VM_BEHAVIOR_RSEQNTL: return("rev-seq");
		case VM_BEHAVIOR_WILLNEED: return("will-need");
		case VM_BEHAVIOR_DONTNEED: return("will-need");
		case VM_BEHAVIOR_FREE: return("free-nowb");
		case VM_BEHAVIOR_ZERO_WIRED_PAGES: return("zero-wire");
		case VM_BEHAVIOR_REUSABLE: return("reusable");
		case VM_BEHAVIOR_REUSE: return("reuse");
		case VM_BEHAVIOR_CAN_REUSE: return("canreuse");
		default: return ("?");
	}


}
char *
protection_bits_to_rwx (vm_prot_t p)
{

  static char returned[4];

  returned[0] = (VM_PROT_READ    ? 'r' : '-');
  returned[1] = (VM_PROT_WRITE   ? 'w' : '-');
  returned[2] = (VM_PROT_EXECUTE ? 'x' : '-');
  returned[3] = '\0';

  return (returned);

}

const char *
unparse_inheritance (vm_inherit_t i)
{
  switch (i)
    {
    case VM_INHERIT_SHARE:
      return "share";
    case VM_INHERIT_COPY:
      return "copy";
    case VM_INHERIT_NONE:
      return "none";
    default:
      return "???";
    }
}

macosx_debug_regions (task_t task, mach_vm_address_t address, int max)
{
  kern_return_t kret;
  vm_region_basic_info_data_t info, prev_info;
  mach_vm_address_t prev_address;
  mach_vm_size_t size, prev_size;

  mach_port_t object_name;
  mach_msg_type_number_t count;

  int nsubregions = 0;
  int num_printed = 0;

  count = VM_REGION_BASIC_INFO_COUNT_64;
  kret = mach_vm_region (task, &address, &size, VM_REGION_BASIC_INFO,
			 (vm_region_info_t) &info, &count, &object_name);
  if (kret != KERN_SUCCESS)
    {
      printf ("Error %d - %s", kret, mach_error_string(kret));
      return;
    }
  memcpy (&prev_info, &info, sizeof (vm_region_basic_info_data_t));
  prev_address = address;
  prev_size = size;
  nsubregions = 1;

  for (;;)
    {
      int print = 0;
      int done = 0;

      address = prev_address + prev_size;

      /* Check to see if address space has wrapped around. */
      if (address == 0)
	{ 
        print = done = 1;
	}

      if (!done)
        {
          // Even on iOS, we use VM_REGION_BASIC_INFO_COUNT_64. This works.

          count = VM_REGION_BASIC_INFO_COUNT_64;


          kret =
            mach_vm_region (task, &address, &size, VM_REGION_BASIC_INFO,
                 	      (vm_region_info_t) &info, &count, &object_name);

          if (kret != KERN_SUCCESS)
            {
		/* iOS 6 workaround - attempt to reget the task port to avoiD */
		/* "(ipc/send) invalid destination port" (1000003 or something) */
		task_for_pid(mach_task_self(),g_pid, &task);
		
		kret =
            mach_vm_region (task, &address, &size, VM_REGION_BASIC_INFO,
                              (vm_region_info_t) &info, &count, &object_name);


		}
	   if (kret != KERN_SUCCESS)
	{
		
		fprintf (stderr,"mach_vm_region failed for address %p - %s\n", address, mach_error_string(kret));
              size = 0;
	if (address >= 0x4000000) return;
              print = done = 1;
            }
        }

      if (address != prev_address + prev_size)
        print = 1;

      if ((info.protection != prev_info.protection)
          || (info.max_protection != prev_info.max_protection)
          || (info.inheritance != prev_info.inheritance)
          || (info.shared != prev_info.reserved)
          || (info.reserved != prev_info.reserved))
        print = 1;

      if (print)
        {
	  int	print_size;
	  char *print_size_unit;
          if (num_printed == 0)
            printf ("Region ");
          else
            printf ("   ... ");

	  /* Quick hack to show size of segment, which GDB does not */
	  print_size = prev_size;
	  if (print_size > 1024) { print_size /= 1024; print_size_unit = "K"; }
	  if (print_size > 1024) { print_size /= 1024; print_size_unit = "M"; }
	  if (print_size > 1024) { print_size /= 1024; print_size_unit = "G"; }
	  /* End Quick hack */
          printf (" %p-%p [%d%s](%s/%s; %s, %s, %s) %s",
                           (prev_address),
                           (prev_address + prev_size),
			   print_size,
			   print_size_unit,
                           protection_bits_to_rwx (prev_info.protection),
                           protection_bits_to_rwx (prev_info.max_protection),
                           unparse_inheritance (prev_info.inheritance),
                           prev_info.shared ? "shared" : "private",
                           prev_info.reserved ? "reserved" : "not-reserved",
			   behavior_to_text (prev_info.behavior));

          if (nsubregions > 1)
            printf (" (%d sub-regions)", nsubregions);

          printf ("\n");

          prev_address = address;
          prev_size = size;
          memcpy (&prev_info, &info, sizeof (vm_region_basic_info_data_t));
          nsubregions = 1;

          num_printed++;
        }
      else
        {
          prev_size += size;
          nsubregions++;
        }

      if ((max > 0) && (num_printed >= max))
	{
	 printf ("Max %d num_printed %d\n", max, num_printed);
        done = 1;
	}

      if (done)
        break;
    }
}

void 
main(int argc, char **argv)
{

	struct vm_region_basic_info vmr;
	kern_return_t	rc;
	mach_port_t	task;

	mach_vm_size_t	size = 8;
	vm_region_info_t	info = (vm_region_info_t) malloc(10000);
	mach_msg_type_number_t	info_count;
	mach_port_t		object_name;
	mach_vm_address_t	addr =1;
 	int pid;

        if (!argv[1]) { printf ("Usage: %s <PID>\n"); exit (1);}
	pid = atoi(argv[1]);
	g_pid = pid; // req for iOS 6
	rc = task_for_pid(mach_task_self(),pid, &task);

	if (rc) { fprintf (stderr, "task_for_pid() failed with error %d - %s\n", rc, mach_error_string(rc)); exit(1); }
	printf ("RC %d - Task: %d\n",rc, task);


	macosx_debug_regions (task, addr, 1000);

	printf("Done\n");
	



}

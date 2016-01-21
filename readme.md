
Thanks Pedram Amini Created PyDbg ,but I search how to using these interface in Internet .So I get these function's informations in PyDbg.py and conver to markdown ,hope this can help anything they want learning PyDbg .

TIPS :These interfaces is a class(PyDbg) in PyDbg.py .This is a simply example :

    import pydbg

    debugger=pydbg.pydbg()
    debugger.load('C:\\Windows\\System32\\cmd.exe')

TIPS :Maybe you will get this problem -- system can't find module pydasm .You should delete pydasm.pyd in directory PyDbg and install Pydasm if you haven't install it 

Thank you for reading my noob english :).

**@author:       Pedram Amini**
**@license:      GNU General Public License 2.0 or later**
**@contact:      pedram.amini@gmail.com**
**@organization: www.openrce.org**
**This class implements standard low leven functionality including:**
**- The load() / attach() routines.**
**- The main debug event loop.**
**- Convenience wrappers for commonly used Windows API.**
**- Single step toggling routine.**
**- Win32 error handler wrapped around PDX.**
**- Base exception / event handler routines which are meant to be overridden.**
**Higher level functionality is also implemented including:**
**- Register manipulation.**
**- Soft (INT 3) breakpoints.**
**- Memory breakpoints (page permissions).**
**- Hardware breakpoints.**
**- Exception / event handling call backs.**
**- Pydasm (libdasm) disassembly wrapper.**
**- Process memory snapshotting and restoring.**
**- Endian manipulation routines.**
**- Debugger hiding.**
**- Function resolution.**
**- "Intelligent" memory derefencing.**
**- Stack/SEH unwinding.**
**- Etc...**

---
###def __init__ (self, ff=True, cs=False):
**Set the default attributes. See the source if you want to modify the default creation values.**
`ff: Boolean`:
&nbsp;&nbsp;&nbsp;&nbsp;ff: (Optional, Def=True) Flag controlling whether or not pydbg attaches to forked processes
`cs: Boolean`:
&nbsp;&nbsp;&nbsp;&nbsp;cs: (Optional, Def=False) Flag controlling whether or not pydbg is in client/server (socket) mode

---
###def addr_to_dll (self, address):
**Return the system DLL that contains the address specified.**
`address: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address: Address to search system DLL ranges for
`return: system_dll`
&nbsp;&nbsp;&nbsp;&nbsp;System DLL that contains the address specified or None if not found.
---
###def addr_to_module (self, address):
**Return the MODULEENTRY32 structure for the module that contains the address specified.**
`address: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address: Address to search loaded module ranges for
`return: MODULEENTRY32`
&nbsp;&nbsp;&nbsp;&nbsp;MODULEENTRY32 strucutre that contains the address specified or None if not found.
---
###def attach (self, pid):
**Attach to the specified process by PID. Saves a process handle in self.h_process and prevents debuggee from**
**exiting on debugger quit.**
`pid: Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;pid: Process ID to attach to
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def bp_del (self, address):
**Removes the breakpoint from target address.**
`address: DWORD or List`:
&nbsp;&nbsp;&nbsp;&nbsp;address: Address or list of addresses to remove breakpoint from
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def bp_del_all (self):
**Removes all breakpoints from the debuggee.**
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def bp_del_hw (self, address=None, slot=None):
**Removes the hardware breakpoint from the specified address or slot. Either an address or a slot must be**
**specified, but not both.**
`address:   DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address:   (Optional) Address to remove hardware breakpoint from.
`slot:      Integer (0 through 3)`:
&nbsp;&nbsp;&nbsp;&nbsp;slot:      (Optional)
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def bp_del_hw_all (self):
**Removes all hardware breakpoints from the debuggee.**
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def bp_del_mem (self, address):
**Removes the memory breakpoint from target address.**
`address: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address: Address or list of addresses to remove memory breakpoint from
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def bp_del_mem_all (self):
**Removes all memory breakpoints from the debuggee.**
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def bp_is_ours (self, address_to_check):
**Determine if a breakpoint address belongs to us.**
`address_to_check: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address_to_check: Address to check if we have set a breakpoint at
`return: Bool`
&nbsp;&nbsp;&nbsp;&nbsp;True if breakpoint in question is ours, False otherwise
---
###def bp_is_ours_mem (self, address_to_check):
**Determines if the specified address falls within the range of one of our memory breakpoints. When handling**
**potential memory breakpoint exceptions it is mandatory to check the offending address with this routine as**
**memory breakpoints are implemented by changing page permissions and the referenced address may very well exist**
**within the same page as a memory breakpoint but not within the actual range of the buffer we wish to break on.**
`address_to_check: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address_to_check: Address to check if we have set a breakpoint on
`return: Mixed`
&nbsp;&nbsp;&nbsp;&nbsp;The starting address of the buffer our breakpoint triggered on or False if address falls outside range.
---
###def bp_set (self, address, description="", restore=True, handler=None):
**Sets a breakpoint at the designated address. Register an EXCEPTION_BREAKPOINT callback handler to catch**
**breakpoint events. If a list of addresses is submitted to this routine then the entire list of new breakpoints**
**get the same description and restore. The optional "handler" parameter can be used to identify a function to**
**specifically handle the specified bp, as opposed to the generic bp callback handler. The prototype of the**
**callback routines is::**
**func (pydbg)**
**return DBG_CONTINUE     # or other continue status**
`address:     DWORD or List`:
&nbsp;&nbsp;&nbsp;&nbsp;address:     Address or list of addresses to set breakpoint at
`description: String`:
&nbsp;&nbsp;&nbsp;&nbsp;description: (Optional) Description to associate with this breakpoint
`restore:     Bool`:
&nbsp;&nbsp;&nbsp;&nbsp;restore:     (Optional, def=True) Flag controlling whether or not to restore the breakpoint
`handler:     Function Pointer`:
&nbsp;&nbsp;&nbsp;&nbsp;handler:     (Optional, def=None) Optional handler to call for this bp instead of the default handler
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def bp_set_hw (self, address, length, condition, description="", restore=True, handler=None):
**Sets a hardware breakpoint at the designated address. Register an EXCEPTION_SINGLE_STEP callback handler to**
**catch hardware breakpoint events. Setting hardware breakpoints requires the internal h_thread handle be set.**
**This means that you can not set one outside the context of an debug event handler. If you want to set a hardware**
**breakpoint as soon as you attach to or load a process, do so in the first chance breakpoint handler.**
**For more information regarding the Intel x86 debug registers and hardware breakpoints see::**
**http://pdos.csail.mit.edu/6.828/2005/readings/ia32/IA32-3.pdf**
**Section 15.2**
**Alternatively, you can register a custom handler to handle hits on the specific hw breakpoint slot.**
***Warning: Setting hardware breakpoints during the first system breakpoint will be removed upon process**
**continue.  A better approach is to set a software breakpoint that when hit will set your hardware breakpoints.**
**@note: Hardware breakpoints are handled globally throughout the entire process and not a single specific thread.**
`address:     DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address:     Address to set hardware breakpoint at
`length:      Integer (1, 2 or 4)`:
&nbsp;&nbsp;&nbsp;&nbsp;length:      Size of hardware breakpoint in bytes (byte, word or dword)
`condition:   Integer (HW_ACCESS, HW_WRITE, HW_EXECUTE)`:
&nbsp;&nbsp;&nbsp;&nbsp;condition:   Condition to set the hardware breakpoint to activate on
`description: String`:
&nbsp;&nbsp;&nbsp;&nbsp;description: (Optional) Description of breakpoint
`restore:     Boolean`:
&nbsp;&nbsp;&nbsp;&nbsp;restore:     (Optional, def=True) Flag controlling whether or not to restore the breakpoint
`handler:     Function Pointer`:
&nbsp;&nbsp;&nbsp;&nbsp;handler:     (Optional, def=None) Optional handler to call for this bp instead of the default handler
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def bp_set_mem (self, address, size, description="", handler=None):
**Sets a memory breakpoint at the target address. This is implemented by changing the permissions of the page**
**containing the address to PAGE_GUARD. To catch memory breakpoints you have to register the EXCEPTION_GUARD_PAGE**
**callback. Within the callback handler check the internal pydbg variable self.memory_breakpoint_hit to**
**determine if the violation was a result of a direct memory breakpoint hit or some unrelated event.**
**Alternatively, you can register a custom handler to handle the memory breakpoint. Memory breakpoints are**
**automatically restored via the internal single step handler. To remove a memory breakpoint, you must explicitly**
**call bp_del_mem().**
`address:     DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address:     Starting address of the buffer to break on
`size:        Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;size:        Size of the buffer to break on
`description: String`:
&nbsp;&nbsp;&nbsp;&nbsp;description: (Optional) Description to associate with this breakpoint
`handler:     Function Pointer`:
&nbsp;&nbsp;&nbsp;&nbsp;handler:     (Optional, def=None) Optional handler to call for this bp instead of the default handler
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def close_handle (self, handle):
**Convenience wraper around kernel32.CloseHandle()**
`handle: Handle`:
&nbsp;&nbsp;&nbsp;&nbsp;handle: Handle to close
`return: Bool`
&nbsp;&nbsp;&nbsp;&nbsp;Return value from CloseHandle().
---
###def dbg_print_all_debug_registers (self):
***** DEBUG ROUTINE *****
**This is a debugging routine that was used when debugging hardware breakpoints. It was too useful to be removed**
**from the release code.**
---
###def dbg_print_all_guarded_pages (self):
***** DEBUG ROUTINE *****
**This is a debugging routine that was used when debugging memory breakpoints. It was too useful to be removed**
**from the release code.**
---
###def debug_active_process (self, pid):
**Convenience wrapper around GetLastError() and FormatMessage(). Returns the error code and formatted message**
**associated with the last error. You probably do not want to call this directly, rather look at attach().**
`pid: Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;pid: Process ID to attach to
**Raise Exception:pdx: An exception is raised on failure.**
---
###def debug_event_iteration (self):
**Check for and process a debug event.**
---
###def debug_event_loop (self):
**Enter the infinite debug event handling loop. This is the main loop of the debugger and is responsible for**
**catching debug events and exceptions and dispatching them appropriately. This routine will check for and call**
**the USER_CALLBACK_DEBUG_EVENT callback on each loop iteration. run() is an alias for this routine.**
**Raise Exception:pdx: An exception is raised on any exceptional conditions, such as debugger being interrupted or**
**debuggee quiting.**
---
###def debug_set_process_kill_on_exit (self, kill_on_exit):
**Convenience wrapper around DebugSetProcessKillOnExit().**
`kill_on_exit: Bool`:
&nbsp;&nbsp;&nbsp;&nbsp;kill_on_exit: True to kill the process on debugger exit, False to let debuggee continue running.
**Raise Exception:pdx: An exception is raised on failure.**
---
###def detach (self):
**Detach from debuggee.**
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def disasm (self, address):
**Pydasm disassemble utility function wrapper. Stores the pydasm decoded instruction in self.instruction.**
`address: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address: Address to disassemble at
`return: String`
&nbsp;&nbsp;&nbsp;&nbsp;Disassembled string.
---
###def disasm_around (self, address, num_inst=5):
**Given a specified address this routine will return the list of 5 instructions before and after the instruction**
**at address (including the instruction at address, so 11 instructions in total). This is accomplished by grabbing**
**a larger chunk of data around the address than what is predicted as necessary and then disassembling forward.**
**If during the forward disassembly the requested address lines up with the start of an instruction, then the**
**assumption is made that the forward disassembly self corrected itself and the instruction set is returned. If**
**we are unable to align with the original address, then we modify our data slice and try again until we do.**
`address:  DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address:  Address to disassemble around
`num_inst: Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;num_inst: (Optional, Def=5) Number of instructions to disassemble up/down from address
`return: List`
&nbsp;&nbsp;&nbsp;&nbsp;List of tuples (address, disassembly) of instructions around the specified address.
---
###def dump_context (self, context=None, stack_depth=5, print_dots=True):
**Return an informational block of text describing the CPU context of the current thread. Information includes:**
**- Disassembly at current EIP**
**- Register values in hex, decimal and "smart" dereferenced**
**- ESP, ESP+4, ESP+8 ... values in hex, decimal and "smart" dereferenced**
`context:     Context`:
&nbsp;&nbsp;&nbsp;&nbsp;context:     (Optional) Current thread context to examine
`stack_depth: Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;stack_depth: (Optional, def:5) Number of dwords to dereference off of the stack (not including ESP)
`print_dots:  Bool`:
&nbsp;&nbsp;&nbsp;&nbsp;print_dots:  (Optional, def:True) Controls suppression of dot in place of non-printable
`return: String`
&nbsp;&nbsp;&nbsp;&nbsp;Information about current thread context.
---
###def dump_context_list (self, context=None, stack_depth=5, print_dots=True, hex_dump=False):
**Return an informational list of items describing the CPU context of the current thread. Information includes:**
**- Disassembly at current EIP**
**- Register values in hex, decimal and "smart" dereferenced**
**- ESP, ESP+4, ESP+8 ... values in hex, decimal and "smart" dereferenced**
`context:     Context`:
&nbsp;&nbsp;&nbsp;&nbsp;context:     (Optional) Current thread context to examine
`stack_depth: Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;stack_depth: (Optional, def:5) Number of dwords to dereference off of the stack (not including ESP)
`print_dots:  Bool`:
&nbsp;&nbsp;&nbsp;&nbsp;print_dots:  (Optional, def:True) Controls suppression of dot in place of non-printable
`hex_dump:   Bool`:
&nbsp;&nbsp;&nbsp;&nbsp;hex_dump:   (Optional, def=False) Return a hex dump in the absense of string detection
`return: Dictionary`
&nbsp;&nbsp;&nbsp;&nbsp;Dictionary of information about current thread context.
---
###def enumerate_modules (self):
**Using the CreateToolhelp32Snapshot() API enumerate and return the list of module name / base address tuples that**
**belong to the debuggee**
`return: List`
&nbsp;&nbsp;&nbsp;&nbsp;List of module name / base address tuples.
---
###def enumerate_processes (self):
**Using the CreateToolhelp32Snapshot() API enumerate all system processes returning a list of pid / process name**
**tuples.**
`return: List`
&nbsp;&nbsp;&nbsp;&nbsp;List of pid / process name tuples.
**Example::**
**for (pid, name) in pydbg.enumerate_processes():**
**if name == "test.exe":**
**break**
**pydbg.attach(pid)**
---
###def enumerate_threads (self):
**Using the CreateToolhelp32Snapshot() API enumerate all system threads returning a list of thread IDs that**
**belong to the debuggee.**
`return: List`
&nbsp;&nbsp;&nbsp;&nbsp;List of thread IDs belonging to the debuggee.
**Example::**
**for thread_id in self.enumerate_threads():**
**context = self.get_thread_context(None, thread_id)**
---
###def event_handler_create_process (self):
**This is the default CREATE_PROCESS_DEBUG_EVENT handler.**
`return: DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;Debug event continue status.
---
###def event_handler_create_thread (self):
**This is the default CREATE_THREAD_DEBUG_EVENT handler.**
`return: DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;Debug event continue status.
---
###def event_handler_exit_process (self):
**This is the default EXIT_PROCESS_DEBUG_EVENT handler.**
**Raise Exception:pdx: An exception is raised to denote process exit.**
---
###def event_handler_exit_thread (self):
**This is the default EXIT_THREAD_DEBUG_EVENT handler.**
`return: DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;Debug event continue status.
---
###def event_handler_load_dll (self):
**This is the default LOAD_DLL_DEBUG_EVENT handler. You can access the last loaded dll in your callback handler**
**with the following example code::**
**last_dll = pydbg.get_system_dll(-1)**
**print "loading:%s from %s into:%08x size:%d" % (last_dll.name, last_dll.path, last_dll.base, last_dll.size)**
**The get_system_dll() routine is preferred over directly accessing the internal data structure for proper and**
**transparent client/server support.**
`return: DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;Debug event continue status.
---
###def event_handler_unload_dll (self):
**This is the default UNLOAD_DLL_DEBUG_EVENT handler.**
`return: DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;Debug event continue status.
---
###def exception_handler_access_violation (self):
**This is the default EXCEPTION_ACCESS_VIOLATION handler. Responsible for handling the access violation and**
**passing control to the registered user callback handler.**
**@attention: If you catch an access violaton and wish to terminate the process, you *must* still return**
**DBG_CONTINUE to avoid a deadlock.**
`return: DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;Debug event continue status.
---
###def exception_handler_breakpoint (self):
**This is the default EXCEPTION_BREAKPOINT handler, responsible for transparently restoring soft breakpoints**
**and passing control to the registered user callback handler.**
`return: DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;Debug event continue status.
---
###def exception_handler_guard_page (self):
**This is the default EXCEPTION_GUARD_PAGE handler, responsible for transparently restoring memory breakpoints**
**passing control to the registered user callback handler.**
`return: DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;Debug event continue status.
---
###def exception_handler_single_step (self):
**This is the default EXCEPTION_SINGLE_STEP handler, responsible for transparently restoring breakpoints and**
**passing control to the registered user callback handler.**
`return: DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;Debug event continue status.
---
###def func_resolve (self, dll, function):
**Utility function that resolves the address of a given module / function name pair under the context of the**
**debugger.**
`dll:      String`:
&nbsp;&nbsp;&nbsp;&nbsp;dll:      Name of the DLL (case-insensitive)
`function: String`:
&nbsp;&nbsp;&nbsp;&nbsp;function: Name of the function to resolve (case-sensitive)
`return: DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;Address
---
###def func_resolve_debuggee (self, dll_name, func_name):
**Utility function that resolves the address of a given module / function name pair under the context of the**
**debuggee. Note: Be weary of calling this function from within a LOAD_DLL handler as the module is not yet**
**fully loaded and therefore the snapshot will not include it.**
**@author: Otto Ebeling**
**@todo:   Add support for followed imports.**
`dll_name:  String`:
&nbsp;&nbsp;&nbsp;&nbsp;dll_name:  Name of the DLL (case-insensitive, ex:ws2_32.dll)
`func_name: String`:
&nbsp;&nbsp;&nbsp;&nbsp;func_name: Name of the function to resolve (case-sensitive)
`return: DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;Address of the symbol in the target process address space if it can be resolved, None otherwise
---
###def get_ascii_string (self, data):
**Retrieve the ASCII string, if any, from data. Ensure that the string is valid by checking against the minimum**
**length requirement defined in self.STRING_EXPLORATION_MIN_LENGTH.**
`data: Raw`:
&nbsp;&nbsp;&nbsp;&nbsp;data: Data to explore for printable ascii string
`return: String`
&nbsp;&nbsp;&nbsp;&nbsp;False on failure, ascii string on discovered string.
---
###def get_arg (self, index, context=None):
**Given a thread context, this convenience routine will retrieve the function argument at the specified index.**
**The return address of the function can be retrieved by specifying an index of 0. This routine should be called**
**from breakpoint handlers at the top of a function.**
`index:   Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;index:   Data to explore for printable ascii string
`context: Context`:
&nbsp;&nbsp;&nbsp;&nbsp;context: (Optional) Current thread context to examine
`return: DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;Value of specified argument.
---
###def get_attr (self, attribute):
**Return the value for the specified class attribute. This routine should be used over directly accessing class**
**member variables for transparent support across local vs. client/server debugger clients.**
`attribute: String`:
&nbsp;&nbsp;&nbsp;&nbsp;attribute: Name of attribute to return.
`return: Mixed`
&nbsp;&nbsp;&nbsp;&nbsp;Requested attribute or None if not found.
---
###def get_debug_privileges (self):
**Obtain necessary privileges for debugging.**
**Raise Exception:pdx: An exception is raised on failure.**
---
###def get_instruction (self, address):
**Pydasm disassemble utility function wrapper. Returns the pydasm decoded instruction in self.instruction.**
`address: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address: Address to disassemble at
`return: pydasm instruction`
&nbsp;&nbsp;&nbsp;&nbsp;pydasm instruction
---
###def get_printable_string (self, data, print_dots=True):
**description**
`data:       Raw`:
&nbsp;&nbsp;&nbsp;&nbsp;data:       Data to explore for printable ascii string
`print_dots: Bool`:
&nbsp;&nbsp;&nbsp;&nbsp;print_dots: (Optional, def:True) Controls suppression of dot in place of non-printable
`return: String`
&nbsp;&nbsp;&nbsp;&nbsp;False on failure, discovered printable chars in string otherwise.
---
###def get_register (self, register):
**Get the value of a register in the debuggee within the context of the self.h_thread.**
`register: Register`:
&nbsp;&nbsp;&nbsp;&nbsp;register: One of EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, EIP
**Raise Exception:pdx: An exception is raised on failure.**
`return:    DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;   Value of specified register.
---
###def get_system_dll (self, idx):
**Return the system DLL at the specified index. If the debugger is in client / server mode, remove the PE**
**structure (we do not want to send that mammoth over the wire).**
`idx: Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;idx: Index into self.system_dlls[] to retrieve DLL from.
`return: Mixed`
&nbsp;&nbsp;&nbsp;&nbsp;Requested attribute or None if not found.
---
###def get_thread_context (self, thread_handle=None, thread_id=0):
**Convenience wrapper around GetThreadContext(). Can obtain a thread context via a handle or thread id.**
`thread_handle: HANDLE`:
&nbsp;&nbsp;&nbsp;&nbsp;thread_handle: (Optional) Handle of thread to get context of
`thread_id:     Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;thread_id:     (Optional) ID of thread to get context of
**Raise Exception:pdx: An exception is raised on failure.**
`return:    CONTEXT`
&nbsp;&nbsp;&nbsp;&nbsp;   Thread CONTEXT on success.
---
###def get_unicode_string (self, data):
**description**
`data: Raw`:
&nbsp;&nbsp;&nbsp;&nbsp;data: Data to explore for printable unicode string
`return: String`
&nbsp;&nbsp;&nbsp;&nbsp;False on failure, ascii-converted unicode string on discovered string.
---
###def hex_dump (self, data, addr=0, prefix=""):
**Utility function that converts data into hex dump format.**
`data:   Raw Bytes`:
&nbsp;&nbsp;&nbsp;&nbsp;data:   Raw bytes to view in hex dump
`addr:   DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;addr:   (Optional, def=0) Address to start hex offset display from
`prefix: String (Optional, def="")`:
&nbsp;&nbsp;&nbsp;&nbsp;prefix: String to prefix each line of hex dump with.
`return: String`
&nbsp;&nbsp;&nbsp;&nbsp;Hex dump of data.
---
###def hide_debugger (self):
**Hide the presence of the debugger. This routine requires an active context and therefore can not be called**
**immediately after a load() for example. Call it from the first chance breakpoint handler. This routine hides**
**the debugger in the following ways:**
**- Modifies the PEB flag that IsDebuggerPresent() checks for.**
**Raise Exception:pdx: An exception is raised if we are unable to hide the debugger for various reasons.**
---
###def is_address_on_stack (self, address, context=None):
**Utility function to determine if the specified address exists on the current thread stack or not.**
`address: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address: Address to check
`context: Context`:
&nbsp;&nbsp;&nbsp;&nbsp;context: (Optional) Current thread context to examine
`return: Bool`
&nbsp;&nbsp;&nbsp;&nbsp;True if address lies in current threads stack range, False otherwise.
---
###def iterate_modules (self):
**A simple iterator function that can be used to iterate through all modules the target process has mapped in its**
**address space. Yielded objects are of type MODULEENTRY32.**
**@author:  Otto Ebeling**
**@warning: break-ing out of loops over this routine will cause a handle leak.**
`return: MODULEENTRY32`
&nbsp;&nbsp;&nbsp;&nbsp;Iterated module entries.
---
###def iterate_processes (self):
**A simple iterator function that can be used to iterate through all running processes. Yielded objects are of**
**type PROCESSENTRY32.**
**@warning: break-ing out of loops over this routine will cause a handle leak.**
`return: PROCESSENTRY32`
&nbsp;&nbsp;&nbsp;&nbsp;Iterated process entries.
---
###def iterate_threads (self):
**A simple iterator function that can be used to iterate through all running processes. Yielded objects are of**
**type THREADENTRY32.**
**@warning: break-ing out of loops over this routine will cause a handle leak.**
`return: THREADENTRY32`
&nbsp;&nbsp;&nbsp;&nbsp;Iterated process entries.
---
###def flip_endian (self, dword):
**Utility function to flip the endianess a given DWORD into raw bytes.**
`dword: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;dowrd: DWORD whose endianess to flip
`return: Raw Bytes`
&nbsp;&nbsp;&nbsp;&nbsp;Converted DWORD in raw bytes.
---
###def flip_endian_dword (self, bytes):
**Utility function to flip the endianess of a given set of raw bytes into a DWORD.**
`bytes: Raw Bytes`:
&nbsp;&nbsp;&nbsp;&nbsp;bytes: Raw bytes whose endianess to flip
`return: DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;Converted DWORD.
---
###def load (self, path_to_file, command_line=None, create_new_console=False, show_window=True):
**Load the specified executable and optional command line arguments into the debugger.**
**@todo: This routines needs to be further tested ... I nomally just attach.**
`path_to_file:       String`:
&nbsp;&nbsp;&nbsp;&nbsp;path_to_file:       Full path to executable to load in debugger
`command_line:       String`:
&nbsp;&nbsp;&nbsp;&nbsp;command_line:       (Optional, def=None) Command line arguments to pass to debuggee
`create_new_console: Boolean`:
&nbsp;&nbsp;&nbsp;&nbsp;create_new_console: (Optional, def=False) Create a new console for the debuggee.
`show_window:        Boolean`:
&nbsp;&nbsp;&nbsp;&nbsp;show_window:        (Optional, def=True) Show / hide the debuggee window.
**Raise Exception:pdx: An exception is raised if we are unable to load the specified executable in the debugger.**
---
###def open_process (self, pid):
**Convenience wrapper around OpenProcess().**
`pid: Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;pid: Process ID to attach to
**Raise Exception:pdx: An exception is raised on failure.**
---
###def open_thread (self, thread_id):
**Convenience wrapper around OpenThread().**
`thread_id: Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;thread_id: ID of thread to obtain handle to
**Raise Exception:pdx: An exception is raised on failure.**
---
###def page_guard_clear (self):
**Clear all debugger-set PAGE_GUARDs from memory. This is useful for suspending memory breakpoints to single step**
**past a REP instruction.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def page_guard_restore (self):
**Restore all previously cleared debugger-set PAGE_GUARDs from memory. This is useful for suspending memory**
**breakpoints to single step past a REP instruction.**
`return: pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;Self
---
###def pid_to_port (self, pid):
**A helper function that enumerates the IPv4 endpoints for a given process ID.**
**@author:    Justin Seitz**
`pid: Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;pid: Process ID to find port information on.
**Raise Exception:pdx: An exception is raised on failure**
`return:    A list of tuples`
&nbsp;&nbsp;&nbsp;&nbsp;   A list of the protocol, bound address and listening port
---
###def process_restore (self):
**Restore memory / context snapshot of the debuggee. All threads must be suspended before calling this routine.**
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def process_snapshot (self, mem_only=False):
**Take memory / context snapshot of the debuggee. All threads must be suspended before calling this routine.**
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def read (self, address, length):
**Alias to read_process_memory().**
---
###def read_msr (self, address):
**Read data from the specified MSR address.**
`address: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address: MSR address to read from.
`return: tuple`
&nbsp;&nbsp;&nbsp;&nbsp;(read status, msr structure)
---
###def read_process_memory (self, address, length):
**Read from the debuggee process space.**
`address: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address: Address to read from.
`length:  Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;length:  Length, in bytes, of data to read.
**Raise Exception:pdx: An exception is raised on failure.**
`return:    Raw`
&nbsp;&nbsp;&nbsp;&nbsp;   Read data.
---
###def resume_all_threads (self):
**Resume all process threads.**
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def resume_thread (self, thread_id):
**Resume the specified thread.**
`thread_id: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;thread_id: ID of thread to resume.
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def ret_self (self):
**This convenience routine exists for internal functions to call and transparently return the correct version of**
**self. Specifically, an object in normal mode and a moniker when in client/server mode.**
&nbsp;&nbsp;&nbsp;&nbsp;Client / server safe version of self
---
###def run (self):
**Alias for debug_event_loop().**
---
###def seh_unwind (self, context=None):
**Unwind the the Structured Exception Handler (SEH) chain of the current or specified thread to the best of our**
**abilities. The SEH chain is a simple singly linked list, the head of which is pointed to by fs:0. In cases where**
**the SEH chain is corrupted and the handler address points to invalid memory, it will be returned as 0xFFFFFFFF.**
`context: Context`:
&nbsp;&nbsp;&nbsp;&nbsp;context: (Optional) Current thread context to examine
`return: List of Tuples`
&nbsp;&nbsp;&nbsp;&nbsp;Naturally ordered list of SEH addresses and handlers.
---
###def set_attr (self, attribute, value):
**Return the value for the specified class attribute. This routine should be used over directly accessing class**
**member variables for transparent support across local vs. client/server debugger clients.**
`attribute: String`:
&nbsp;&nbsp;&nbsp;&nbsp;attribute: Name of attribute to return.
`value:     Mixed`:
&nbsp;&nbsp;&nbsp;&nbsp;value:     Value to set attribute to.
---
###def set_callback (self, exception_code, callback_func):
**Set a callback for the specified exception (or debug event) code. The prototype of the callback routines is::**
**func (pydbg):**
**return DBG_CONTINUE     # or other continue status**
**You can register callbacks for any exception code or debug event. Look in the source for all event_handler_???**
**and exception_handler_??? routines to see which ones have internal processing (internal handlers will still**
**pass control to your callback). You can also register a user specified callback that is called on each loop**
**iteration from within debug_event_loop(). The callback code is USER_CALLBACK_DEBUG_EVENT and the function**
**prototype is::**
**func (pydbg)**
**return DBG_CONTINUE     # or other continue status**
**User callbacks do not / should not access debugger or contextual information.**
`exception_code: Long`:
&nbsp;&nbsp;&nbsp;&nbsp;exception_code: Exception code to establish a callback for
`callback_func:  Function`:
&nbsp;&nbsp;&nbsp;&nbsp;callback_func:  Function to call when specified exception code is caught.
---
###def set_debugger_active (self, enable):
**Enable or disable the control flag for the main debug event loop. This is a convenience shortcut over set_attr.**
`enable: Boolean`:
&nbsp;&nbsp;&nbsp;&nbsp;enable: Flag controlling the main debug event loop.
---
###def set_register (self, register, value):
**Set the value of a register in the debuggee within the context of the self.h_thread.**
`register: Register`:
&nbsp;&nbsp;&nbsp;&nbsp;register: One of EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, EIP
`value:    DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;value:    Value to set register to
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def set_thread_context (self, context, thread_handle=None, thread_id=0):
**Convenience wrapper around SetThreadContext(). Can set a thread context via a handle or thread id.**
`thread_handle: HANDLE`:
&nbsp;&nbsp;&nbsp;&nbsp;thread_handle: (Optional) Handle of thread to get context of
`context:       CONTEXT`:
&nbsp;&nbsp;&nbsp;&nbsp;context:       Context to apply to specified thread
`thread_id:     Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;thread_id:     (Optional, Def=0) ID of thread to get context of
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def sigint_handler (self, signal_number, stack_frame):
**Interrupt signal handler. We override the default handler to disable the run flag and exit the main**
**debug event loop.**
`signal_number:`:
&nbsp;&nbsp;&nbsp;&nbsp;signal_number:
`stack_frame:`:
&nbsp;&nbsp;&nbsp;&nbsp;stack_frame:
---
###def single_step (self, enable, thread_handle=None):
**Enable or disable single stepping in the specified thread or self.h_thread if a thread handle is not specified.**
`enable:        Bool`:
&nbsp;&nbsp;&nbsp;&nbsp;enable:        True to enable single stepping, False to disable
`thread_handle: Handle`:
&nbsp;&nbsp;&nbsp;&nbsp;thread_handle: (Optional, Def=None) Handle of thread to put into single step mode
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def smart_dereference (self, address, print_dots=True, hex_dump=False):
**"Intelligently" discover data behind an address. The address is dereferenced and explored in search of an ASCII**
**or Unicode string. In the absense of a string the printable characters are returned with non-printables**
**represented as dots (.). The location of the discovered data is returned as well as either "heap", "stack" or**
**the name of the module it lies in (global data).**
`address:    DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address:    Address to smart dereference
`print_dots: Bool`:
&nbsp;&nbsp;&nbsp;&nbsp;print_dots: (Optional, def:True) Controls suppression of dot in place of non-printable
`hex_dump:   Bool`:
&nbsp;&nbsp;&nbsp;&nbsp;hex_dump:   (Optional, def=False) Return a hex dump in the absense of string detection
`return: String`
&nbsp;&nbsp;&nbsp;&nbsp;String of data discovered behind dereference.
---
###def stack_range (self, context=None):
**Determine the stack range (top and bottom) of the current or specified thread. The desired information is**
**located at offsets 4 and 8 from the Thread Environment Block (TEB), which in turn is pointed to by fs:0.**
`context: Context`:
&nbsp;&nbsp;&nbsp;&nbsp;context: (Optional) Current thread context to examine
`return: Mixed`
&nbsp;&nbsp;&nbsp;&nbsp;List containing (stack_top, stack_bottom) on success, False otherwise.
---
###def stack_unwind (self, context=None):
**Unwind the stack to the best of our ability. This function is really only useful if called when EBP is actually**
**used as a frame pointer. If it is otherwise being used as a general purpose register then stack unwinding will**
**fail immediately.**
`context: Context`:
&nbsp;&nbsp;&nbsp;&nbsp;context: (Optional) Current thread context to examine
`return: List`
&nbsp;&nbsp;&nbsp;&nbsp;The current call stack ordered from most recent call backwards.
---
###def suspend_all_threads (self):
**Suspend all process threads.**
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def suspend_thread (self, thread_id):
**Suspend the specified thread.**
`thread_id: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;thread_id: ID of thread to suspend
**Raise Exception:pdx: An exception is raised on failure.**
`return:    pydbg`
&nbsp;&nbsp;&nbsp;&nbsp;   Self
---
###def terminate_process (self, exit_code=0, method="terminateprocess"):
**Terminate the debuggee using the specified method.**
**"terminateprocess": Terminate the debuggee by calling TerminateProcess(debuggee_handle).**
**"exitprocess":      Terminate the debuggee by setting its current EIP to ExitProcess().**
`exit_code: Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;exit_code: (Optional, def=0) Exit code
`method:    String`:
&nbsp;&nbsp;&nbsp;&nbsp;method:    (Optonal, def="terminateprocess") Termination method. See __doc__ for more info.
**Raise Exception:pdx: An exception is raised on failure.**
---
###def to_binary (self, number, bit_count=32):
**Convert a number into a binary string. This is an ugly one liner that I ripped off of some site.**
`number:    Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;number:    Number to convert to binary string.
`bit_count: Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;bit_count: (Optional, Def=32) Number of bits to include in output string.
`return: String`
&nbsp;&nbsp;&nbsp;&nbsp;Specified integer as a binary string
---
###def to_decimal (self, binary):
**Convert a binary string into a decimal number.**
`binary: String`:
&nbsp;&nbsp;&nbsp;&nbsp;binary: Binary string to convert to decimal
`return: Integer`
&nbsp;&nbsp;&nbsp;&nbsp;Specified binary string as an integer
---
###def virtual_alloc (self, address, size, alloc_type, protection):
**Convenience wrapper around VirtualAllocEx()**
`address:    DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address:    Desired starting address of region to allocate, can be None
`size:       Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;size:       Size of memory region to allocate, in bytes
`alloc_type: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;alloc_type: The type of memory allocation (most often MEM_COMMIT)
`protection: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;protection: Memory protection to apply to the specified region
**Raise Exception:pdx: An exception is raised on failure.**
`return:    DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;   Base address of the allocated region of pages.
---
###def virtual_free (self, address, size, free_type):
**Convenience wrapper around VirtualFreeEx()**
`address:    DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address:    Pointer to the starting address of the region of memory to be freed
`size:       Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;size:       Size of memory region to free, in bytes
`free_type:  DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;free_type:  The type of free operation
**Raise Exception:pdx: An exception is raised on failure.**
---
###def virtual_protect (self, base_address, size, protection):
**Convenience wrapper around VirtualProtectEx()**
`base_address: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;base_address: Base address of region of pages whose access protection attributes are to be changed
`size:         Integer`:
&nbsp;&nbsp;&nbsp;&nbsp;size:         Size of the region whose access protection attributes are to be changed
`protection:   DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;protection:   Memory protection to apply to the specified region
**Raise Exception:pdx: An exception is raised on failure.**
`return:    DWORD`
&nbsp;&nbsp;&nbsp;&nbsp;   Previous access protection.
---
###def virtual_query (self, address):
**Convenience wrapper around VirtualQueryEx().**
`address: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address: Address to query
**Raise Exception:pdx: An exception is raised on failure.**
`return: MEMORY_BASIC_INFORMATION`
&nbsp;&nbsp;&nbsp;&nbsp;MEMORY_BASIC_INFORMATION
---
###def win32_error (self, prefix=None):
**Convenience wrapper around GetLastError() and FormatMessage(). Raises an exception with the relevant error code**
**and formatted message.**
`prefix: String`:
&nbsp;&nbsp;&nbsp;&nbsp;prefix: (Optional) String to prefix error message with.
**Raise Exception:pdx: An exception is always raised by this routine.**
---
###def write (self, address, data, length=0):
**Alias to write_process_memory().**
---
###def write_msr (self, address, data):
**Write data to the specified MSR address.**
`address: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address: MSR address to write to.
`data:    QWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;data:    Data to write to MSR address.
`return: tuple`
&nbsp;&nbsp;&nbsp;&nbsp;(read status, msr structure)
---
###def write_process_memory (self, address, data, length=0):
**Write to the debuggee process space. Convenience wrapper around WriteProcessMemory(). This routine will**
**continuously attempt to write the data requested until it is complete.**
`address: DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;address: Address to write to
`data:    Raw Bytes`:
&nbsp;&nbsp;&nbsp;&nbsp;data:    Data to write
`length:  DWORD`:
&nbsp;&nbsp;&nbsp;&nbsp;length:  (Optional, Def:len(data)) Length of data, in bytes, to write
**Raise Exception:pdx: An exception is raised on failure.**

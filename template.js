import { VM, InstPosition, VMAction, SyncDirection, AnalysisType} from "./frida-qbdi.js";

// Inicializa a VM do QBDI
function QBI(ctx, funcPtr, funcSym, args, postSync){
    var vm = new VM();
    
    console.log("QBDI version is " + vm.version.string);
    
    var state = vm.getGPRState();


    state.synchronizeContext(ctx, SyncDirection.FRIDA_TO_QBDI);
    var stack = vm.allocateVirtualStack(state, 0x10000); 
    vm.addInstrumentedModuleFromAddr(funcPtr);
    //console.log(module)  
    
// Tabela de mapeamento de números de syscall para nomes de funções // aarch64
const syscallLookup = {
    0: "io_setup",
    1: "io_destroy",
    2: "io_submit",
    3: "io_cancel",
    4: "io_getevents",
    5: "setxattr",
    6: "lsetxattr",
    7: "fsetxattr",
    8: "getxattr",
    9: "lgetxattr",
    10: "fgetxattr",
    11: "listxattr",
    12: "llistxattr",
    13: "flistxattr",
    14: "removexattr",
    15: "lremovexattr",
    16: "fremovexattr",
    17: "getcwd",
    18: "lookup_dcookie",
    19: "eventfd2",
    20: "epoll_create1",
    21: "epoll_ctl",
    22: "epoll_pwait",
    23: "dup",
    24: "dup3",
    25: "fcntl",
    26: "inotify_init1",
    27: "inotify_add_watch",
    28: "inotify_rm_watch",
    29: "ioctl",
    30: "ioprio_set",
    31: "ioprio_get",
    32: "flock",
    33: "mknodat",
    34: "mkdirat",
    35: "unlinkat",
    36: "symlinkat",
    37: "linkat",
    38: "renameat",
    39: "umount2",
    40: "mount",
    41: "pivot_root",
    42: "nfsservctl",
    43: "statfs",
    44: "fstatfs",
    45: "truncate",
    46: "ftruncate",
    47: "fallocate",
    48: "faccessat",
    49: "chdir",
    50: "fchdir",
    51: "chroot",
    52: "fchmod",
    53: "fchmodat",
    54: "fchownat",
    55: "fchown",
    56: "openat",
    57: "close",
    58: "vhangup",
    59: "pipe2",
    60: "quotactl",
    61: "getdents64",
    62: "lseek",
    63: "read",
    64: "write",
    65: "readv",
    66: "writev",
    67: "pread64",
    68: "pwrite64",
    69: "preadv",
    70: "pwritev",
    71: "sendfile",
    72: "pselect6",
    73: "ppoll",
    74: "signalfd4",
    75: "vmsplice",
    76: "splice",
    77: "tee",
    78: "readlinkat",
    79: "newfstatat",
    80: "fstat",
    81: "sync",
    82: "fsync",
    83: "fdatasync",
    84: "sync_file_range",
    85: "timerfd_create",
    86: "timerfd_settime",
    87: "timerfd_gettime",
    88: "utimensat",
    89: "acct",
    90: "capget",
    91: "capset",
    92: "personality",
    93: "exit",
    94: "exit_group",
    95: "waitid",
    96: "set_tid_address",
    97: "unshare",
    98: "futex",
    99: "set_robust_list",
    100: "get_robust_list",
    101: "nanosleep",
    102: "getitimer",
    103: "setitimer",
    104: "kexec_load",
    105: "init_module",
    106: "delete_module",
    107: "timer_create",
    108: "timer_gettime",
    109: "timer_getoverrun",
    110: "timer_settime",
    111: "timer_delete",
    112: "clock_settime",
    113: "clock_gettime",
    114: "clock_getres",
    115: "clock_nanosleep",
    116: "syslog",
    117: "ptrace",
    118: "sched_setparam",
    119: "sched_setscheduler",
    120: "sched_getscheduler",
    121: "sched_getparam",
    122: "sched_setaffinity",
    123: "sched_getaffinity",
    124: "sched_yield",
    125: "sched_get_priority_max",
    126: "sched_get_priority_min",
    127: "sched_rr_get_interval",
    128: "restart_syscall",
    129: "kill",
    130: "tkill",
    131: "tgkill",
    132: "sigaltstack",
    133: "rt_sigsuspend",
    134: "rt_sigaction",
    135: "rt_sigprocmask",
    136: "rt_sigpending",
    137: "rt_sigtimedwait",
    138: "rt_sigqueueinfo",
    139: "rt_sigreturn",
    140: "setpriority",
    141: "getpriority",
    142: "reboot",
    143: "setregid",
    144: "setgid",
    145: "setreuid",
    146: "setuid",
    147: "setresuid",
    148: "getresuid",
    149: "setresgid",
    150: "getresgid",
    151: "setfsuid",
    152: "setfsgid",
    153: "times",
    154: "setpgid",
    155: "getpgid",
    156: "getsid",
    157: "setsid",
    158: "getgroups",
    159: "setgroups",
    160: "uname",
    161: "sethostname",
    162: "setdomainname",
    163: "getrlimit",
    164: "setrlimit",
    165: "getrusage",
    166: "umask",
    167: "prctl",
    168: "getcpu",
    169: "gettimeofday",
    170: "settimeofday",
    171: "adjtimex",
    172: "getpid",
    173: "getppid",
    174: "getuid",
    175: "geteuid",
    176: "getgid",
    177: "getegid",
    178: "gettid",
    179: "sysinfo",
    180: "mq_open",
    181: "mq_unlink",
    182: "mq_timedsend",
    183: "mq_timedreceive",
    184: "mq_notify",
    185: "mq_getsetattr",
    186: "msgget",
    187: "msgctl",
    188: "msgrcv",
    189: "msgsnd",
    190: "semget",
    191: "semctl",
    192: "semtimedop",
    193: "semop",
    194: "shmget",
    195: "shmctl",
    196: "shmat",
    197: "shmdt",
    198: "socket",
    199: "socketpair",
    200: "bind",
    201: "listen",
    202: "accept",
    203: "connect",
    204: "getsockname",
    205: "getpeername",
    206: "sendto",
    207: "recvfrom",
    208: "setsockopt",
    209: "getsockopt",
    210: "shutdown",
    211: "sendmsg",
    212: "recvmsg",
    213: "readahead",
    214: "brk",
    215: "munmap",
    216: "mremap",
    217: "add_key",
    218: "request_key",
    219: "keyctl",
    220: "clone",
    221: "execve",
    222: "mmap",
    223: "fadvise64",
    224: "swapon",
    225: "swapoff",
    226: "mprotect",
    227: "msync",
    228: "mlock",
    229: "munlock",
    230: "mlockall",
    231: "munlockall",
    232: "mincore",
    233: "madvise",
    234: "remap_file_pages",
    235: "mbind",
    236: "get_mempolicy",
    237: "set_mempolicy",
    238: "migrate_pages",
    239: "move_pages",
    240: "rt_tgsigqueueinfo",
    241: "perf_event_open",
    242: "accept4",
    243: "recvmmsg",
    260: "wait4",
    261: "prlimit64",
    262: "fanotify_init",
    263: "fanotify_mark",
    264: "name_to_handle_at",
    265: "open_by_handle_at",
    266: "clock_adjtime",
    267: "syncfs",
    268: "setns",
    269: "sendmmsg",
    270: "process_vm_readv",
    271: "process_vm_writev",
    272: "kcmp",
    273: "finit_module",
    274: "sched_setattr",
    275: "sched_getattr",
    276: "renameat2",
    277: "seccomp",
    278: "getrandom",
    279: "memfd_create",
    280: "bpf",
    281: "execveat",
    282: "userfaultfd",
    283: "membarrier",
    284: "mlock2",
    285: "copy_file_range",
    286: "preadv2",
    287: "pwritev2",
    288: "pkey_mprotect",
    289: "pkey_alloc",
    290: "pkey_free",
    291: "statx"
};


    // Define o callback para interceptar a instrução SVC
    // SVC MNEMONIC = service call
    function myCallback(vm, gprState, fprState, data) {
        const syscallNumber = gprState.getRegister("x8");
        if (syscallNumber == undefined) {
           // console.error("Syscall number is undefined!");
            return VMAction.CONTINUE;
        }
        const analysis = vm.getInstAnalysis(AnalysisType.ANALYSIS_INSTRUCTION || AnalysisType.ANALYSIS_DISASSEMBLY )

        //retorna a function referente ao numero da syscall
        const sysStr = syscallLookup[parseInt(syscallNumber.toString())] || "unknown_syscall";
      
        console.log("0x" + analysis.address.toString(16)+ " " + analysis.disassembly + ' Syscall: ' + sysStr);
        return VMAction.CONTINUE;
    }
    
    // Cria um callback nativo
    const callback = vm.newInstCallback(myCallback);
    
    // Adiciona o callback para o mnemônico "SVC"
    vm.addMnemonicCB("SVC",InstPosition.POSTINST, callback, null, 1);
    
    console.log("Callback added, starting VM run.");
    try {
        
        const entry = 100000;
        const javavm = ptr(args[0]);
        const reserved = ptr(args[1]);
        console.log("[+] Executing " + funcSym + "(" + javavm + ", " + reserved + ") through QBDI...");
        vm.call(funcPtr, [javavm, reserved]);
        var retVal = state.getRegister(); 
        console.log("[+] " + funcSym + "() returned " + retVal);    
        if (postSync) {
            state.synchronizeContext(ctx, SyncDirection.QBDI_TO_FRIDA);
        }
        //return   
        return retVal;
    } catch (err) {
        console.error("Error during VM run:", err);
    }
}

Java.perform(function() 
{
    const libraryName = "libbe1f.so";
    waitForLibLoading(libraryName);
});


function waitForLibLoading(libraryName) 
{
    var isLibLoaded = false;
    console.log(isLibLoaded)
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), 
    {
        onEnter: function (args) {
            var libraryPath = Memory.readCString(args[0]);
            if (libraryPath.includes(libraryName)) {
                console.log("[+] Loading library " + libraryPath + "...");
                isLibLoaded = true;
            }
        },
        onLeave: function (args) {
            if (isLibLoaded) 
            {

                processJniOnLoad(libraryName);
                var module = Process.findModuleByName(libraryName);

                console.log("[*] Base: " + module.base);
                isLibLoaded = false;
            }
            //console.log(isLibLoaded)
        }
    });
}
function processJniOnLoad(libraryName) 
{
    const funcSym = "JNI_OnLoad";
    const funcPtr = Module.findExportByName(libraryName, funcSym);

    console.log("[+] Replacing " + funcSym + "() @ " + funcPtr + "...");
    
    // jint JNI_OnLoad(JavaVM *vm, void *reserved);
    
    Interceptor.replace(funcPtr, new NativeCallback(function (load_vm, load_reserved) 
    {
        const vm = load_vm;
        const reserved = load_reserved;
        console.log("[+] " + funcSym + "(" + vm + ", " + reserved + ") called");
        Interceptor.revert(funcPtr); 
        Interceptor.flush(); 
       
        var retval = QBI(this.context, funcPtr, funcSym, [vm, reserved], true);
        processJniOnLoad(libraryName, funcSym);
        return retVal;
    }, "long", ["pointer", "pointer"]));

}

# frida-qbdi
Template Frida QBDI native function loader

## Requirements

* /data/local/tmp/libQBDI.so

* frida-compile


## Template Example

The example in the template uses qbdi to return the syscalls made, and using the syscall number we try to obtain the function.

    function myCallback(vm, gprState, fprState, data) {
        //console.log("Callback executed");
        const syscallNumber = gprState.getRegister("x8");
        if (syscallNumber == undefined) {
           // console.error("Syscall number is undefined!");
            return VMAction.CONTINUE;
        }
        const analysis = vm.getInstAnalysis(AnalysisType.ANALYSIS_INSTRUCTION || AnalysisType.ANALYSIS_DISASSEMBLY )
        
        const sysStr = syscallLookup[parseInt(syscallNumber.toString())] || "unknown_syscall";
        console.log("0x" + analysis.address.toString(16)+ " " + analysis.disassembly + ' Syscall: ' + sysStr);
        return VMAction.CONTINUE;
    }
![frida-qbdi.png](https://github.com/thalysonz/frida-qbdi/blob/main/frida-qbdi.png)

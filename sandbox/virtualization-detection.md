# Virtualization Detection Evasion

TODO: write introduction, remember to say that this is focused on the kvm hypervisor and windows VMs


## [Pafish](https://github.com/a0rtega/pafish)

Pafish is an open source tool used to detect analysis enviroments. 

Here's an example of Pafish's output:

````
[pafish] Start
[pafish] Windows version: 6.2 build 9200 (WoW64)
[pafish] CPU: GenuineIntel (HV: Microsoft Hv) QEMU Virtual CPU version 2.5+
[pafish] CPU VM traced by checking the difference between CPU timestamp counters (rdtsc) forcing VM exit
[pafish] CPU VM traced by checking hypervisor bit in cpuid feature bits
[pafish] CPU VM traced by checking cpuid hypervisor vendor for known VM vendors
[pafish] Start
[pafish] Windows version: 6.2 build 9200 (WoW64)
[pafish] CPU: GenuineIntel (HV: Microsoft Hv) QEMU Virtual CPU version 2.5+
[pafish] CPU VM traced by checking the difference between CPU timestamp counters (rdtsc) forcing VM exit
[pafish] CPU VM traced by checking hypervisor bit in cpuid feature bits
[pafish] CPU VM traced by checking cpuid hypervisor vendor for known VM vendors
[pafish] Sandbox traced by missing dialog confirmation
[pafish] Sandbox traced by missing or implausible dialog confirmation
[pafish] Sandbox traced by checking disk size <= 60GB via DeviceIoControl()
[pafish] Sandbox traced by checking disk size <= 60GB via GetDiskFreeSpaceExA()
[pafish] Start
[pafish] Windows version: 6.2 build 9200 (WoW64)
[pafish] CPU: GenuineIntel (HV: Microsoft Hv) QEMU Virtual CPU version 2.5+
[pafish] CPU VM traced by checking the difference between CPU timestamp counters (rdtsc) forcing VM exit
[pafish] CPU VM traced by checking hypervisor bit in cpuid feature bits
[pafish] CPU VM traced by checking cpuid hypervisor vendor for known VM vendors
[pafish] Sandbox traced by missing mouse click activity
[pafish] Sandbox traced by missing double click activity
[pafish] Start
[pafish] Windows version: 6.2 build 9200 (WoW64)
[pafish] CPU: GenuineIntel (HV: Microsoft Hv) QEMU Virtual CPU version 2.5+
[pafish] CPU VM traced by checking the difference between CPU timestamp counters (rdtsc) forcing VM exit
[pafish] CPU VM traced by checking hypervisor bit in cpuid feature bits
[pafish] CPU VM traced by checking cpuid hypervisor vendor for known VM vendors
[pafish] Sandbox traced by missing mouse movement
[pafish] Sandbox traced by missing mouse movement or supernatural speed
[pafish] Sandbox traced by missing mouse click activity
[pafish] Sandbox traced by missing double click activity
[pafish] Sandbox traced by missing or implausible dialog confirmation
[pafish] Sandbox traced by checking disk size <= 60GB via DeviceIoControl()
[pafish] Sandbox traced by checking disk size <= 60GB via GetDiskFreeSpaceExA()
[pafish] Sandbox traced by checking operating system uptime using GetTickCount()
[pafish] Hooks traced using ShellExecuteExW method 1
[pafish] Qemu traced using CPU brand string 'QEMU Virtual CPU'
[pafish] Bochs traced using Reg key HKLM\HARDWARE\Description\System "SystemBiosVersion"
[pafish] End
````
The example above was obtained by running pafish on SACI's sandbox

## Detection Techniques and How to bypass them

Let's break down the output from pafish and figure out how each one was traced and how we can make them untraceable

### CPU VM Detection

One of the ways malware will use to detect a vrtualized enviroment is by checking some cpu info. On x86 cpus there's an intruction [`cpuid`](https://learn.microsoft.com/pt-br/cpp/intrinsics/cpuid-cpuidex?view=msvc-170), which can be used to retrieve information about the cpu. According to intel's reference manual by changing the value of the EAX register, the set of informations retrieved will vary. 

#### RDTSC forcing Vm exit

Some API calls' execution time differ from when they're being executed outside of the virtualized enviroment. One of these intruction is the `cpuid` intruction. A malware could use the instruction [`__rstsc`](https://learn.microsoft.com/pt-br/cpp/intrinsics/rdtsc?view=msvc-170) to check the cpu timestamps and see if the calls are taking a different amount of time than they normally would.
By calling a privileged instruction, like `cpuid`, you will uncondionally cause a VM exit[^1] causing it to taking longer than it would on the host.
Note that depending on some settings `__rdtsc` may also cause vm exit, for more information see “Changes to Instruction Behavior in VMX Non-Root Operation” in Chapter 26 of the Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 3C, for more information about the behavior of this instruction in VMX non-root operation.

```
BOOL rdtsc_diff_vmexit()
{
    ULONGLONG tsc1 = 0;
    ULONGLONG tsc2 = 0;
    ULONGLONG avg = 0;
    INT cpuInfo[4] = {};

    // Try this 10 times in case of small fluctuations
    for (INT i = 0; i < 10; i++)
    {
        tsc1 = __rdtsc();
        __cpuid(cpuInfo, 0);
        tsc2 = __rdtsc();

        // Get the delta of the two RDTSC
        avg += (tsc2 - tsc1);
    }

    // We repeated the process 10 times so we make sure our check is as much reliable as we can
    avg = avg / 10;
    return (avg < 1000 && avg > 0) ? FALSE : TRUE;
}
```

Here an example of how one could implement this. credit to [al-kasher](https://github.com/LordNoteworthy/al-khaser)

Now comes the question on how to hide this delay from the malware. So it's possible to achieve this by patching kvm, so it will create fake timestamps that will take into account the time spent outside of the vm. This [patch](https://gitlab.com/DonnerPartyOf1/kvm-hidden/-/blob/master/rdtscv2.patch) implements exactly this.

Here the main function that will allow this: 

```
static int handle_rdtsc(struct kvm_vcpu *vcpu) 
{ 
    u64 rdtsc_fake = vcpu->last_exit_start - vcpu->total_exit_time;

    vcpu->arch.regs[VCPU_REGS_RAX] = rdtsc_fake & -1u;
    vcpu->arch.regs[VCPU_REGS_RDX] = (rdtsc_fake >> 32) & -1u;
    
    return skip_emulated_instruction(vcpu);
}

```

In the first instruction








## Referências

Intel® 64 and IA-32 Architectures Software Developer’s Manual Volume 3C: System Programming Guide, Part 3 Order Number: 326019-072US May 2020

[Spoof and make your VM Undetectable - Reddit](https://www.reddit.com/r/VFIO/comments/i071qx/spoof_and_make_your_vm_undetectable_no_more/)

[Kvm and Qemu Patches](https://gitlab.com/DonnerPartyOf1/kvm-hidden/-/tree/master)

[Disable the hipervisor bit](https://www.reddit.com/r/VFIO/comments/jpvf2c/disable_the_hypervisor_flag_at_runtime_vm/)

[Evasion Techniques](https://evasions.checkpoint.com/)

[^1]: So this is a big one. Intel's VMX(virtual machine extensions) uses a VMCS(Virtual machine control structure) to control the vm, this structure will hold the cpu state from the guest and host os/hypervisor, when the guest state is loaded and its code is executed, it's called vm entry. When some condition is met, like a interruption or a trap like the on genrated by cpuid, the host os state will be loaded to take care of that, this is whats called a vm exit. [more info](https://stromberry.com/vmcs-virtual-machine-control-structures/)
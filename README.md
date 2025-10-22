# otel-ebpf-profiler-vfork-sample

This repository is used to debug an issue with the OTEL eBPF profiler and `vfork`.

## Test setup

On a `x86_64` host checkout this repository. Make sure that `golang`, `docker`, `gcc` is installed.
The host I use is using GLIBC v2.42.

Build [danielpacak/opentelemetry-lazybackend](https://github.com/danielpacak/opentelemetry-lazybackend) and run:
```sh
git clone https://github.com/danielpacak/opentelemetry-lazybackend
cd opentelemetry-lazybackend
go run ./main.go
```

Open a new terminal.

Clone and build the OTEL eBPF profiler:
```sh
git clone https://github.com/open-telemetry/opentelemetry-ebpf-profiler
cd opentelemetry-ebpf-profiler
make agent
sudo ./ebpf-profiler -collection-agent="localhost:4137" -disable-tls
```

Open a new terminal.

[dummy.c](dummy.c) contains a small simple example, that calls `vfork` in a loop every `100ms`.

Build and run the sample:
```sh
gcc -o dummy dummy.c
./dummy
```

In the opentelemetry-lazybackend terminal window, you should now see profiles arriving.

## Issue

If the `vfork` libc function is used, samples are missing any frames from the application. The issue
occurs on `x86_64`, but not `aarch64`.

Here is a full sampel collected for the `dummy` program:
```
------------------- New Sample --------------------
  Timestamp[0]: 1761136876434313775 (2025-10-22 12:41:16.434313775 +0000 UTC)
  thread.name: dummy
  process.executable.name: dummy
  process.executable.path: /home/laborant/sample/dummy
  process.pid: 9685
  thread.id: 9685
---------------------------------------------------
Instrumentation: kernel, Function: queue_work_on, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: tty_insert_flip_string_and_push_buffer, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: pty_write, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: process_output_block, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: n_tty_write, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: do_tty_write, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: file_tty_write.constprop.0, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: tty_write, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: new_sync_write, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: vfs_write, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: ksys_write, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: __x64_sys_write, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: do_syscall_64, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: entry_SYSCALL_64_after_hwframe, File: , Line: 0, Column: 0
Instrumentation: native: Function: 0x931cd, File: libc.so.6
Instrumentation: native: Function: 0x931f3, File: libc.so.6
Instrumentation: native: Function: 0x10e53d, File: libc.so.6
Instrumentation: native: Function: 0x8eb74, File: libc.so.6
Instrumentation: native: Function: 0x8c9b5, File: libc.so.6
Instrumentation: native: Function: 0x8dae0, File: libc.so.6
Instrumentation: native: Function: 0x8dfff, File: libc.so.6
Instrumentation: native: Function: 0x82e79, File: libc.so.6
Instrumentation: native: Function: 0x12c6, File: dummy
Instrumentation: native: Function: 0x11d1, File: dummy
Instrumentation: native: Function: 0x27674, File: libc.so.6
Instrumentation: native: Function: 0x27728, File: libc.so.6
Instrumentation: native: Function: 0x10f4, File: dummy
```

And here a sample that contains the frames up to a function in `libc.so.6`.

```
------------------- New Sample --------------------
  Timestamp[0]: 1761136872834323100 (2025-10-22 12:41:12.8343231 +0000 UTC)
  thread.name: dummy
  process.executable.name: dummy
  process.executable.path: /home/laborant/sample/dummy
  process.pid: 9685
  thread.id: 9685
---------------------------------------------------
Instrumentation: kernel, Function: selinux_cred_prepare, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: prepare_creds, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: copy_creds, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: copy_process, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: kernel_clone, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: __do_sys_vfork, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: do_syscall_64, File: , Line: 0, Column: 0
Instrumentation: kernel, Function: entry_SYSCALL_64_after_hwframe, File: , Line: 0, Column: 0
Instrumentation: native: Function: 0x103d3b, File: libc.so.6
```

Function `0x103d3b` corresponds to the `vfork` function within GLIBC.

Looking at the source code of `vfork` ([source](https://elixir.bootlin.com/glibc/glibc-2.42.9000/source/sysdeps/unix/sysv/linux/x86_64/vfork.S#L32)), the issue
becomes quite clear:
```c
ENTRY (__vfork)

	/* Pop the return PC value into RDI.  We need a register that
	   is preserved by the syscall and that we're allowed to destroy. */
	popq	%rdi /* <-- here is the issue */
	cfi_adjust_cfa_offset(-8)
	cfi_register(%rip, %rdi)

	/* Stuff the syscall number in RAX and enter into the kernel.  */
	movl	$SYS_ify (vfork), %eax
	syscall

	/* Push back the return PC.  */
	pushq	%rdi
	cfi_adjust_cfa_offset(8)

	cmpl	$-4095, %eax
	jae SYSCALL_ERROR_LABEL		/* Branch forward if it failed.  */
```

The the return `PC` value is popped into the `RDI` register. This case isn't handled by the OTEL eBPF profiler.
`GLIBC` does include `CFI` instructions though on how to recover the `PC`. There is support for some CFI instructions in
the profiler, but from what I can tell it is lacking support for the `RDI` register ([source](https://github.com/patrickpichler/opentelemetry-ebpf-profiler/blob/eb8909ecce3f8dba1eec6bb3d20e6d495a27b937/nativeunwind/elfunwindinfo/elfehframe_x86.go#L142)).

For MUSL the situation is a bit different. Here is what `vfork` looks in MUSL `1.2.5` for `x86_64`:
```c
.global vfork
.type vfork,@function
vfork:
	pop %rdx
	mov $58,%eax
	syscall
	push %rdx
	mov %rax,%rdi
	.hidden __syscall_ret
	jmp __syscall_ret
```

There are no manual `CFI` instructions in the code. There is an open issue though to rework some AWK scripts that produce
those CFI instructions ([link](https://www.openwall.com/lists/musl/2025/03/20/6)).

**TODO:** investigate if MUSL CFI instructions are present or not

The reason why this issue doesn't occur on `aarch64` is, that there is **no** `vfork` syscall! GLIBC implements `vfork`
on top of `clone` ([source](https://elixir.bootlin.com/glibc/glibc-2.42.9000/source/sysdeps/unix/sysv/linux/aarch64/vfork.S#L28)). No `PC` popping is happening.

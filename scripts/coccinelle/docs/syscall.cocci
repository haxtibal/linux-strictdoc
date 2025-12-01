@syscall@
identifier fn;
position p;
type t;
@@

/* Relies on special --macro-file-builtins standard.h,
 * where SYSCALL macros are enhanced with searchable fake parameters
 */
(
 t fn(void SYSCALL_DEFINE0, ...) {@p ... }
|
 t fn(void SYSCALL_DEFINE1, ...) {@p ... }
|
 t fn(void SYSCALL_DEFINE2, ...) {@p ... }
|
 t fn(void SYSCALL_DEFINE3, ...) {@p ... }
|
 t fn(void SYSCALL_DEFINE4, ...) {@p ... }
|
 t fn(void SYSCALL_DEFINE5, ...) {@p ... }
|
 t fn(void SYSCALL_DEFINE6, ...) {@p ... }
)


@compat_syscall@
identifier fn;
position p;
type t;
@@

(
 t fn(void COMPAT_SYSCALL_DEFINE0, ...) {@p ... }
|
 t fn(void COMPAT_SYSCALL_DEFINE1, ...) {@p ... }
|
 t fn(void COMPAT_SYSCALL_DEFINE2, ...) {@p ... }
|
 t fn(void COMPAT_SYSCALL_DEFINE3, ...) {@p ... }
|
 t fn(void COMPAT_SYSCALL_DEFINE4, ...) {@p ... }
|
 t fn(void COMPAT_SYSCALL_DEFINE5, ...) {@p ... }
|
 t fn(void COMPAT_SYSCALL_DEFINE6, ...) {@p ... }
)


@script:python@
fn << syscall.fn;
p << syscall.p;
@@

print(f"syscall: {fn} in {p[0].file}:{p[0].line}")


@script:python@
fn << compat_syscall.fn;
p << compat_syscall.p;
@@

print(f"compat syscall: {fn} in {p[0].file}:{p[0].line}")

#!/bin/bash

coccidir=$(dirname "$0")

/usr/bin/spatch \
  --very-quiet \
  --cocci-file "${coccidir}/syscall.cocci" \
  --macro-file-builtins "${coccidir}/standard.h" \
  --no-includes \
  --include-headers \
  -I ./arch/x86/include \
  -I ./arch/x86/include/generated \
  -I ./include \
  -I ./include \
  -I ./arch/x86/include/uapi \
  -I ./arch/x86/include/generated/uapi \
  -I ./include/uapi \
  -I ./include/generated/uapi \
  --include ./include/linux/compiler-version.h \
  --include ./include/linux/kconfig.h \
  --jobs 4 --chunksize 1 \
  --dir .

/usr/bin/spatch \
  --very-quiet \
  --cocci-file "${coccidir}/exportedsyms.cocci" \
  --no-includes \
  --include-headers \
  -I ./arch/x86/include \
  -I ./arch/x86/include/generated \
  -I ./include \
  -I ./include \
  -I ./arch/x86/include/uapi \
  -I ./arch/x86/include/generated/uapi \
  -I ./include/uapi \
  -I ./include/generated/uapi \
  --include ./include/linux/compiler-version.h \
  --include ./include/linux/kconfig.h \
  --jobs 4 --chunksize 1 \
  --no-show-diff \
  --dir .

/usr/bin/spatch \
  --very-quiet \
  --cocci-file "${coccidir}/sysfs.cocci" \
  --no-includes \
  --include-headers \
  -I ./arch/x86/include \
  -I ./arch/x86/include/generated \
  -I ./include \
  -I ./include \
  -I ./arch/x86/include/uapi \
  -I ./arch/x86/include/generated/uapi \
  -I ./include/uapi \
  -I ./include/generated/uapi \
  --include ./include/linux/compiler-version.h \
  --include ./include/linux/kconfig.h \
  --jobs 4 --chunksize 1 \
  --no-show-diff \
  --dir .

/usr/bin/spatch \
  --very-quiet \
  --cocci-file "${coccidir}/fops.cocci" \
  --no-includes \
  --include-headers \
  -I ./arch/x86/include \
  -I ./arch/x86/include/generated \
  -I ./include \
  -I ./include \
  -I ./arch/x86/include/uapi \
  -I ./arch/x86/include/generated/uapi \
  -I ./include/uapi \
  -I ./include/generated/uapi \
  --include ./include/linux/compiler-version.h \
  --include ./include/linux/kconfig.h \
  --jobs 4 --chunksize 1 \
  --dir .

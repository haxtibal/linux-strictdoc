/*
 * All functions of file-like drivers.
 */

@ fops0 @
identifier fops;
@@
  struct file_operations fops = {
    ...
  };

@ has_read @
identifier fops0.fops;
identifier read_f;
@@
  struct file_operations fops = {
    .read = read_f,
  };

@ read_fn @
identifier has_read.read_f;
position p_read_f;
@@
  read_f@p_read_f(...) {...}


@ has_read_iter @
identifier fops0.fops;
identifier read_iter_f;
@@
  struct file_operations fops = {
    .read_iter = read_iter_f,
  };

@ read_iter_fn @
identifier has_read_iter.read_iter_f;
position p_read_iter_f;
@@
  read_iter_f@p_read_iter_f(...) {...}


@ has_write @
identifier fops0.fops;
identifier write_f;
@@
  struct file_operations fops = {
    .write = write_f,
  };

@ write_fn @
identifier has_write.write_f;
position p_write_f;
@@
  write_f@p_write_f(...) {...}


@ has_write_iter @
identifier fops0.fops;
identifier write_iter_f;
@@
  struct file_operations fops = {
    .write_iter = write_iter_f,
  };

@ write_iter_fn @
identifier has_write_iter.write_iter_f;
position p_write_iter_f;
@@
  write_iter_f@p_write_iter_f(...) {...}


@ has_llseek @
identifier fops0.fops;
identifier llseek_f;
@@
  struct file_operations fops = {
    .llseek = llseek_f,
  };

@ llseek_fn @
identifier has_llseek.llseek_f;
position p_llseek_f;
@@
  llseek_f@p_llseek_f(...) {...}


@ has_mmap @
identifier fops0.fops;
identifier mmap_f;
@@
  struct file_operations fops = {
    .mmap = mmap_f,
  };

@ mmap_fn @
identifier has_mmap.mmap_f;
position p_mmap_f;
@@
  mmap_f@p_mmap_f(...) {...}


@ has_copy_file_range @
identifier fops0.fops;
identifier copy_file_range_f;
@@
  struct file_operations fops = {
    .copy_file_range = copy_file_range_f,
  };

@ copy_file_range_fn @
identifier has_copy_file_range.copy_file_range_f;
position p_copy_file_range_f;
@@
  copy_file_range_f@p_copy_file_range_f(...) {...}


@ has_remap_file_range @
identifier fops0.fops;
identifier remap_file_range_f;
@@
  struct file_operations fops = {
    .remap_file_range = remap_file_range_f,
  };

@ remap_file_range_fn @
identifier has_remap_file_range.remap_file_range_f;
position p_remap_file_range_f;
@@
  remap_file_range_f@p_remap_file_range_f(...) {...}


@ has_splice_read @
identifier fops0.fops;
identifier splice_read_f;
@@
  struct file_operations fops = {
    .splice_read = splice_read_f,
  };

@ splice_read_fn @
identifier has_splice_read.splice_read_f;
position p_splice_read_f;
@@
  splice_read_f@p_splice_read_f(...) {...}


@ has_splice_write @
identifier fops0.fops;
identifier splice_write_f;
@@
  struct file_operations fops = {
    .splice_write = splice_write_f,
  };

@ splice_write_fn @
identifier has_splice_write.splice_write_f;
position p_splice_write_f;
@@
  splice_write_f@p_splice_write_f(...) {...}


@ script:python@
fops << fops0.fops;
read_f << has_read.read_f;
p << read_fn.p_read_f;
@@
print(f"read ({fops}): {read_f} at {p[0].file}:{p[0].line}")

@script:python@
fops << fops0.fops;
read_iter_f << has_read_iter.read_iter_f;
p << read_iter_fn.p_read_iter_f;
@@
print(f"read_iter ({fops}): {read_iter_f} at {p[0].file}:{p[0].line}")

@script:python@
fops << fops0.fops;
write_f << has_write.write_f;
p << write_fn.p_write_f;
@@
print(f"write ({fops}): {write_f} at {p[0].file}:{p[0].line}")

@script:python@
fops << fops0.fops;
write_iter_f << has_write_iter.write_iter_f;
p << write_iter_fn.p_write_iter_f;
@@
print(f"write_iter ({fops}): {write_iter_f} at {p[0].file}:{p[0].line}")

@script:python@
fops << fops0.fops;
llseek_f << has_llseek.llseek_f;
p << llseek_fn.p_llseek_f;
@@
print(f"llseek ({fops}): {llseek_f} at {p[0].file}:{p[0].line}")

@script:python@
fops << fops0.fops;
mmap_f << has_mmap.mmap_f;
p << mmap_fn.p_mmap_f;
@@
print(f"mmap_f ({fops}): {mmap_f} at {p[0].file}:{p[0].line}")

@script:python@
fops << fops0.fops;
copy_file_range_f << has_copy_file_range.copy_file_range_f;
p << copy_file_range_fn.p_copy_file_range_f;
@@
print(f"copy_file_range ({fops}): {copy_file_range_f} at {p[0].file}:{p[0].line}")

@script:python@
fops << fops0.fops;
remap_file_range_f << has_remap_file_range.remap_file_range_f;
p << remap_file_range_fn.p_remap_file_range_f;
@@
print(f"remap_file_range ({fops}): {remap_file_range_f} at {p[0].file}:{p[0].line}")

@script:python@
fops << fops0.fops;
splice_read_f << has_splice_read.splice_read_f;
p << splice_read_fn.p_splice_read_f;
@@
print(f"splice_read ({fops}): {splice_read_f} at {p[0].file}:{p[0].line}")

@script:python@
fops << fops0.fops;
splice_write_f << has_splice_write.splice_write_f;
p << splice_write_fn.p_splice_write_f;
@@
print(f"splice_write ({fops}): {splice_write_f} at {p[0].file}:{p[0].line}")

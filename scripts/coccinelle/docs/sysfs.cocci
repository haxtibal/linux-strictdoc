/*
 * sysfs
 *
 * Devices may export their attributes through sysfs, where registered show and
 * store callbacks can be considered functional entrypoints. All show and store
 * callbacks should be documented as LLR.
 *
 * This implements a search for macros DEVICE_ATTR, DEVICE_ATTR_RO,
 * DEVICE_ATTR_RW, and then finds the name and position of the show and store
 * callbacks assigned by the macros.
 */


// DEVICE_ATTR

@device_attr@
declarer name DEVICE_ATTR;
identifier attr_name, show_fn, store_fn;
@@
  DEVICE_ATTR(attr_name, ..., show_fn, store_fn);

@device_attr_show_fn@
identifier device_attr.show_fn;
position p_fn;
@@
  show_fn@p_fn(...) {...}

@device_attr_store_fn@
identifier device_attr.store_fn;
position p_fn;
@@
  store_fn@p_fn(...) {...}


// DEVICE_ATTR_RO

@device_attr_ro@
declarer name DEVICE_ATTR_RO;
identifier attr_name;
@@
  DEVICE_ATTR_RO(attr_name);

@script:python device_attr_ro_funcs@
attr_name << device_attr_ro.attr_name;
SHOW;
@@
coccinelle.SHOW = cocci.make_ident(attr_name + "_show")

@device_attr_ro_show_fn@
identifier device_attr_ro_funcs.SHOW;
position p_fn;
@@
  SHOW@p_fn(...) {...}


// DEVICE_ATTR_RW

@device_attr_rw@
declarer name DEVICE_ATTR_RW;
identifier attr_name;
@@
  DEVICE_ATTR_RW(attr_name);

@script:python device_attr_rw_funcs@
attr_name << device_attr_rw.attr_name;
SHOW;
STORE;
@@
coccinelle.SHOW = cocci.make_ident(attr_name + "_show")
coccinelle.STORE = cocci.make_ident(attr_name + "_store")

@device_attr_rw_show_fn@
identifier device_attr_rw_funcs.SHOW;
position p_fn;
@@
  SHOW@p_fn(...) {...}

@device_attr_rw_store_fn@
identifier device_attr_rw_funcs.STORE;
position p_fn;
@@
  STORE@p_fn(...) {...}


// Report

@script:python@
fn << device_attr.show_fn;
p << device_attr_show_fn.p_fn;
@@
print(f"sysfs show: {fn} at {p[0].file}:{p[0].line}")

@script:python@
fn << device_attr.store_fn;
p << device_attr_store_fn.p_fn;
@@
print(f"sysfs store: {fn} at {p[0].file}:{p[0].line}")

@script:python@
fn << device_attr_ro_funcs.SHOW;
p << device_attr_ro_show_fn.p_fn;
@@
print(f"sysfs show (RO): {fn} at {p[0].file}:{p[0].line}")

@script:python@
fn << device_attr_rw_funcs.SHOW;
p << device_attr_rw_show_fn.p_fn;
@@
print(f"sysfs show (RW): {fn} at {p[0].file}:{p[0].line}")

@script:python@
fn << device_attr_rw_funcs.STORE;
p << device_attr_rw_store_fn.p_fn;
@@
print(f"sysfs store (RW): {fn} at {p[0].file}:{p[0].line}")

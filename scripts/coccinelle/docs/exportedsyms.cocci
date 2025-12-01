/*
 * Exported Symbols
 *
 * Exported symbols are accessible to loadable module and out-of-tree drivers
 * and thus are public API.
 * 
 * This implements a search for macros EXPORT_SYMBOL and EXPORT_SYMBOL_GPL,
 * and then finds the name and position of the referenced function definition.
 */


@export_symbol@
declarer name EXPORT_SYMBOL;
declarer name EXPORT_SYMBOL_GPL;
identifier fn;
@@
(
  EXPORT_SYMBOL(fn);
|
  EXPORT_SYMBOL_GPL(fn);
)

@export_symbol_fn@
identifier export_symbol.fn;
position p_fn;
@@
  fn@p_fn(...) {...}


// Report

@script:python@
fn << export_symbol.fn;
p << export_symbol_fn.p_fn;
@@
print(f"exported function: {fn} at {p[0].file}:{p[0].line}")

# Exploring possibilities for integrating StrictDoc with ELISA’s requirements template approach for the Linux kernel

This demonstrates how to realize the tool-agnostic
[ELISA Kernel Requirements Template](https://docs.google.com/document/d/1c7S7YAledHP2EEQ2nh26Ibegij-XPNuUFkrFLtJPlzs/edit?tab=t.0)
proposal by using [StrictDoc](https://strictdoc.readthedocs.io) as requirements
processing tool. The repository is a copy of the Linux kernel with requirements
and tests from Alessandro Carminat and Gabriele Paoloni ([^1], [^2]) applied on
top. ELISA's
[`SPDX-*` tagging scheme]((https://docs.google.com/document/d/1c7S7YAledHP2EEQ2nh26Ibegij-XPNuUFkrFLtJPlzs/edit?tab=t.0#heading=h.9dudo2y6dlhf))
was
[added](https://github.com/strictdoc-project/linux-strictdoc/commit/a59697d733f2)
along with a minimal StrictDoc project configuration.

[^1]: https://lore.kernel.org/all/20250910170000.6475-1-gpaoloni@redhat.com/
[^2]: https://lore.kernel.org/linux-trace-kernel/20250814122206.109096-1-gpaoloni@redhat.com/#r

Go to [rendered requirements](https://strictdoc-project.github.io/linux-strictdoc/).

## Demonstrated features

- Use `strictdoc export .` to generate a nice
  [static HTML document tree](https://strictdoc-project.github.io/linux-strictdoc/linux-strictdoc/Documentation/requirements/charmisc.html)
  with visual representation of the
  [traceability graph](https://strictdoc-project.github.io/linux-strictdoc/linux-strictdoc/Documentation/requirements/charmisc-TRACE.html#DOC-SUBSYS-CHARMISC),
  validation results and full-text search. Other output formats as e.g. PDF are available.
- Compile and validate requirements
  [in CI](https://github.com/strictdoc-project/linux-strictdoc/blob/lpc25/.github/workflows/ci.yaml).
- Parses source code
  [SPDX-Req-* tags proposed by ELISA](https://docs.google.com/document/d/1c7S7YAledHP2EEQ2nh26Ibegij-XPNuUFkrFLtJPlzs/edit?tab=t.0#heading=h.9dudo2y6dlhf)
  and translates them to StrictDocs internal model.
- Sidecar: Proposed by ELISA to hold additional requirement meta data outside source code. Realized as
  [separate sdoc file](https://github.com/strictdoc-project/linux-strictdoc/blob/lpc25/Documentation/requirements/tracing.sdoc)s
  containing requirement stubs. Stubs are merged with source code tags by matching on `SPDX-Req-ID`.
- Use `strictdoc manage auto-assign` to generate SPDX-Req-ID and SPDX-Req-HKey as suggested by Linux kernel 
  requirements template. The hash generation method is `echo -nE "${PROJECT}${FILE_PATH}${INSTANCE}${CODE}" | sha256sum`.
  See [commit f8fbab99aa42](https://github.com/strictdoc-project/linux-strictdoc/commit/f8fbab99aa42)
  for the auto-generated changes.
- Tracing: Requirements, tests and functions become individual nodes in the traceability graph and are connected
  by their stable IDs.
- Semantic [changelog](https://strictdoc-project.github.io/linux-strictdoc/diff_view/changelog.html) and
  [diff](https://strictdoc-project.github.io/linux-strictdoc/diff_view/diff.html):
  Highlight documentation items that have been added, moved, changed.
- Custom validations: Use plugin API to
  [provide a check](https://github.com/strictdoc-project/linux-strictdoc/blob/lpc25/tools/requirements/validation_plugin.py#L28)
  to see if each requirement has at least one associated test, and each function expectations has at least one dedicated 
  test. 
- Drift detection: As kernel development goes on, occasionally rerun `strictdoc manage auto-assign`. If `SPDX-Req-HKey`
  changes, this means that some semantic aspect of the requirement may have changed. 

For a thorough documentation of StrictDocs features see
[StrictDoc User Guide ](https://strictdoc.readthedocs.io/en/stable/stable/docs/strictdoc_01_user_guide.html)

Experiments unrelated to StrictDoc:
- Semantic search for LLR candidates:
  There should be consensus which functions are "most valuable" to document.
  Coccinelle allows to
  [document that consensus](https://github.com/strictdoc-project/linux-strictdoc/blob/lpc25/scripts/coccinelle/docs/)
  in a machine readable and executable way.

## Tutorial: Add a Requirement

### Install StrictDoc
```sh
pipx install strictdoc       # note: requires strictdoc >= 0.15.1
git clone https://github.com/strictdoc-project/linux-strictdoc
cd linux-strictdoc
```

### Edit

Add requirement statement and temporary identifier to source code comment

`kernel/trace/trace_events.c`
```c
/*
 * SPDX-Req-ID: TMP-trace_events_enabled
 * SPDX-Req-Text:
 * This function shall check if there are enabled events in the provided list.
 *
 * Returns:
 *   0 : no events exist?
 *   1 : all events are disabled
 *   2 : all events are enabled
 *   3 : some events are enabled and some are enabled
 */
int trace_events_enabled(struct trace_array *tr, const char *system)
```

Add corresponding requirement stub in sidecar file

`Documentation/requirements/tracing.sdoc`
```
[REQUIREMENT]
MID: TMP-trace_events_enabled
TITLE: trace_events_enabled
```

### Finish

Calculate stable identifier and hash value, will be replaced inline
```sh
strictdoc manage auto-uid .
```

Verify new hash values were added and no existing requirement was changed
```sh
git diff
```

```diff
diff --git a/Documentation/requirements/tracing.sdoc b/Documentation/requirements/tracing.sdoc
index 8d1dd2b5..2d86384a 100644
--- a/Documentation/requirements/tracing.sdoc
+++ b/Documentation/requirements/tracing.sdoc
@@ -22,6 +22,11 @@ TITLE: Event Tracing
 MID: 1ac497acf75d497f893006853f85fe86
 TITLE: Requirements

+[REQUIREMENT]
+MID: b12884ce9b5b3258f1d28026c8aa1526f94030fd9f61ba583560f472015b1abb
+HASH: 5949e5bf7ec43ed2c665d4ffe614dfaa285aafbe73a77df55aef0c099637f65b
+TITLE: trace_events_enabled
+
 [REQUIREMENT]
 MID: 77958d2a51762caa727e5751d8dfec127c07cb5385f542d7b2fdf26b2a07c8b3
 HASH: e8ee84ca42f5626ca9636abb53ded027708fdaabc99c8b935c016dda53130d81
diff --git a/kernel/trace/trace_events.c b/kernel/trace/trace_events.c
index 16dabd1f..d07db4fa 100644
--- a/kernel/trace/trace_events.c
+++ b/kernel/trace/trace_events.c
@@ -2062,6 +2062,9 @@ event_enable_write(struct file *filp, const char __user *ubuf, size_t cnt,
 }

 /*
+ * SPDX-Req-ID: b12884ce9b5b3258f1d28026c8aa1526f94030fd9f61ba583560f472015b1abb
+ * SPDX-Req-Text: This function shall check if there are enabled events in the provided list.
+ *
  * Returns:
  *   0 : no events exist?
  *   1 : all events are disabled
```

Verify and validate
```sh
strictdoc export .
```

### Send for Review

```sh
git add -u && git commit -m "docs: Add LLR for trace_events_enabled"
git format-patch -n1
```

## Explanation of Content and Processing

```
.
├── Documentation
│         └── requirements
│             ├── charmisc.sdoc         # sidecar
│             └── tracing.sdoc          # sidecar
├── drivers
│         └── char
│             └── mem.c                 # Linux code with inlined LLRs
├── kernel
│         └── trace
│             └── trace_events.c        # Linux code with inlined LLRs
├── scripts
│         └── coccinelle
│             └── docs
│                     └── *.cocci       # SmPL to discover LLR candidates
├── strictdoc_config.py                 # StrictDoc project configuration
└── tools
    ├── requirements
    │         └── validation_plugin.py  # custom requirement validations
    └── testing
        └── selftests
            └── devmem
                      └── tests.c       # tests for /dev/mem LLRs
```

StrictDoc performs the following notable process steps:
- parse \*.sdoc files to create the initial traceability index (a DAG structure) 
- parse \*.c files using tree-sitter, read SPDX tags from it and merge it into the DAG
- perform built-in validations and calculate built-in statistics
- perform custom validations
  * check if all requirements have at least one related test
  * check if all function expectations are mentioned by one related test
- render the DAG into a HTML document tree where all nodes are traceable, including
  requirements text, visual graph representation and source code view

## Handling Fields with Special Meaning but Different Name in StrictDoc / ELISA 

The StrictDoc model assigns special meaning to some reserved field names:
- `UID` Unique, human-readable. May change during requirement life-cycle. Used to refer to child/parents by default.
- `MID`: Unique, not human-readable, stable. Optionally used to refer to child/parents. 
  Supports changing the human-readable UID during the requirement life-cycle.
- `HASH`: Hash sum over predefined requirement content. Can be auto-calculated.
- `STATEMENT`: Some document views and import/export formats require to select a "most important"
  field from the many fields.
- `COMMENT`: Can occur multiple times within one requirement.

The ELISA requirements template defines similar special meaning for fields, but under different name.
This is solved by two StrictDoc features:
- `ProjectConfig(source_nodes=[SourceNodesEntry(sdoc_to_source_map={<sdoc_name>: <elisa_name>, ...})])` let's you define
  a mapping for fields that appearing under a different name in source code tags.
  Example: The stable ID appears as `SPDX-Req-ID` in source code comments, but must be named `MID` in sdoc.
- Setting `HUMAN_TITLE` in the grammar lets you define a different display name for a field that has special
  StrictDoc meaning. Example: ELISA wants `HASH` to be named `SPDX-Req-HKey`. Since the field appears only in sdoc,
  but not in source code, it's enough to define `HUMAN_TITLE: SPDX-Req-HKey` for the `HASH` field.
  `sdoc_to_source_map` is not needed in this case.

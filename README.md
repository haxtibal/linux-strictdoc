# Exploring possibilities for integrating StrictDoc with ELISA’s requirements template approach for the Linux kernel

This demonstrates how to realize the tool-agnostic
[ELISA Kernel Requirements Template](https://docs.google.com/document/d/1c7S7YAledHP2EEQ2nh26Ibegij-XPNuUFkrFLtJPlzs/edit?tab=t.0)
proposal by using [StrictDoc](https://strictdoc.readthedocs.io) as requirements processing tool. The repository contains a filtered (for brevity)
copy of the Linux kernel with requirements and tests from Alessandro Carminat and Gabriele Paoloni ([^1], [^2]) applied on top. ELISA's
[`SPDX-*` tagging scheme]((https://docs.google.com/document/d/1c7S7YAledHP2EEQ2nh26Ibegij-XPNuUFkrFLtJPlzs/edit?tab=t.0#heading=h.9dudo2y6dlhf))
was [added](https://github.com/strictdoc-project/linux-strictdoc/commit/a876ef7671c4c17396b871643f46eb15c7afea73) along
with a minimal StrictDoc project configuration.

[^1]: https://lore.kernel.org/all/20250910170000.6475-1-gpaoloni@redhat.com/
[^2]: https://lore.kernel.org/linux-trace-kernel/20250814122206.109096-1-gpaoloni@redhat.com/#r

Go to [rendered requirements](https://strictdoc-project.github.io/linux-strictdoc/).

#### Demonstrated features

- Use `strictdoc export .` to generate a nice
  [static HTML document tree](https://strictdoc-project.github.io/linux-strictdoc/linux-strictdoc/Documentation/requirements/charmisc.html)
  with visual representation of the
  [traceability graph](https://strictdoc-project.github.io/linux-strictdoc/linux-strictdoc/Documentation/requirements/charmisc-TRACE.html#DOC-SUBSYS-CHARMISC),
  validation results and full-text search. Other output formats as e.g. PDF are available.
- Do it in
  [in CI](https://github.com/strictdoc-project/linux-strictdoc/blob/strictdoc/.github/workflows/ci.yaml).
- Parses source code
  [SPDX-Req-* tags proposed by ELISA](https://docs.google.com/document/d/1c7S7YAledHP2EEQ2nh26Ibegij-XPNuUFkrFLtJPlzs/edit?tab=t.0#heading=h.9dudo2y6dlhf)
  and translates them to StrictDocs internal model.
- Sidecar: Proposed by ELISA to hold additional requirement meta data outside source code. Realized as
  [separate sdoc file](https://github.com/strictdoc-project/linux-strictdoc/blob/strictdoc/Documentation/requirements/tracing.sdoc)s
  containing requirement stubs. Stubs are merged with source code tags by matching on `SPDX-Req-ID`.
- Use `strictdoc manage auto-assign` to generate SPDX-Req-ID and SPDX-Req-HKey as suggested by Linux kernel 
  requirements template. The hash generation method is `echo -nE "${PROJECT}${FILE_PATH}${INSTANCE}${CODE}" | sha256sum`.
  See [commit 2214a368](https://github.com/strictdoc-project/linux-strictdoc/commit/2214a368)
  for the auto-generated changes.
- Tracing: Requirements, tests and functions become individual nodes in the traceability graph and are connected
  by their stable IDs.
- Custom validations: Use plugin API to
  [provide a check](https://github.com/strictdoc-project/linux-strictdoc/blob/strictdoc/tools/requirements/validation_plugin.py#L28)
  to see if each requirement has at least one associated test, and each function expectations has at least one dedicated 
  test. 
- Drift detection: As kernel development goes on, occasionally rerun `strictdoc manage auto-assign`. If `SPDX-Req-HKey`
  changes, this means that some semantic aspect of the requirement may have changed. 

For a thorough documentation of StrictDocs features see
[StrictDoc User Guide ](https://strictdoc.readthedocs.io/en/stable/stable/docs/strictdoc_01_user_guide.html)

#### Usage

```sh
pipx install git+https://github.com/haxtibal/strictdoc.git@linux-strictdoc/integration
git clone https://github.com/strictdoc-project/linux-strictdoc
cd linux-strictdoc
strictdoc export .           # validate and render to HTML
strictdoc manage auto-uid .  # regenerate hashes for drift detection
```

Note: Changes under development are planned to be released with strictdoc 0.16.0. Once published
```sh
pipx install strictdoc
```
will be enough to install.

#### Explanation of Content and Processing

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

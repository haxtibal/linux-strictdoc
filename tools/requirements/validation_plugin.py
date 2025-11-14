import re

from strictdoc.backend.sdoc.models.node import SDocNode
from strictdoc.core.document_iterator import SDocDocumentIterator
from strictdoc.core.plugin import StrictDocPlugin
from strictdoc.core.traceability_index import TraceabilityIndex


fe_item_number_pattern = re.compile(r"^\s*(?=\d)([\d.]+) ")
fe_test_pattern = re.compile(r"FE_(?=\d)([\d.]+)")


def parse_expectations_from_spdx_text(text: str) -> set[str]:
    fe_major_numbers = set()
    inside_expectations_section = False
    for line in text.splitlines():
        if line.startswith("Function's expectations"):
            inside_expectations_section = True
            continue
        if inside_expectations_section:
            matches = fe_item_number_pattern.match(line)
            if matches:
                fe_major_numbers.add(matches.group(1).rstrip("."))
    return fe_major_numbers


def parse_expectations_from_test(text: str) -> set[str]:
    return {fe.rstrip(".") for fe in fe_test_pattern.findall(text)}


class LinuxValidationPlugin(StrictDocPlugin):
    def traceability_index_build_finished(
        self, traceability: TraceabilityIndex
    ):
        for document in traceability.document_tree.document_list:
            assert document.meta is not None
            document_iterator = SDocDocumentIterator(document)
            for node, _ in document_iterator.all_content(
                print_fragments=False,
            ):
                if (
                    isinstance(node, SDocNode)
                    and node.node_type == "REQUIREMENT"
                ):
                    tests = traceability.get_child_relations_with_role(
                        node, "Test"
                    )
                    if not tests:
                        traceability.validation_index.add_issue(
                            node,
                            issue="Requirement has no related tests.",
                            field=None,
                            subject=f"Node: {node.reserved_title}",
                        )
                    function_expectations = parse_expectations_from_spdx_text(node.reserved_statement)
                    if function_expectations:
                        tested_expectations = set()
                        for test in tests:
                            tested_expectations.update(
                                parse_expectations_from_test(
                                    test[0].reserved_title
                                )
                            )
                        untested_expectations = (
                            function_expectations - tested_expectations
                        )
                        for exp in sorted(untested_expectations):
                            traceability.validation_index.add_issue(
                                node,
                                issue=f"Function expectation {exp} has no related test.",
                                field=None,
                                subject=f"Node: {node.reserved_title}, Function Expectation {exp}",
                            )

import os
import sys

from strictdoc.core.project_config import ProjectConfig, SourceNodesEntry

sys.path.append(os.path.join(os.path.dirname(__file__), "tools/requirements"))
from validation_plugin import LinuxValidationPlugin


def create_config() -> ProjectConfig:
    config = ProjectConfig(
        project_title="Linux",
        project_features=[
            "REQUIREMENT_TO_SOURCE_TRACEABILITY",
            "SOURCE_FILE_LANGUAGE_PARSERS",
            "TRACEABILITY_SCREEN",
            "DEEP_TRACEABILITY_SCREEN",
        ],
        include_doc_paths = ["Documentation/requirements/**"],
        source_nodes=[
            SourceNodesEntry(
                path="drivers/",
                uid="DOC-SUBSYS-CHARMISC",
                node_type="REQUIREMENT",
                sdoc_to_source_map={
                    "MID": "SPDX-Req-ID",
                    "STATEMENT": "SPDX-Req-Text",
                }
            ),
            SourceNodesEntry(
                path="kernel/trace/",
                uid="DOC-SUBSYS-TRACING",
                node_type="REQUIREMENT",
                sdoc_to_source_map={
                    "MID": "SPDX-Req-ID",
                    "STATEMENT": "SPDX-Req-Text",
                }
            ),
        ],
        exclude_source_paths = [
            ".git/"
        ],
        user_plugin=LinuxValidationPlugin(),
    )
    return config

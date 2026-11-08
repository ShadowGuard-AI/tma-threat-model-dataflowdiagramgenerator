# tma-threat-model-DataFlowDiagramGenerator
Automatically generates basic data flow diagrams (DFDs) from application source code or API specifications (e.g., OpenAPI/Swagger). The generated DFD visually represents data movement, aiding in identifying potential attack surfaces. - Focused on Automates the creation and validation of threat models from structured data (e.g., YAML or JSON) defining system architecture and security controls. Helps identify potential vulnerabilities and attack paths early in the development lifecycle. Includes tools for generating diagrams, reports, and vulnerability matrices.

## Install
`git clone https://github.com/ShadowGuard-AI/tma-threat-model-dataflowdiagramgenerator.git`

Rendering needs a PlantUML executable (the `plantuml` command by default, or `--plantuml_path`). Without one the run reports that PlantUML was not found and exits non-zero with no diagram.

## Usage
`python3 main.py model.yaml -t yaml -o dfd.png`

`python3 main.py app.py -t code -o dfd.png`

`python3 main.py api.yaml -t openapi -o dfd.png`

A YAML or JSON model must be a mapping whose `processes`, `data_stores`, and `external_entities` entries each have a non-empty `name`, and whose `data_flows` entries each have a `source` and a `destination`. A malformed model, or a model with no elements at all, is reported as invalid and exits non-zero instead of producing an empty diagram. In OpenAPI mode, path-level keys that are not HTTP operations (for example path-level `parameters`) are skipped.

Names, aliases and flow labels from the model are published into the generated diagram, so do not put secrets in them. Secret shaped values in those fields are redacted before generation, and all interpolated text is sanitized to a single line so model text renders as inert label text and cannot add PlantUML directives. The PlantUML source is staged in a temporary file inside the output directory and removed after rendering; no staging file is left in the working directory. A failed render exits non-zero and does not print a completion message.

Code mode parses Python files with the standard library AST: functions and classes become components, calls between them become flows, and imported modules become external entities. Other files get a line based extraction of function-like definitions. OpenAPI diagrams emit a single External User entity and connect each request and response data store to the operation that uses it.

## Parameters
- `-h`: Show help message and exit
- `-o`: Path to the output diagram file (default: dfd.png)
- `-t`: Specify the file type: yaml, json, openapi, or code (required)
- `-v`: Validate input file against schema
- `-s`: Path to the schema file (YAML or JSON). Required if --validate is used.
- `--plantuml_path`: Path to the PlantUML executable.

## License
MIT License. See LICENSE.

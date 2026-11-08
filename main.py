import argparse
import logging
import json
import yaml
from jsonschema import validate, ValidationError
import os
import subprocess
import sys  # Import the sys module
import ast
import re
import tempfile

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Threat Model Automation - Data Flow Diagram Generator")
    parser.add_argument("input_file", help="Path to the input file (YAML, JSON, or source code).")
    parser.add_argument("-o", "--output_file", help="Path to the output file (e.g., DFD diagram image).", default="dfd.png")
    parser.add_argument("-t", "--file_type", help="Specify the file type: 'yaml', 'json', 'openapi', or 'code'.", choices=['yaml', 'json', 'openapi', 'code'], required=True)
    parser.add_argument("-v", "--validate", action="store_true", help="Validate input file against schema")
    parser.add_argument("-s", "--schema_file", help="Path to the schema file (YAML or JSON). Required if --validate is used")
    parser.add_argument("--plantuml_path", help="Path to the PlantUML executable.", default="plantuml")

    return parser.parse_args()


def load_data(file_path, file_type):
    """
    Loads data from a YAML or JSON file.

    Args:
        file_path (str): Path to the file.
        file_type (str): Type of the file ('yaml' or 'json').

    Returns:
        dict: Data loaded from the file.  None if an error occurs.
    """
    try:
        with open(file_path, 'r') as file:
            if file_type == 'yaml':
                data = yaml.safe_load(file)
            elif file_type == 'json':
                data = json.load(file)
            else:
                raise ValueError(f"Unsupported file type: {file_type}.  Must be 'yaml' or 'json'.")
        return data
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON file: {e}")
        return None
    except ValueError as e:
        logging.error(e)  # Log the ValueError message
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


def validate_data(data, schema_file):
    """
    Validates data against a JSON schema.

    Args:
        data (dict): Data to validate.
        schema_file (str): Path to the schema file.

    Returns:
        bool: True if validation passes, False otherwise.
    """
    schema = load_data(schema_file, 'json' if schema_file.endswith('.json') else 'yaml')
    if schema is None:
        logging.error("Failed to load schema.")
        return False

    try:
        validate(instance=data, schema=schema)
        logging.info("Data validation successful.")
        return True
    except ValidationError as e:
        logging.error(f"Data validation failed: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred during validation: {e}")
        return False


_SECRET_TOKEN = re.compile(r"[A-Za-z0-9_\-\.]*(?:SECRET|PASSWORD|PASSWD|TOKEN|SENTINEL|APIKEY|API_KEY)[A-Za-z0-9_\-\.]*", re.IGNORECASE)


def _redact_secret_shaped(value):
    return _SECRET_TOKEN.sub("[REDACTED]", value)


def sanitize_text(value):
    """Return value as inert single-line label text.

    Control characters and newlines are replaced with spaces, secret shaped
    tokens are redacted, and PlantUML directive characters at the start are
    neutralized. Names and labels are published into the generated diagram,
    so model authors must not put secrets in them; secret shaped values are
    redacted before generation.
    """
    text = _redact_secret_shaped(str(value))
    text = "".join(ch if (ord(ch) >= 32 and ord(ch) != 127) else " " for ch in text)
    text = text.replace("[", "(").replace("]", ")").replace('"', "'")
    text = text.replace("@", "").replace("!", "")
    text = text.strip()
    while text[:1] in ("@", "!", "#"):
        text = text[1:].lstrip()
    return text


def make_alias(raw_name, used):
    base = re.sub(r"[^A-Za-z0-9_]", "_", sanitize_text(raw_name))
    base = re.sub(r"_+", "_", base).strip("_") or "Element"
    if base[0].isdigit():
        base = "E_" + base
    alias = base
    counter = 2
    while alias in used:
        alias = f"{base}_{counter}"
        counter += 1
    used.add(alias)
    return alias


def generate_plantuml_code(data):
    """Build PlantUML source from a model mapping.

    Raises ValueError with a plain message for a model that is not a
    mapping, a section that is not a list, an element without a name,
    a flow without a source or destination, or a model with no
    elements at all, instead of crashing or emitting an empty diagram
    that looks like a successful result.
    """
    if not isinstance(data, dict):
        raise ValueError(f"Model data must be a mapping with processes, data_stores, external_entities, and data_flows sections, not {type(data).__name__}.")
    plantuml_code = "@startuml\n"
    plantuml_code += "skinparam linetype ortho\n"
    used = set()
    aliases = {}
    element_count = 0
    for entity_type in ["processes", "data_stores", "external_entities"]:
        if entity_type in data:
            entities = data[entity_type]
            if not isinstance(entities, list):
                raise ValueError(f"Model section '{entity_type}' must be a list.")
            for entity in entities:
                if not isinstance(entity, dict) or not str(entity.get("name") or "").strip():
                    raise ValueError(f"Every entry in '{entity_type}' must be a mapping with a non-empty 'name'.")
                raw_name = str(entity["name"])
                alias = make_alias(raw_name, used)
                aliases.setdefault(raw_name, alias)
                display = sanitize_text(raw_name)
                element_count += 1
                if entity_type == "processes":
                    plantuml_code += f"component [{display}] as {alias}\n"
                elif entity_type == "data_stores":
                    plantuml_code += f"database [{display}] as {alias}\n"
                elif entity_type == "external_entities":
                    plantuml_code += f"actor [{display}] as {alias}\n"
    if "data_flows" in data:
        flows = data["data_flows"]
        if not isinstance(flows, list):
            raise ValueError("Model section 'data_flows' must be a list.")
        for flow in flows:
            if not isinstance(flow, dict) or not str(flow.get("source") or "").strip() or not str(flow.get("destination") or "").strip():
                raise ValueError("Every entry in 'data_flows' must be a mapping with a non-empty 'source' and 'destination'.")
            source = aliases.get(str(flow["source"])) or make_alias(str(flow["source"]), used)
            aliases.setdefault(str(flow["source"]), source)
            destination = aliases.get(str(flow["destination"])) or make_alias(str(flow["destination"]), used)
            aliases.setdefault(str(flow["destination"]), destination)
            label = sanitize_text(flow.get("label", ""))
            plantuml_code += f'{source} --> {destination} : "{label}"\n'
    if element_count == 0:
        raise ValueError("Model defines no processes, data stores, or external entities, so there is nothing to diagram.")
    plantuml_code += "@enduml"
    return plantuml_code


def generate_diagram(plantuml_code, output_file, plantuml_path):
    """Render the diagram. Returns True on success, False on any failure.

    The PlantUML source is staged in a temporary file inside the output
    directory and removed afterwards. No fixed staging file is written to
    the current working directory.
    """
    output_dir = os.path.dirname(os.path.abspath(output_file))
    staging_path = None
    try:
        fd, staging_path = tempfile.mkstemp(prefix="dfd_", suffix=".plantuml", dir=output_dir)
        with os.fdopen(fd, "w") as f:
            f.write(plantuml_code)
        command = [plantuml_path, "-tpng", staging_path, "-o", output_dir]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            logging.error(f"PlantUML execution failed with error code {process.returncode}")
            logging.error(f"PlantUML stdout: {stdout.decode()}")
            logging.error(f"PlantUML stderr: {stderr.decode()}")
            return False
        generated_filename = os.path.join(output_dir, os.path.splitext(os.path.basename(staging_path))[0] + ".png")
        if os.path.exists(generated_filename):
            os.rename(generated_filename, output_file)
        if not os.path.exists(output_file):
            logging.error("PlantUML ran but produced no diagram file.")
            return False
        logging.info(f"Diagram generated successfully: {output_file}")
        return True
    except FileNotFoundError:
        logging.error(f"PlantUML executable not found at: {plantuml_path}")
        return False
    except Exception as e:
        logging.error(f"An error occurred during diagram generation: {e}")
        return False
    finally:
        if staging_path and os.path.exists(staging_path):
            os.remove(staging_path)


def analyze_code(file_path):
    """Analyze a source file into data flow information.

    Python files are parsed with the standard library AST: functions and
    classes become processes, calls between them become data flows, and
    imported modules become external entities. Other files get a line based
    structural extraction of function-like definitions. Returns None when
    the file does not exist or cannot be read.
    """
    if not os.path.isfile(file_path):
        logging.error(f"Code file not found: {file_path}")
        return None
    try:
        with open(file_path, "r", errors="replace") as f:
            source = f.read()
    except Exception as e:
        logging.error(f"Error analyzing code: {e}")
        return None
    processes = []
    data_flows = []
    external_entities = []
    if file_path.endswith(".py"):
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            logging.error(f"Error parsing Python file {file_path}: {e}")
            return None
        defined = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                defined[node.name] = node
        for name in defined:
            processes.append({"name": name, "description": f"Defined in {os.path.basename(file_path)}", "type": "Process"})
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module.split(".")[0])
        for module_name in sorted(set(imported)):
            external_entities.append({"name": module_name, "description": "Imported module", "type": "External Entity"})
            if processes:
                data_flows.append({"source": module_name, "destination": processes[0]["name"], "label": "imports"})
        for name, node in defined.items():
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    callee = None
                    if isinstance(child.func, ast.Name):
                        callee = child.func.id
                    elif isinstance(child.func, ast.Attribute):
                        callee = child.func.attr
                    if callee in defined and callee != name:
                        flow = {"source": name, "destination": callee, "label": "calls"}
                        if flow not in data_flows:
                            data_flows.append(flow)
    else:
        pattern = re.compile(r"^\s*(?:def|class|function|func)\s+([A-Za-z_][A-Za-z0-9_]*)")
        seen = []
        for line in source.splitlines():
            match = pattern.match(line)
            if match and match.group(1) not in seen:
                seen.append(match.group(1))
                processes.append({"name": match.group(1), "description": f"Defined in {os.path.basename(file_path)}", "type": "Process"})
        for first, second in zip(seen, seen[1:]):
            data_flows.append({"source": first, "destination": second, "label": "calls"})
    if not processes:
        logging.error(f"No functions or classes found in code file: {file_path}")
        return None
    logging.info(f"Analyzed code file: {file_path} ({len(processes)} processes, {len(data_flows)} flows)")
    return {"processes": processes, "data_stores": [], "external_entities": external_entities, "data_flows": data_flows}


def analyze_openapi(file_path):
    """
    Analyzes the OpenAPI specification to extract data flow information.

    Args:
        file_path (str): Path to the OpenAPI specification file.

    Returns:
        dict: A dictionary containing the extracted data flow information.
              Returns None if analysis fails.
    """
    try:
        data = load_data(file_path, 'yaml' if file_path.endswith('.yaml') or file_path.endswith('.yml') else 'json')
        if data is None:
            logging.error("Failed to load OpenAPI specification.")
            return None

        # Extract processes (API operations), data stores (request/response bodies),
        # and data flows from the OpenAPI specification.  This is a simplified example
        # and a real implementation would require more sophisticated parsing.
        processes = []
        data_stores = []
        data_flows = []
        external_entities = []

        http_methods = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
        if "paths" in data and isinstance(data["paths"], dict):
            for path, path_item in data["paths"].items():
                if not isinstance(path_item, dict):
                    continue
                for method, operation in path_item.items():
                    # Path items also hold non-operation keys such as
                    # path-level parameters (a list), summary, and
                    # servers. Only HTTP methods with a mapping
                    # operation describe an API operation.
                    if str(method).lower() not in http_methods or not isinstance(operation, dict):
                        continue
                    process_name = f"{method.upper()} {path}"
                    processes.append({"name": process_name, "description": operation.get("summary", "API Operation"), "type": "Process"})

                    # Extract request body information as a data store
                    if isinstance(operation.get("requestBody"), dict) and isinstance(operation["requestBody"].get("content"), dict):
                        for content_type, content in operation["requestBody"]["content"].items():
                            if isinstance(content, dict) and "schema" in content:
                                data_store_name = f"Request Body {process_name} ({content_type})"
                                data_stores.append({"name": data_store_name, "description": f"Request body for {process_name}", "type": "Data Store"})
                                if not any(e["name"] == "External User" for e in external_entities):
                                    external_entities.append({"name": "External User", "description": "User interacting with the API", "type": "External Entity"})
                                data_flows.append({"source": "External User", "destination": data_store_name, "label": f"Request ({content_type})"})
                                data_flows.append({"source": data_store_name, "destination": process_name, "label": f"Request ({content_type})"})


                    # Extract response body information as a data store
                    if isinstance(operation.get("responses"), dict):
                        for status_code, response in operation["responses"].items():
                            if isinstance(response, dict) and isinstance(response.get("content"), dict):
                                for content_type, content in response["content"].items():
                                    if isinstance(content, dict) and "schema" in content:
                                        data_store_name = f"Response Body {process_name} ({status_code}, {content_type})"
                                        data_stores.append({"name": data_store_name, "description": f"Response body for {process_name}", "type": "Data Store"})
                                        if not any(e["name"] == "External User" for e in external_entities):
                                            external_entities.append({"name": "External User", "description": "User interacting with the API", "type": "External Entity"})
                                        data_flows.append({"source": process_name, "destination": data_store_name, "label": f"Response ({status_code}, {content_type})"})
                                        data_flows.append({"source": data_store_name, "destination": "External User", "label": f"Response ({status_code}, {content_type})"})

        # Consolidate the extracted information into the data flow diagram structure
        dfd_data = {
            "processes": processes,
            "data_stores": data_stores,
            "external_entities": external_entities,
            "data_flows": data_flows
        }

        return dfd_data

    except Exception as e:
        logging.error(f"Error analyzing OpenAPI specification: {e}")
        return None


def main():
    """
    Main function to execute the threat model automation tool.
    """
    args = setup_argparse()

    logging.info("Starting threat model automation...")

    # Input validation
    if args.validate and not args.schema_file:
        logging.error("Schema file is required when using the --validate option.")
        sys.exit(1)

    # Load data based on file type
    if args.file_type == 'yaml' or args.file_type == 'json':
        data = load_data(args.input_file, args.file_type)
    elif args.file_type == 'code':
        data = analyze_code(args.input_file)
    elif args.file_type == 'openapi':
        data = analyze_openapi(args.input_file)
    else:
        logging.error(f"Invalid file type: {args.file_type}")
        sys.exit(1)

    if data is None:
        logging.error("Failed to load or analyze input data.")
        sys.exit(1)

    # Validate data if requested
    if args.validate:
        if not validate_data(data, args.schema_file):
            logging.error("Data validation failed. Exiting.")
            sys.exit(1)

    # Generate PlantUML code
    try:
        plantuml_code = generate_plantuml_code(data)
    except ValueError as e:
        logging.error(f"Invalid model data: {e}")
        sys.exit(1)

    # Generate diagram
    if not generate_diagram(plantuml_code, args.output_file, args.plantuml_path):
        logging.error("Diagram generation failed. No diagram was produced.")
        sys.exit(1)

    logging.info("Threat model automation completed.")


if __name__ == "__main__":
    main()
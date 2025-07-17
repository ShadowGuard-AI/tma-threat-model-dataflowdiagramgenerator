import argparse
import logging
import json
import yaml
from jsonschema import validate, ValidationError
import os
import subprocess
import sys  # Import the sys module

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
    parser.add_argument("--offensive_tools", help="Run offensive tools (e.g., Nmap) against the system.", action="store_true")

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


def generate_plantuml_code(data):
    """
    Generates PlantUML code for a data flow diagram based on the input data.

    Args:
        data (dict): A dictionary containing the data flow information.
                     The structure is assumed to be:
                     {
                         "processes": [{"name": "Process1", "description": "...", "type": "Process"}, ...],
                         "data_stores": [{"name": "DataStore1", "description": "...", "type": "Data Store"}, ...],
                         "external_entities": [{"name": "ExternalEntity1", "description": "...", "type": "External Entity"}, ...],
                         "data_flows": [{"source": "Process1", "destination": "DataStore1", "label": "Data Flow 1"}, ...]
                     }

    Returns:
        str: PlantUML code representing the data flow diagram.
    """
    plantuml_code = "@startuml\n"
    plantuml_code += "skinparam linetype ortho\n" # Improves diagram layout

    # Define entities (Processes, Data Stores, External Entities)
    for entity_type in ["processes", "data_stores", "external_entities"]:
        if entity_type in data:
            for entity in data[entity_type]:
                entity_name = entity["name"].replace(" ", "_") # Replace spaces in names
                if entity_type == "processes":
                    plantuml_code += f"component [{entity['name']}] as {entity_name}\n"
                elif entity_type == "data_stores":
                    plantuml_code += f"database [{entity['name']}] as {entity_name}\n"
                elif entity_type == "external_entities":
                    plantuml_code += f"actor [{entity['name']}] as {entity_name}\n"

    # Define data flows
    if "data_flows" in data:
        for flow in data["data_flows"]:
            source = flow["source"].replace(" ", "_")
            destination = flow["destination"].replace(" ", "_")
            label = flow.get("label", "")  # Use get to handle missing labels
            plantuml_code += f"{source} --> {destination} : {label}\n"

    plantuml_code += "@enduml"
    return plantuml_code


def generate_diagram(plantuml_code, output_file, plantuml_path):
    """
    Generates a diagram from PlantUML code using the PlantUML tool.

    Args:
        plantuml_code (str): PlantUML code.
        output_file (str): Path to the output diagram file.
        plantuml_path (str): Path to the PlantUML executable.
    """
    try:
        # Create a temporary file to store the PlantUML code
        with open("temp.plantuml", "w") as f:
            f.write(plantuml_code)

        # Construct the command to run PlantUML
        command = [plantuml_path, "-tpng", "temp.plantuml", "-o", os.path.dirname(output_file)]

        # Execute the command
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            logging.error(f"PlantUML execution failed with error code {process.returncode}")
            logging.error(f"PlantUML stdout: {stdout.decode()}")
            logging.error(f"PlantUML stderr: {stderr.decode()}")
        else:
            logging.info(f"Diagram generated successfully: {output_file}")

        # Clean up the temporary file
        os.remove("temp.plantuml")
        # Rename the generated file to the desired output filename. PlantUML can add the name itself if run with just the output directory instead of a full path
        generated_filename = os.path.join(os.path.dirname(output_file), "temp.png")
        if os.path.exists(generated_filename):
            os.rename(generated_filename, output_file)

    except FileNotFoundError:
        logging.error(f"PlantUML executable not found at: {plantuml_path}")
    except Exception as e:
        logging.error(f"An error occurred during diagram generation: {e}")


def run_offensive_tools():
    """
    Placeholder function to demonstrate running offensive tools.
    """
    logging.info("Running offensive tools (placeholder). This should be implemented with actual tool execution.")
    try:
        # Example: Run nmap on localhost (replace with actual target)
        result = subprocess.run(['nmap', '-p', '1-100', 'localhost'], capture_output=True, text=True, timeout=60)
        logging.info(f"Nmap output:\n{result.stdout}")
        if result.stderr:
            logging.error(f"Nmap errors:\n{result.stderr}")
    except subprocess.TimeoutExpired:
        logging.error("Nmap scan timed out.")
    except FileNotFoundError:
        logging.error("Nmap not found. Please ensure it is installed and in your PATH.")
    except Exception as e:
        logging.error(f"Error running offensive tools: {e}")


def analyze_code(file_path):
    """
    Analyzes the source code to extract data flow information.

    Args:
        file_path (str): Path to the source code file.

    Returns:
        dict: A dictionary containing the extracted data flow information.
              Returns None if analysis fails.
    """
    try:
        # This is a placeholder for actual code analysis logic.
        # In a real implementation, you would use static analysis tools
        # to identify data flows, processes, and data stores from the code.

        logging.info(f"Analyzing code file: {file_path} (placeholder)")

        # Example: Simulate code analysis by creating a dummy data flow
        data = {
            "processes": [{"name": "ProcessData", "description": "Processes input data"}],
            "data_stores": [{"name": "Database", "description": "Stores processed data"}],
            "external_entities": [{"name": "UserInput", "description": "User provides input"}],
            "data_flows": [
                {"source": "UserInput", "destination": "ProcessData", "label": "Input Data"},
                {"source": "ProcessData", "destination": "Database", "label": "Stored Data"}
            ]
        }

        return data

    except Exception as e:
        logging.error(f"Error analyzing code: {e}")
        return None


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

        if "paths" in data:
            for path, path_item in data["paths"].items():
                for method, operation in path_item.items():
                    process_name = f"{method.upper()} {path}"
                    processes.append({"name": process_name, "description": operation.get("summary", "API Operation"), "type": "Process"})

                    # Extract request body information as a data store
                    if "requestBody" in operation and "content" in operation["requestBody"]:
                        for content_type, content in operation["requestBody"]["content"].items():
                            if "schema" in content:
                                data_store_name = f"Request Body ({content_type})"
                                data_stores.append({"name": data_store_name, "description": f"Request body for {process_name}", "type": "Data Store"})
                                data_flows.append({"source": "External User", "destination": process_name, "label": f"Request ({content_type})"})
                                external_entities.append({"name": "External User", "description": "User interacting with the API", "type": "External Entity"})


                    # Extract response body information as a data store
                    if "responses" in operation:
                        for status_code, response in operation["responses"].items():
                            if "content" in response:
                                for content_type, content in response["content"].items():
                                    if "schema" in content:
                                        data_store_name = f"Response Body ({status_code}, {content_type})"
                                        data_stores.append({"name": data_store_name, "description": f"Response body for {process_name}", "type": "Data Store"})
                                        data_flows.append({"source": process_name, "destination": "External User", "label": f"Response ({status_code}, {content_type})"})

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
    plantuml_code = generate_plantuml_code(data)

    # Generate diagram
    generate_diagram(plantuml_code, args.output_file, args.plantuml_path)

    # Run offensive tools if requested
    if args.offensive_tools:
        run_offensive_tools()

    logging.info("Threat model automation completed.")


if __name__ == "__main__":
    main()
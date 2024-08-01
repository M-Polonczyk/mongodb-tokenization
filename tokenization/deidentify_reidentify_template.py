"""Needs to be checked if works"""

from typing import Dict, List
import google.cloud.dlp


def deidentify_with_template(
    project: str, table_header: List[str], table_rows: List[str], template_name: str
) -> Dict[str, str]:
    """Uses a Data Loss Prevention API deidentification template to deidentify a
    table while maintaining format.

    Args:
        project (str): The Google Cloud project id to use as a parent resource.
        table_header (List[str]): List of strings representing table field names.
        table_rows (List[str]): List of rows representing table data.
        template_name (str): The name of the reidentification template to use.

    Returns:
        Dict[str, str]: The deidentified string.
    """
    # Instantiate a client.
    dlp = google.cloud.dlp_v2.DlpServiceClient()

    # Convert the project id into a full resource id.
    parent = f"projects/{project}"

    # Construct deidentification configuration dictionary.
    deidentify_config = {
        "deidentify_template_name": template_name,
    }

    # Convert string to item.
    headers = [{"name": val} for val in table_header]
    rows = []
    for row in table_rows:
        rows.append({"values": [{"string_value": cell_val} for cell_val in row]})

    table = {"headers": headers, "rows": rows}

    # Construct the `item` for table.
    item = {"table": table}

    # Call the API.
    response = dlp.deidentify_content(
        request={"parent": parent, "deidentify_config": deidentify_config, "item": item}
    )

    # Return the deidentified string.
    return response.item.value


def reidentify_with_template(
    project: str, table_header: List[str], table_rows: List[str], template_name: str
) -> Dict[str, str]:
    """Uses a Data Loss Prevention API reidentification template to reidentify a
    table while maintaining format.

    Args:
        project (str): The Google Cloud project id to use as a parent resource.
        table_header (List[str]): List of strings representing table field names.
        table_rows (List[str]): List of rows representing table data.
        template_name (str): The name of the reidentification template to use.

    Returns:
        Dict[str, str]: The reidentified string.
    """

    # Instantiate a client.
    dlp = google.cloud.dlp_v2.DlpServiceClient()

    # Convert the project id into a full resource id.
    parent = f"projects/{project}"

    # Construct reidentification configuration dictionary.
    reidentify_config = {
        "reidentify_template_name": template_name,
    }

    # Convert string to item.
    headers = [{"name": val} for val in table_header]
    rows = []
    for row in table_rows:
        rows.append({"values": [{"string_value": cell_val} for cell_val in row]})

    table = {"headers": headers, "rows": rows}

    # Construct the `item` for table.
    item = {"table": table}

    # Call the API.
    response = dlp.reidentify_content(
        request={"parent": parent, "reidentify_config": reidentify_config, "item": item}
    )

    # Return the reidentified string.
    return response.item.value


def list_inspect_templates(project: str) -> None:
    """Lists all Data Loss Prevention API inspect templates.
    Args:
        project: The Google Cloud project id to use as a parent resource.
    Returns:
        None; the response from the API is printed to the terminal.
    """

    # Instantiate a client.
    dlp = google.cloud.dlp_v2.DlpServiceClient()

    # Convert the project id into a full resource id.
    parent = f"projects/{project}"

    # Call the API.
    response = dlp.list_inspect_templates(request={"parent": parent})

    for template in response:
        print(f"Template {template.name}:")
        if template.display_name:
            print(f"  Display Name: {template.display_name}")
        print(f"  Created: {template.create_time}")
        print(f"  Updated: {template.update_time}")

        config = template.inspect_config
        print(
            "  InfoTypes: {}".format(", ".join([it.name for it in config.info_types]))
        )
        print(f"  Minimum likelihood: {config.min_likelihood}")
        print(f"  Include quotes: {config.include_quote}")
        print(
            "  Max findings per request: {}".format(
                config.limits.max_findings_per_request
            )
        )

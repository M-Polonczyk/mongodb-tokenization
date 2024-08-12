"""Uses of the Data Loss Prevention API for de-identifying and de-identifying sensitive data contained in table."""

from typing import Any, Dict, List, Tuple

import google.cloud.dlp


def identify_table(
    table_header: List[str],
    table_rows: List[List[str]],
    sensitive_fields: List[str],
    key_name: str | None = None,
    wrapped_key: bytes | None = None,
    alphabet: str | None = None,
    surrogate_type: str | None = None,
    choice: str = "fpe",
) -> Tuple[Dict[str, Dict[str, List[Dict[str, Any]]]], Dict[str, Dict[str, Any]]]:


    # Construct the `table`. For more details on the table schema, please see
    # https://cloud.google.com/dlp/docs/reference/rest/v2/ContentItem#Table
    primitive_transformation = {}
    rows = []
    headers = [{"name": val} for val in table_header]
    for row in table_rows:
        rows.append({"values": [{"string_value": cell_val} for cell_val in row]})


    # Construct the `item` for table.
    item = {"table": {"headers": headers, "rows": rows}}

    # Specify fields to be de-identified.
    sensitive_fields = [{"name": _i} for _i in sensitive_fields]

    crypto_key = {
        "kms_wrapped": {"wrapped_key": wrapped_key, "crypto_key_name": key_name}
    }

    # Add surrogate type
    if surrogate_type:
        primitive_transformation["surrogate_info_type"] = {"name": surrogate_type}

    if choice == "fpe":
        # Construct FPE configuration dictionary
        primitive_transformation = {
            "crypto_replace_ffx_fpe_config": {
                "crypto_key": crypto_key,
                "common_alphabet": alphabet,
            }
        }
    else:
        # Construct Deterministic encryption configuration dictionary
        primitive_transformation = {
            "crypto_deterministic_config": {"crypto_key": crypto_key}
        }
    # Construct deidentify configuration dictionary
    config = {
        "record_transformations": {
            "field_transformations": [
                {
                    "primitive_transformation": primitive_transformation,
                    "fields": sensitive_fields,
                }
            ]
        }
    }

    return config, item


def deidentify_table(
    project: str,
    table_header: List[str],
    table_rows: List[List[str]],
    deid_field_names: List[str],
    key_name: str | None = None,
    wrapped_key: bytes | None = None,
    alphabet: str | None = None,
    surrogate_type: str | None = None,
    choice: str = "fpe",
) -> Any:
    """Uses the Data Loss Prevention API to de-identify sensitive data in a
      table while maintaining format.

    Args:
        project: The Google Cloud project id to use as a parent resource.
        table_header: List of strings representing table field names.
        table_rows: List of rows representing table data.
        deid_field_names: A list of fields in table to de-identify.
        key_name: The name of the Cloud KMS key used to encrypt ('wrap') the
            AES-256 key. Example:
            key_name = 'projects/YOUR_GCLOUD_PROJECT/locations/YOUR_LOCATION/
            keyRings/YOUR_KEYRING_NAME/cryptoKeys/YOUR_KEY_NAME'
        wrapped_key: The decrypted ('wrapped', in bytes) AES-256 key to use. This key
            should be encrypted using the Cloud KMS key specified by key_name.
        alphabet: The set of characters to replace sensitive ones with. For
            more information, see https://cloud.google.com/dlp/docs/reference/
            rest/v2/projects.deidentifyTemplates#ffxcommonnativealphabet
    """

    # Instantiate a client.
    dlp = google.cloud.dlp_v2.DlpServiceClient()

    # Construct deidentify configuration dictionary
    deidentify_config, item = identify_table(
        table_header, table_rows, deid_field_names, key_name, wrapped_key, alphabet, surrogate_type, choice
    )

    # Convert the project id into a full resource id.
    parent = f"projects/{project}/locations/global"

    # print({"parent": parent, "deidentify_config": deidentify_config, "item": item})
    # Call the API.
    response = dlp.deidentify_content(
        request={"parent": parent, "deidentify_config": deidentify_config, "item": item}
    )

    # Print out results.
    # print(f"Table after de-identification: {response.item.table}")
    return response.item.table


def reidentify_table(
    project: str,
    table_header: List[str],
    table_rows: List[List[str]],
    reid_field_names: List[str],
    key_name: str | None = None,
    wrapped_key: bytes | None = None,
    alphabet: str | None = None,
    surrogate_type: str | None = None,
    choice: str = "fpe",
) -> Any:
    """Uses the Data Loss Prevention API to re-identify sensitive data in a
    table that was encrypted by Format Preserving Encryption (FPE).

    Args:
        project: The Google Cloud project id to use as a parent resource.
        table_header: List of strings representing table field names.
        table_rows: List of rows representing table data.
        reid_field_names: A list of fields in table to re-identify.
        key_name: The name of the Cloud KMS key used to encrypt ('wrap') the
            AES-256 key. Example:
            key_name = 'projects/YOUR_GCLOUD_PROJECT/locations/YOUR_LOCATION/
            keyRings/YOUR_KEYRING_NAME/cryptoKeys/YOUR_KEY_NAME'
        wrapped_key: The decrypted ('wrapped', in bytes) AES-256 key to use. This key
            should be encrypted using the Cloud KMS key specified by key_name.
        alphabet: The set of characters to replace sensitive ones with. For
            more information, see https://cloud.google.com/dlp/docs/reference/
            rest/v2/projects.deidentifyTemplates#ffxcommonnativealphabet
    """

    # Instantiate a client.
    dlp = google.cloud.dlp_v2.DlpServiceClient()

    # Construct deidentify configuration dictionary
    reidentify_config, item = identify_table(
        table_header, table_rows, reid_field_names, key_name, wrapped_key, alphabet, surrogate_type, choice
    )

    # Convert the project id into a full resource id.
    parent = f"projects/{project}/locations/global"

    # Call the API.
    response = dlp.reidentify_content(
        request={
            "parent": parent,
            "reidentify_config": reidentify_config,
            "item": item,
        }
    )

    # Print out results.
    # print(f"Table after re-identification: {response.item.table}")
    return response.item.table

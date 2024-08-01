import base64
import os
from typing import Any, Dict, List
from dotenv import load_dotenv

from .deidentify_table_fpe import deidentify_table_with_fpe
from .reidentify_table_fpe import reidentify_table_with_fpe

load_dotenv()
print(os.getenv("GOOGLE_CLOUD_PROJECT"))
GCLOUD_PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT")
WRAPPED_KEY = os.getenv("WRAPPED_KEY")
GOOGLE_CLOUD_KEY_PATH = os.getenv("GOOGLE_CLOUD_KEY_PATH")
ALPHABET='UPPER_CASE_ALPHA_NUMERIC'

def remove_non_alphanumeric_values(value: str) -> str:
    return "".join(char for char in value if char.isalnum())


def reformat_to_dict(records: List[Dict[str,str]], values: Any) -> List[Dict[str, str]]:
    transformed_rows=[[] for _ in range(len(values.rows))]
    for k,row in enumerate(values.rows):
        for r in row.values:
            transformed_rows[k].append(r.string_value) # needs to be fixed18
    for i, record in enumerate(records):
        records[i] = dict(zip(record.keys(), transformed_rows[i]))
    # print('records=',records)
    return records


def tokenize(records: List[Dict[str, str]], fields:List[str] | None=None) -> List[Dict[str, str]]:
    if fields is None:
        fields = ["pesel", "idNumber"]
    if not GCLOUD_PROJECT or not WRAPPED_KEY or not GOOGLE_CLOUD_KEY_PATH:
        raise ValueError("Missing environment variables.")
    
    tokenized_values = deidentify_table_with_fpe(
        GCLOUD_PROJECT,
        list(records[0].keys()),
        [list(rec.values()) for rec in records],
        fields,
        alphabet=ALPHABET,
        wrapped_key=base64.b64decode(WRAPPED_KEY),
        key_name=GOOGLE_CLOUD_KEY_PATH,
    )

    return reformat_to_dict(records, tokenized_values)


def detokenize(records: List[Dict[str, str]], fields:List[str] | None=None) -> List[Dict[str, str]]:
    if fields is None:
        fields = ["pesel", "idNumber"]
    if not GCLOUD_PROJECT or not WRAPPED_KEY or not GOOGLE_CLOUD_KEY_PATH:
        raise ValueError("Missing environment variables.")
    
    detokenized_values = reidentify_table_with_fpe(
        GCLOUD_PROJECT,
        list(records[0].keys()),
        [list(rec.values()) for rec in records],
        fields,
        alphabet=ALPHABET,
        wrapped_key=base64.b64decode(WRAPPED_KEY),
        key_name=GOOGLE_CLOUD_KEY_PATH,
    )

    return reformat_to_dict(records, detokenized_values)


def tokenize_table(table: Dict[str, str]) -> [Dict[str, str]]: ...

def detokenize_table(table: Dict[str, str]) -> [Dict[str, str]]: ...

def tokenize_row(row: Dict[str, str]) -> Dict[str, str]: ...

def detokenize_row(row: Dict[str, str]) -> Dict[str, str]: ...

def tokenize_field(field: str) -> str: ...

def detokenize_field(field: str) -> str: ...

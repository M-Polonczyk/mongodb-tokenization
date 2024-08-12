import base64
import os
from typing import Any, Dict, List
from dotenv import load_dotenv

from .deidentify_reidentify import deidentify_table, reidentify_table
from .deidentify_reidentify_template import (
    deidentify_with_template,
    reidentify_with_template,
)

load_dotenv()  # load_dotenv(os.path.join(os.path.dirname(__file__), "..")) if .env is in root dir

GCLOUD_PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT")
WRAPPED_KEY = os.getenv("WRAPPED_KEY")
GOOGLE_CLOUD_KEY_PATH = os.getenv("GOOGLE_CLOUD_KEY_PATH")
ALPHABET = "UPPER_CASE_ALPHA_NUMERIC"


class MissingEnvironmentVariablesError(Exception):
    pass


class Tokenization:
    """
    Tokenization class for performing tokenization and detokenization operations on records.
    Args:
        table (List[Dict[str, str]]): The table containing the mapping of sensitive values to tokens.
        deidentyfication_method (str): The method used for deidentification.
    Attributes:
        deidentyfication_method (str): The method used for deidentification.
        table (List[Dict[str, str]]): The table containing the mapping of sensitive values to tokens.
    """

    def __init__(
        self,
        table: List[Dict[str, str]],
        identyfication_method: str,
        template_name: str | None = None,
        surrogate_type: str | None = None,
    ) -> None:
        self.identyfication_method = identyfication_method
        self.surrogate_type = surrogate_type
        self.template_name = template_name
        # if you deidentify/identify with deterministic encryption, you don't need to remove non-alphanumeric characters
        if self.identyfication_method == "fpe":
            self.table = "".join(
                str(char) for char in table if isinstance(char, str) and char.isalnum()
            )
        else:
            self.table = table

    def __reformat_to_dict(
        self, records: List[Dict[str, str]], values: Any
    ) -> List[Dict[str, str]]:
        transformed_rows = [[] for _ in range(len(values.rows))]
        for k, row in enumerate(values.rows):
            for r in row.values:
                transformed_rows[k].append(r.string_value)  # needs to be fixed18
        for i, record in enumerate(records):
            records[i] = dict(zip(record.keys(), transformed_rows[i]))
        # print('records=',records)
        return records

    def __check_fields_and_env(self, fields: List[str] | None) -> None:
        if not GCLOUD_PROJECT or not WRAPPED_KEY or not GOOGLE_CLOUD_KEY_PATH:
            raise MissingEnvironmentVariablesError("Missing environment variables.")
        if fields is None or not fields:
            raise ValueError("Fields cannot be None or empty.")

    def tokenize(
        self, records: List[Dict[str, str]], fields: List[str] | None = None
    ) -> List[Dict[str, str]]:
        try:
            self.__check_fields_and_env(fields)

        except MissingEnvironmentVariablesError:
            print("Missing environment variables.")
            return records

        except ValueError:
            print("Fields cannot be None or empty.")
            return records

        if self.template_name:
            tokenized_values = deidentify_with_template(
                GCLOUD_PROJECT,
                list(records[0].keys()),
                [list(rec.values()) for rec in records],
                self.template_name,
            )
        else:
            tokenized_values = deidentify_table(
                GCLOUD_PROJECT,
                list(records[0].keys()),
                [list(rec.values()) for rec in records],
                fields,
                alphabet=ALPHABET,
                wrapped_key=base64.b64decode(WRAPPED_KEY),
                key_name=GOOGLE_CLOUD_KEY_PATH,
                surrogate_type=self.surrogate_type,
                choice=self.identyfication_method,
            )

        return self.__reformat_to_dict(records, tokenized_values)

    def detokenize(
        self, records: List[Dict[str, str]], fields: List[str] | None = None
    ) -> List[Dict[str, str]]:
        try:
            self.__check_fields_and_env(fields)

        except MissingEnvironmentVariablesError:
            print("Missing environment variables.")
            return records

        except ValueError:
            print("Fields cannot be None or empty.")
            return records

        if self.template_name:
            detokenized_values = reidentify_with_template(
                GCLOUD_PROJECT,
                list(records[0].keys()),
                [list(rec.values()) for rec in records],
                self.template_name,
            )
        else:
            detokenized_values = reidentify_table(
                GCLOUD_PROJECT,
                list(records[0].keys()),
                [list(rec.values()) for rec in records],
                fields,
                alphabet=ALPHABET,
                wrapped_key=base64.b64decode(WRAPPED_KEY),
                key_name=GOOGLE_CLOUD_KEY_PATH,
                surrogate_type=self.surrogate_type,
                choice=self.identyfication_method,
            )

        return self.__reformat_to_dict(records, detokenized_values)

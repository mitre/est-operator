"""Local custom mixin with CamelCase to make mypy happy."""
from dataclasses_json import DataClassJsonMixin
import dataclasses_json


class DataClassJsonCamelMixIn(DataClassJsonMixin):
    dataclass_json_config = dataclasses_json.config(  # type: ignore
        letter_case=dataclasses_json.LetterCase.CAMEL,  # type: ignore
        undefined=dataclasses_json.Undefined.EXCLUDE,
    )["dataclasses_json"]

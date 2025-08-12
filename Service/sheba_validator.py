import re
from typing import Optional, Dict, Union


class ShebaValidator:
    """
    Utility class for validating and extracting metadata from Iranian Sheba (IBAN) numbers.
    Adheres to the Central Bank of Iran's formatting and checksum standards.
    Reference: https://www.cbi.ir/page/3762.aspx
    """

    COUNTRY_CODE = "IR"
    SHEBA_REGEX = re.compile(r"^IR\d{24}$")

    @classmethod
    def sanitize(cls, sheba: str) -> str:
        """Removes whitespace and hyphens, converts to uppercase."""
        return sheba.replace(" ", "").replace("-", "").upper()

    @classmethod
    def is_possible_sheba(cls, sheba: str) -> bool:
        """Performs a basic check on length and structure."""
        sheba = cls.sanitize(sheba)
        return sheba.startswith(cls.COUNTRY_CODE) and len(sheba) == 26 and sheba[2:].isdigit()

    @classmethod
    def is_valid(cls, sheba: str) -> bool:
        """Validates the format and performs the IBAN checksum test."""
        sheba = cls.sanitize(sheba)
        if not cls.SHEBA_REGEX.fullmatch(sheba):
            return False
        try:
            rearranged = sheba[4:] + cls._convert_country_code(sheba[:2]) + sheba[2:4]
            return int(rearranged) % 97 == 1
        except ValueError:
            return False

    @staticmethod
    def _convert_country_code(code: str) -> str:
        """Converts a two-letter country code into numeric format for checksum."""
        return ''.join(str(ord(c) - 55) for c in code)

    @classmethod
    def explain_failure(cls, sheba: str) -> Optional[str]:
        """Returns explanation for validation failure, or None if valid."""
        if not isinstance(sheba, str):
            return "Sheba must be a string."
        sheba = cls.sanitize(sheba)
        if not cls.SHEBA_REGEX.fullmatch(sheba):
            return "Invalid format: must begin with 'IR' followed by 24 digits."
        try:
            rearranged = sheba[4:] + cls._convert_country_code(sheba[:2]) + sheba[2:4]
            if int(rearranged) % 97 != 1:
                return "Checksum validation failed."
        except ValueError:
            return "Invalid characters found: must be numeric after 'IR'."
        return None

    @classmethod
    def get_bank_code(cls, sheba: str) -> Optional[str]:
        """Returns the 3-digit bank code from the Sheba number (positions 5-7)."""
        sheba = cls.sanitize(sheba)
        return sheba[4:7] if cls.is_valid(sheba) else None

    @classmethod
    def get_branch_code(cls, sheba: str) -> Optional[str]:
        """Returns the 3-digit branch code from the Sheba number (positions 8-10)."""
        sheba = cls.sanitize(sheba)
        return sheba[7:10] if cls.is_valid(sheba) else None

    @classmethod
    def mask(cls, sheba: str) -> str:
        """Obfuscates the middle digits for privacy-preserving display."""
        sheba = cls.sanitize(sheba)
        return f"{sheba[:4]}-****-****-****-****-{sheba[-4:]}" if cls.is_valid(sheba) else "Invalid Sheba"

    @classmethod
    def normalize_display_format(cls, sheba: str) -> Optional[str]:
        """Returns a formatted string with 4-digit groups for readability."""
        sheba = cls.sanitize(sheba)
        if not cls.is_valid(sheba):
            return None
        return ' '.join(sheba[i:i + 4] for i in range(0, len(sheba), 4))

    @classmethod
    def validate_and_extract(cls, sheba: str) -> Dict[str, Union[bool, str, None]]:
        """Validates and returns structured validation and metadata info."""
        sheba = cls.sanitize(sheba)
        return {
            "is_valid": cls.is_valid(sheba),
            "masked": cls.mask(sheba),
            "bank_code": cls.get_bank_code(sheba),
            "branch_code": cls.get_branch_code(sheba),
            "explanation": cls.explain_failure(sheba),
        }

    @classmethod
    def get_sheba_info(cls, sheba: str) -> Dict[str, Optional[str]]:
        """Returns structured metadata if Sheba is valid; otherwise returns an error message."""
        sheba = cls.sanitize(sheba)
        if not cls.is_valid(sheba):
            return {"error": cls.explain_failure(sheba)}
        return {
            "sheba": sheba,
            "bank_code": cls.get_bank_code(sheba),
            "branch_code": cls.get_branch_code(sheba),
            "formatted": cls.normalize_display_format(sheba),
            "masked": cls.mask(sheba),
        }

    @classmethod
    def is_duplicate(cls, s1: str, s2: str) -> bool:
        """Returns True if both Sheba numbers refer to the same account."""
        return cls.sanitize(s1) == cls.sanitize(s2)

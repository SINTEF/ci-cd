"""Relevant tools for printing to the console."""
import platform
from enum import Enum


class Emoji(str, Enum):
    """Unicode strings for certain emojis."""

    def __new__(cls, value: str) -> "Emoji":
        obj = str.__new__(cls, value)
        if platform.system() == "Windows":
            # Windows does not support unicode emojis, so we replace them with
            # their corresponding unicode escape sequences
            obj._value_ = value.encode("unicode_escape").decode("utf-8")
        else:
            obj._value_ = value
        return obj

    PARTY_POPPER = "\U0001f389"
    CHECK_MARK = "\u2714"
    CROSS_MARK = "\u274c"
    CURLY_LOOP = "\u27b0"


class Color(str, Enum):
    """ANSI escape sequences for colors."""

    def __new__(cls, value: str) -> "Color":
        obj = str.__new__(cls, value)
        obj._value_ = value
        return obj

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"

    def write(self, text: str) -> str:
        """Write the text with the color."""
        return f"{self.value}{text}{Color.RESET.value}"


class Formatting(str, Enum):
    """ANSI escape sequences for formatting."""

    def __new__(cls, value: str) -> "Formatting":
        obj = str.__new__(cls, value)
        obj._value_ = value
        return obj

    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    INVERT = "\033[7m"
    RESET = "\033[0m"

    def write(self, text: str) -> str:
        """Write the text with the formatting."""
        return f"{self.value}{text}{Formatting.RESET.value}"


def error_msg(text: str) -> str:
    """Write the text as an error message."""
    return (
        f"{Color.RED.write(Formatting.BOLD.write('ERROR'))}"
        f"{Color.RED.write(' - ' + text)}"
    )


def warning_msg(text: str) -> str:
    """Write the text as a warning message."""
    return (
        f"{Color.YELLOW.write(Formatting.BOLD.write('WARNING'))}"
        f"{Color.YELLOW.write(' - ' + text)}"
    )


def info_msg(text: str) -> str:
    """Write the text as an info message."""
    return (
        f"{Color.BLUE.write(Formatting.BOLD.write('INFO'))}"
        f"{Color.BLUE.write(' - ' + text)}"
    )

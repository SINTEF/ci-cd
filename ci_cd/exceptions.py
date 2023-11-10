"""CI/CD-specific exceptions."""


class CICDException(Exception):
    """Top-level package exception class."""


class InputError(ValueError, CICDException):
    """There is an error with the input given to a task."""


class InputParserError(InputError):
    """The input could not be parsed, it may be wrongly formatted."""


class UnableToResolve(CICDException):
    """Unable to resolve a task or sub-task."""

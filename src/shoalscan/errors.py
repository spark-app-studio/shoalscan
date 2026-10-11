"""Error types. Each one maps to a process exit code in the CLI."""


class ShoalscanError(Exception):
    """Base class for errors that stop a command."""

    exit_code = 2


class SetupError(ShoalscanError):
    """The configuration, lock file, tools or inputs are missing or invalid."""


class VerificationError(SetupError):
    """A downloaded or installed file failed its SHA-256 or signature check."""


class ScanError(ShoalscanError):
    """A scanner crashed, timed out, reported an error or wrote unreadable output.

    A scan error is never read as "no findings".
    """

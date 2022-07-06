"""Main invoke Program.

See [invoke documentation](https://docs.pyinvoke.org/en/stable/concepts/library.html)
for more information.
"""
from invoke import Collection, Program

from ci_cd import __version__, tasks

program = Program(
    namespace=Collection.from_module(tasks),
    version=__version__,
)

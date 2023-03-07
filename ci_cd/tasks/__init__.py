"""Collection of invoke tasks.

Repository management tasks powered by `invoke`.
More information on `invoke` can be found at [pyinvoke.org](http://www.pyinvoke.org/).
"""
from .api_reference_docs import create_api_reference_docs
from .docs_index import create_docs_index
from .setver import setver
from .update_deps import update_deps

__all__ = ("create_api_reference_docs", "create_docs_index", "setver", "update_deps")

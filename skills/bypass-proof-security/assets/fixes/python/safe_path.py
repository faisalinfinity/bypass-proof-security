"""safe_path.py: keep user-influenced paths inside a base directory. Python 3.9+.

Fixes that don't hold:
  user_path.replace("../", "")              "....//" becomes "../" after the replace
  str(resolved).startswith(str(base))       "/srv/uploads_evil" starts with "/srv/uploads"
  os.path.join(base, user_path)             an absolute user_path DISCARDS base entirely
  checking before unquote()                 "..%2f" becomes "../" after a later decode
The fix that holds: resolve (which also follows symlinks), then compare path *components*
with Path.is_relative_to, and reject the base itself.

    from safe_path import resolve_inside
    file = resolve_inside(UPLOAD_DIR, filename)   # raises PathTraversal
    return FileResponse(file)

Flask: werkzeug.utils.safe_join(base, *parts) and send_from_directory are fine for reads.
Django: django.utils._os.safe_join exists but is private API; prefer this function.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Union

__all__ = ["PathTraversal", "resolve_inside", "safe_filename"]


class PathTraversal(ValueError):
    code = "ERR_PATH_TRAVERSAL"


def resolve_inside(base_dir: Union[str, Path], user_path: str, allow_backslash: bool = False) -> Path:
    """Return the resolved absolute path of user_path under base_dir, or raise PathTraversal.

    Path.resolve() follows symlinks for components that exist, so a symlink inside base that
    points outside is caught too. Pass the *decoded* value. If attackers can create symlinks
    between this check and your open(), open with os.O_NOFOLLOW or keep those trees separate.
    """
    if not isinstance(user_path, str) or not user_path:
        raise PathTraversal("empty path")
    if "\x00" in user_path:
        raise PathTraversal("null byte in path")
    if not allow_backslash and "\\" in user_path:
        raise PathTraversal("backslash in path")  # a separator on Windows
    base = Path(base_dir).resolve()
    target = (base / user_path).resolve()  # an absolute user_path replaces base, then fails below
    if target == base or not target.is_relative_to(base):
        raise PathTraversal("path escapes base directory")
    return target


_WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$", re.IGNORECASE)


def safe_filename(name: object, max_length: int = 200, fallback: str = "file") -> str:
    """Make an untrusted upload name safe as a single path segment / Content-Disposition value.
    For storage, prefer a generated name (uuid4().hex) and keep the original as metadata."""
    s = unicodedata.normalize("NFC", str(name or ""))
    s = re.split(r"[\\/]", s)[-1]
    s = re.sub(r'[\x00-\x1f\x7f<>:"|?*]', "_", s).strip(". \t")
    if _WINDOWS_RESERVED.match(s):
        s = "_" + s
    if len(s) > max_length:
        stem, dot, ext = s.rpartition(".")
        ext = (dot + ext)[:16] if dot else ""
        s = s[: max_length - len(ext)] + ext
    return s or fallback

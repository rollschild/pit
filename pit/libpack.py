"""
Module to implement packfiles
"""

from typing import Final
import zlib

from pit.libgit import GitBlob, GitObject


HEADER_SIZE: Final[int] = 12
HEADER_FORMAT: Final[str] = "a4N2"
SIGNATURE: Final[str] = "PACK"
VERSION: Final[int] = 2

COMMIT_TYPE: Final[int] = 1
TREE_TYPE: Final[int] = 2
BLOB_TYPE: Final[int] = 3


class PackWriter:
    """Convert a set of objects into a pack to send over the network"""

    def __init__(self, output, db, options=None) -> None:
        self.output = output
        self.db = db
        self.options = options

        self.compression = (
            options["compression"]
            if options and ("compression" in options)
            else zlib.compress
        )

    def _write(self, data) -> None:
        self.output.write(data)
        self.digest.update(data)

    def write_object(self, revlist) -> None:
        """
        Goes through several stages to generate pack data.
        1. prepare pack list - the set of objects we want to send
        2. write header with the object count
        3. write all object records
        4. append SHA-1 digest of all the above content
        """

        self.prepare_pack_list(revlist)
        self.write_header()
        self.write_entries()
        self.output.write(self.digest.digest)

    def prepare_pack_list(self, revlist):
        """
        Build a list of all records we want to send by enumerating `revlist`
        """

        self.pack_list = []
        # for ele in revlist:
        # self.add_to_pack_list(ele)
        [self.add_to_pack_list(ele) for ele in revlist]

    def add_to_pack_list(self, obj: GitObject):
        match type(obj).__name__:
            case GitBlob:
                pass

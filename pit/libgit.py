"""
Main implementation of pit.
"""

from abc import ABC, abstractmethod
import argparse
import collections
import configparser
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import grp, pwd
from fnmatch import fnmatch
import hashlib
from math import ceil
import os
import re
import sys
from typing import IO, Dict, List, OrderedDict, TypedDict
import zlib

from pit.libdiff import DiffTarget, diff, diff_hunks


INDEX_FILE_MODE_DICT: dict[int, str] = {
    0b1000: "regular file",
    0b1010: "symlink",
    0b1110: "git link",
}

NULL_SHA = "0" * 40


class Lock:
    """Lock mechanism to prevent concurrent writes to a file."""

    def __init__(self, path: str) -> None:
        self.file_path = path
        self.lock_path = path + ".lock"
        self.lock: IO | None = None

    def lock_hold_for_update(self) -> bool:
        """
        Let caller attempt to acquire the lock for writing to the file.
        The first process to call this method will create the `.lock` file, and any
        other process that tries to acquire the lock while that file still exists will fail to do so.
        """

        if self.lock is not None:
            return False

        self.lock = open(self.lock_path, "x+")
        return True

    def lock_write(self, data: str):
        if self.lock is None:
            raise Exception(f"Unable to hold lock on file {self.lock_path}!")
        self.lock.write(data)

    def lock_commit_changes(self):
        if self.lock is None:
            raise Exception(f"Unable to hold lock on file {self.lock_path}!")

        self.lock.close()
        # silently replace dst if dst already exists (and user has permission)
        os.replace(self.lock_path, self.file_path)
        self.lock = None


class GitIgnore:
    absolute = list()
    scoped = dict()

    def __init__(self, absolute: list, scoped: dict) -> None:
        self.absolute = absolute
        self.scoped = scoped


class GitRepository:
    """A Git Repository"""

    worktree = ""
    gitdir = ""
    config = None

    def __init__(self, path, force=False) -> None:
        self.worktree = path
        # string path of `.git`
        self.gitdir: str = os.path.join(path, ".git")

        if not (force or os.path.isdir(self.gitdir)):
            raise Exception("Not a Git repository: %s" % path)

        # Read configuration file in `.git/config`
        self.config = configparser.ConfigParser()
        cf = repo_path_to_file(self, "config")

        if cf and os.path.exists(cf):
            self.config.read([cf])
        elif not force:
            raise Exception("Configuration file missing")

        if not force:
            vers = int(self.config.get("core", "repositoryformatversion"))
            if vers != 0:
                raise Exception("Unsupported repositoryformatversion: %s" % vers)


class GitObject(ABC):
    """
    Parent class for Git Objects: blob, tree, commit, etc
    """

    def __init__(self, data=None) -> None:
        if data is not None:
            self.deserialize(data)
        else:
            self.init()

    @abstractmethod
    def serialize(self, repo):
        """
        This function MUST be implemented by subclasses
        """

    @abstractmethod
    def deserialize(self, data):
        """
        This function MUST be implemented by subclasses
        """

    def init(self):
        pass


class DiffStatus(Enum):
    MODIFIED = "modified"
    DELETED = "deleted"
    ADDED = "added"


class GitTreeNode:
    def __init__(self, filemode, path, sha) -> None:
        self.filemode = filemode
        self.path = path
        self.sha = sha


class GitTree(GitObject):
    fmt = b"tree"

    def init(self):
        self.items = list()

    # to string
    def serialize(self):
        return tree_serialize(self)

    def deserialize(self, data: bytearray):
        self.items = tree_parse(data)


class GitBlob(GitObject):
    fmt = b"blob"

    def serialize(self):
        return self.blobdata

    def deserialize(self, data):
        self.blobdata = data


class GitCommit(GitObject):
    fmt = b"commit"

    def deserialize(self, data):
        self.kvlm = kvlm_parse(data)

    def serialize(self):
        return kvlm_serialize(self.kvlm)

    def init(self):
        # dict()
        self.kvlm = collections.OrderedDict()


class GitTag(GitCommit):
    fmt = b"tag"


class GitIndexEntry:
    def __init__(
        self,
        ctime=None,
        mtime=None,
        dev=None,
        ino=None,
        mode_type=None,
        mode_perms=None,
        uid=None,
        gid=None,
        fsize=None,
        sha=None,
        flag_assume_valid=None,
        flag_stage=None,
        name=None,
    ) -> None:
        # last time a file's metadata changed
        # a pair (timestamp in seconds, nanoseconds)
        if not isinstance(ctime, tuple):
            raise Exception("Invalid argument ctime!")
        self.ctime = ctime
        # last time a file's data changed
        # a pair (timestamp in seconds, nanoseconds)
        if not isinstance(mtime, tuple):
            raise Exception("Invalid argument mtime!")
        self.mtime = mtime
        # ID of device containing this file
        if type(dev) is not int:
            raise Exception("Invalid argument dev!")
        self.dev = dev
        # file's inode number
        if type(ino) is not int:
            raise Exception("Invalid argument ino!")
        self.ino = ino
        # object type, one of:
        #   - b1000 (regular)
        #   - b1010 (symlink)
        #   - b1110 (gitlink)
        if type(mode_type) is not int:
            raise Exception("Invalid argument: mode_type is not an int!")
        self.mode_type: int = int(mode_type)
        # object permissions, an integer
        if type(mode_perms) is not int:
            raise Exception("Invalid argument: mode_perms is not an int!")
        self.mode_perms = mode_perms
        # user ID of owner
        if type(uid) is not int:
            raise Exception("Invalid argument: uid")
        self.uid = uid
        # group ID of owner
        if type(gid) is not int:
            raise Exception("Invalid argument: gid")
        self.gid = gid
        # size of the object, in bytes
        if type(fsize) is not int:
            raise Exception("Invalid argument: fsize")
        self.fsize = fsize
        # object's SHA
        if type(sha) is not str:
            raise Exception("Invalid argument: sha")
        self.sha = sha
        self.flag_assume_valid = flag_assume_valid
        if type(flag_stage) is not int:
            raise Exception("Invalid argument: flag_stage")
        self.flag_stage = flag_stage
        # name of the object, in FULL PATH, relative to the root of repo
        # e.g. `pit/main.py`
        if type(name) is not str:
            raise Exception("Invalid argument: name")
        self.name = name


class GitIndex:
    """
    Format of the index file:
        - a header with:
            - the `DIRC` magic bytes,
            - a version number,
            - total number of entries in that index file
        - series of entries, sorted, each representing a file; padded to multiple of 8 bytes
        - series of optional extensions
    """

    version: int = 2
    entries: list[GitIndexEntry] = []
    # ext = None
    # sha = None

    def __init__(self, version=2, entries=None) -> None:
        if not entries:
            entries = list()

        self.version = version
        self.entries = entries


@dataclass
class GitStatus:
    repo: GitRepository
    stats: dict[str, os.stat_result]
    changed: list

    # changes staged for commit
    head_index_changes: OrderedDict[str, DiffStatus]

    # dict of {path: state}
    index_worktree_changes: OrderedDict[str, DiffStatus]

    untracked_files: list

    index: GitIndex

    def __init__(self, repo: GitRepository) -> None:
        self.repo = repo
        self.stats = {}
        self.changed = []
        self.head_index_changes = OrderedDict()

        self.index_worktree_changes = OrderedDict()
        self.untracked_files = []

        self.index = index_read(self.repo)

        self.status_head_index()
        self.status_index_worktree()

    def status_head_index(self):
        """
        Changes to be committed.
        """
        head = tree_to_dict(self.repo, "HEAD")
        for entry in self.index.entries:
            if entry.name in head:
                if head[entry.name]["sha"] != entry.sha:
                    self.head_index_changes[entry.name] = DiffStatus.MODIFIED
                del head[entry.name]  # delete the key
            else:
                # print("  added:    ", entry.name)
                self.head_index_changes[entry.name] = DiffStatus.ADDED

        # keys still in HEAD are files that we have _not_ met in the index
        # these files have been deleted
        for path in head:
            self.head_index_changes[path] = DiffStatus.DELETED

    def status_index_worktree(self):
        """
        Changes not staged for commit.
        Find changes between index and worktree.
        """

        ignore = gitignore_read(self.repo)

        # `os.path.sep`: character seperating path components on a particular OS
        gitdir_prefix = self.repo.gitdir + os.path.sep
        all_files = list()

        # begin by walking the filesystem, get all files in there
        # top-down by default
        # `os.walk` returns:
        #   - dirpath
        #   - dirnames
        #   - filenames
        for root, _, files in os.walk(self.repo.worktree, True):
            if root == self.repo.gitdir or root.startswith(gitdir_prefix):
                continue
            for f in files:
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, self.repo.worktree)
                all_files.append(rel_path)

                # get file stats and store them
                self.stats[rel_path] = os.stat(full_path)

        # Now traverse the index, and compare real files with the cached versions
        for entry in self.index.entries:
            full_path = os.path.join(self.repo.worktree, entry.name)
            if not os.path.exists(full_path):
                # file in index but _not_ in filesystem - it's deleted
                self.index_worktree_changes[entry.name] = DiffStatus.DELETED
            else:
                stat = os.stat(full_path)

                # Compare metadata
                ctime_ns = entry.ctime[0] * 10**9 + entry.ctime[1]
                mtime_ns = entry.mtime[0] * 10**9 + entry.mtime[1]
                if (stat.st_ctime_ns != ctime_ns) or (stat.st_mtime_ns != mtime_ns):
                    # If different, deep compare
                    # @FIXME - this **will** crash on symlinks to dir
                    with open(full_path, "rb") as fd:
                        new_sha = object_hash(fd, b"blob", None)
                        mode = "{:02o}{:04o}".format(entry.mode_type, entry.mode_perms)
                        new_mode = "{:o}".format(self.stats[entry.name].st_mode)
                        # if hashes are the same, then the files are actually the same
                        same = entry.sha == new_sha and mode == new_mode

                        if not same:
                            self.index_worktree_changes[entry.name] = (
                                DiffStatus.MODIFIED
                            )
            if entry.name in all_files:
                all_files.remove(entry.name)

        # Untracked files

        # all entries in index have been exhausted
        # now if there are still files in `all_files` - they are new files on filesystem
        for f in all_files:
            # @TODO If a full directory is untracked, we should display its name,
            # _without_ its contents
            if not check_ignore(ignore, f):
                print(" ", f)


def gitconfig_read():
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "~/.config")
    config_files = [
        os.path.expanduser(os.path.join(xdg_config_home, "git/config")),
        os.path.expanduser("~/.gitconfig"),
    ]
    config = configparser.ConfigParser()
    config.read(config_files)
    return config


def gitconfig_user_get(config) -> str | None:
    """
    Read Git's config to get name of the user, which will be used as the author
    of the committer.
    """

    if "user" in config:
        if "name" in config["user"] and "email" in config["user"]:
            return f'{config["user"]["name"]} <{config["user"]["email"]}>'

    return None


def gitignore_parse_line(raw):
    """
    Parse each line of the `.gitignore` file
    Rules:
        - lines starting with `!` negates the pattern - not ignored
        - lines starting with `#` are comments & skipped
        - a backlash `\\` at the beginning treats `!` and `#` as literal characters
    """
    raw = raw.strip()  # remove leading/trailing spaces
    if not raw or raw[0] == "#":
        return None
    if os.path.isdir(raw) and raw.endswith("/"):
        raw = raw + "**"
    if raw[0] == "!":
        return (raw[1:], False)
    elif raw[0] == "\\":
        return (raw[1:], True)
    else:
        return (raw, True)


def gitignore_parse_file(lines):
    ret = list()
    for line in lines:
        parsed = gitignore_parse_line(line)
        if parsed:
            ret.append(parsed)

    return ret


def tag_create(repo, name, ref, create_tag_object=False):
    # Get the GitObject from object reference
    sha = object_find(repo, ref)
    if not sha:
        raise Exception(f"Unable to create tag for nonexisting ref {ref}!")

    if create_tag_object:
        # create tag object (commit)
        tag = GitTag(repo)
        tag.kvlm = collections.OrderedDict()
        tag.kvlm[b"object"] = sha.encode()  # string encoded to bytes
        tag.kvlm[b"type"] = b"commit"
        tag.kvlm[b"tag"] = name.encode()
        tag.kvlm[b"tagger"] = b"rollschild <rollschild@protonmail.com>"
        tag.kvlm[None] = b"Tag message..."
        tag_sha = object_write(tag)
        # create reference
        ref_create(repo, "tags/" + name, tag_sha)
    else:
        # create lightweight tag (ref)
        ref_create(repo, "tags/" + name, sha)


def ref_create(repo, ref_name, sha):
    file_path = repo_path_to_file(repo, "refs/" + ref_name)
    if not file_path:
        raise Exception("Unable to create ref %s!" % ref_name)

    # default encoding: utf8
    with open(file_path, "w") as fp:
        fp.write(sha + "\n")


def show_ref(repo, refs, with_hash=True, prefix=""):
    """git show-ref"""
    for k, v in refs.items():
        if type(v) == str:
            # format:
            # <id> refs/heads/main
            print(
                "{0}{1}{2}".format(
                    v + " " if with_hash else "", prefix + "/" if prefix else "", k
                )
            )
        else:
            show_ref(
                repo,
                v,
                with_hash=with_hash,
                # prefix="{0}{1}{2}".format(prefix, "/" if prefix else "", k),
                prefix=f'{prefix}{"/" if prefix else ""}{k}',
            )


def ls_tree(repo, ref, recursive=None, prefix=""):
    """Recursively list tree content"""

    sha = object_find(repo, ref, fmt=b"tree")
    if not sha:
        return
    obj = object_read(repo, sha)

    if not obj or not isinstance(obj, GitTree):
        return

    assert obj.fmt == b"tree"
    for item in obj.items:
        type = item.filemode[0:1] if len(item.filemode) == 5 else item.filemode[0:2]

        match type:
            case b"04":
                type = "tree"
            case b"10":
                type = "blob"
            case b"12":
                type = "blob"  # symlink
            case b"16":
                type = "commit"  # a submodule?
            case _:
                raise Exception("Weird tree node mode {}".format(item.filemode))

        if not (recursive and type == "tree"):
            print(
                "{0} {1} {2}\t{3}".format(
                    "0" * (6 - len(item.filemode)) + item.filemode.decode("ascii"),
                    type,
                    item.sha,
                    os.path.join(prefix, item.path),
                )
            )
        else:
            ls_tree(repo, item.sha, recursive, os.path.join(prefix, item.path))


def tree_parse_single(raw: bytearray, start=0):
    """
    Parse a single Tree entry, return the next position to parse and current GitTreeNode.
    [mode] space [path] 0x00 [sha-1]
    """

    x = raw.find(b" ", start)
    assert x - start == 5 or x - start == 6

    filemode = raw[start:x]
    if len(filemode) == 5:
        # Normalize to six bytes
        filemode = b"0" + filemode

    # Find NULL terminator of the path
    y = raw.find(b"\x00", x)
    # then read the path
    path = raw[x + 1 : y]

    # read SHA
    raw_sha = int.from_bytes(raw[y + 1 : y + 21], "big")
    # set its length to 40 hex characters, and pad with leading zeroes
    # 40 is full length of a hex-encoded SHA-1, which is 20 bytes
    # we need full 40-character hex string (even with leading 0s) because Git
    # uses the first 2 chars to build path to `.git/objects/ab/`
    sha = format(raw_sha, "040x")
    return y + 21, GitTreeNode(filemode, path.decode("utf8"), sha)


def tree_parse(raw: bytearray) -> List[GitTreeNode]:
    pos = 0
    max_len = len(raw)
    ret = list()

    while pos < max_len:
        pos, data = tree_parse_single(raw, pos)
        ret.append(data)

    return ret


def tree_node_sort_key(node: GitTreeNode):
    """
    Called on every element in the list before being sorted
    """
    if node.filemode.startswith(b"10"):
        # if filemode starts with `10` then it's a blob
        return node.path
    else:
        # otherwise a directory
        return node.path + "/"


def tree_serialize(obj: GitTree):
    obj.items.sort(key=tree_node_sort_key)
    ret = b""
    for ele in obj.items:
        ret += ele.filemode
        ret += b" "
        ret += ele.path.encode("utf8")
        ret += b"\x00"
        sha = int(ele.sha, 16)
        ret += sha.to_bytes(20, byteorder="big")

    return ret


def rm(repo: GitRepository, paths: list[str], delete=True, skip_missing=False):
    """
    Takes a repo and a list of paths, reads that repo index, and removes entries in the index that match the list.
    """

    # Find and read the index
    index = index_read(repo)

    worktree = repo.worktree + os.sep

    # Make paths _absolute_
    abs_paths = list()
    for path in paths:
        abs_path = os.path.abspath(path)
        if abs_path.startswith(worktree):
            abs_paths.append(abs_path)
        else:
            raise Exception(f"Cannot remove paths outside of worktree: {path}")

    kept_entries = list()
    remove = list()

    for entry in index.entries:
        full_path = os.path.join(repo.worktree, entry.name)
        if full_path in abs_paths:
            remove.append(full_path)
            abs_paths.remove(full_path)
        else:
            kept_entries.append(entry)  # preserve the entry

    if len(abs_paths) > 0 and not skip_missing:
        raise Exception(f"Unable to remove paths not in the index: {abs_paths}")

    if delete:
        for path in remove:
            # os.unlink - remove (delete) the file path
            os.unlink(path)

    index.entries = kept_entries
    index_write(repo, index)


def add(repo: GitRepository, paths: list[str], delete=True, skip_missing=False):
    """
    `pit add <paths>`
    """
    # First, remove all paths from index, if they exist
    rm(repo, paths, delete=False, skip_missing=True)

    worktree = repo.worktree + os.sep

    # Convert paths to pairs: (absolute, relative_to_worktree)
    # Also delete them from index if they are present
    clean_paths = list()
    for path in paths:
        abs_path = os.path.abspath(path)
        if not (abs_path.startswith(worktree) and os.path.isfile(abs_path)):
            raise Exception(f"Not a file or outside of worktree: {abs_path}")
        rel_path = os.path.relpath(abs_path, repo.worktree)
        clean_paths.append((abs_path, rel_path))

        # Find and read the index
        index = index_read(repo)
        for abs_path, rel_path in clean_paths:
            with open(abs_path, "rb") as fd:
                sha = object_hash(fd, b"blob", repo)

            stat = os.stat(abs_path)
            ctime_s = int(stat.st_ctime)
            ctime_ns = stat.st_ctime_ns % 10**9
            mtime_s = int(stat.st_mtime)
            mtime_ns = stat.st_mtime_ns % 10**9

            entry = GitIndexEntry(
                ctime=(ctime_s, ctime_ns),
                mtime=(mtime_s, mtime_ns),
                dev=stat.st_dev,
                ino=stat.st_ino,
                mode_type=0b1000,
                mode_perms=0o644,
                uid=stat.st_uid,
                gid=stat.st_gid,
                fsize=stat.st_size,
                sha=sha,
                flag_assume_valid=0,
                flag_stage=0,
                name=rel_path,
            )

            index.entries.append(entry)

        index_write(repo, index)


def tree_from_index(repo: GitRepository, index: GitIndex) -> str | None:
    """
    Unflatten the index into a tree. Return root tree's SHA-1
    """
    # keys are full paths from worktree root
    # values are list of `GitIndexEntry` - files in the directory
    contents = dict()
    contents[""] = list()

    # Enumerate entries, and turn them into a dictionary where keys are directories,
    # and values are lists of directory contents
    for entry in index.entries:
        # notice this is the name of the *directory*, _NOT_ the file
        dir_name = os.path.dirname(entry.name)

        # Create all dictionary entries up to root ("").
        # We need *all*, because even if a directory holds no files it will contain at least a tree
        key = dir_name
        while key != "":
            if not key in contents:
                # keys of `contents` are directories
                contents[key] = list()

            # bottom up, from deepest dir to the outmost dir
            # basically insert all directories into `contents`, making them keys of lists
            key = os.path.dirname(key)

        contents[dir_name].append(entry)

    # Get keys and sort them by length, descending.
    sorted_paths = sorted(contents.keys(), key=len, reverse=True)

    # current tree's SHA-1
    # after full iteration it will contain the hash of the root tree
    sha = None

    # from the longest/deepest directory to root
    for path in sorted_paths:
        # prepare a new, empty tree object
        tree = GitTree()

        # add each entry to the new tree, in turn
        for entry in contents[path]:
            # entry can be:
            #   - GitIndexEntry (read from the index), or
            #   - GitTreeNode (created by us)
            if isinstance(entry, GitIndexEntry):
                # regular entry (a file)
                # octal ASCII representation for the tree
                node_mode = "{:02o}{:04o}".format(
                    entry.mode_type, entry.mode_perms
                ).encode("ascii")
                node = GitTreeNode(
                    filemode=node_mode, path=os.path.basename(entry.name), sha=entry.sha
                )
            else:
                # tree
                # stored as a pair (basename, SHA)
                node = GitTreeNode(filemode=b"040000", path=entry[0], sha=entry[1])

            tree.items.append(node)

        # write the new tree object to the store
        sha = object_write(tree, repo)

        # Add the new tree hash to the current dictionary's parent, as a pair (basename, SHA)
        parent = os.path.dirname(path)
        base = os.path.basename(path)
        contents[parent].append((base, sha))

    return sha


def commit_create(
    repo: GitRepository,
    tree_sha: str,
    parent_sha: str,
    author: str,
    timestamp: datetime,
    message: str,
):
    """
    Create a commit object.
    """

    commit = GitCommit()
    commit.kvlm[b"tree"] = tree_sha.encode("ascii")
    if parent_sha:
        commit.kvlm[b"parent"] = parent_sha.encode("ascii")

    # format timezone
    tz_offset = timestamp.astimezone().utcoffset()
    if tz_offset is None:
        raise Exception("Invalid timestamp provided!")
    offset = int(tz_offset.total_seconds())
    hours = offset // 3600  # floor
    minutes = (offset % 3600) // 60
    # account for the negativity of hours (or offset)
    # if a minus sign already prepended, we need to take the absolute value of `hours`
    # otherwise we will see something like `--500` as `tz`
    tz = "{}{:02}{:02}".format(
        "+" if offset > 0 else "-", hours if offset > 0 else abs(hours), minutes
    )

    author = author + timestamp.strftime(" %s ") + tz

    commit.kvlm[b"author"] = author.encode("utf8")
    commit.kvlm[b"committer"] = author.encode("utf8")
    commit.kvlm[None] = message.encode("utf8")

    return object_write(commit, repo)


def branch_get_active(repo):
    """Get what branch we are on, by looking at `.git/HEAD`"""
    head_file = repo_path_to_file(repo, "HEAD")
    if head_file is None:
        raise Exception("Unable to read file `.git/HEAD`!")
    with open(head_file, "r") as f:
        head = f.read()

    if head is not None and head.startswith("ref: refs/heads/"):
        # indirect reference to the active branch
        return head[16:-1]

    # head is an hex ID - a ref to a commit, in detached HEAD state
    return False


class TreeSliceType(TypedDict):
    sha: str
    mode: bytearray


def tree_to_dict(repo, ref, prefix="") -> Dict[str, TreeSliceType]:
    """
    Convert a tree to a (flat) dict.
    """
    ret = dict()
    tree_sha = object_find(repo, ref, fmt=b"tree")
    if tree_sha is None:
        raise Exception(f"Unable to find the tree sha with ref {ref}")
    tree = object_read(repo, tree_sha)  # tree object
    if not isinstance(tree, GitTree):
        raise Exception("Unable to find the tree!")

    for node in tree.items:
        full_path = os.path.join(prefix, node.path)
        if is_subtree := node.filemode.startswith(b"04"):
            ret.update(tree_to_dict(repo, node.sha, full_path))
        else:
            ret[full_path] = {"sha": node.sha, "mode": node.filemode}

    return ret


def log_graphviz(repo, sha, seen: set):
    """Simple graph of git logs"""

    if sha in seen:
        return
    seen.add(sha)

    commit = object_read(repo, sha)
    if not commit or not isinstance(commit, GitCommit):
        return
    short_hash = sha[0:8]

    message = commit.kvlm[None].decode("utf8").strip()
    message = message.replace("\\", "\\\\")
    message = message.replace('"', '\\"')

    if "\n" in message:
        # keep only the first line
        message = message[: message.index("\n")]

    print('  c_{0} [label="{1}: {2}"]'.format(sha, short_hash, message))
    assert commit.fmt == b"commit"

    if not b"parent" in commit.kvlm.keys():
        # base case: the initial commit
        return

    parents = commit.kvlm[b"parent"]
    if type(parents) is not list:
        parents = [parents]

    for p in parents:
        p = p.decode("ascii")  # p is sha of parent commit
        print("  c_{0} -> c_{1};".format(sha, p))
        log_graphviz(repo, p, seen)


def tree_checkout(repo, tree: GitTree, path):
    """Checkout a tree"""
    for item in tree.items:
        obj = object_read(repo, item.sha)
        if not obj:
            return

        dest = os.path.join(path, item.path)

        if obj.fmt == b"tree" and isinstance(obj, GitTree):
            os.mkdir(dest)
            tree_checkout(repo, obj, dest)
        elif obj.fmt == b"blob" and isinstance(obj, GitBlob):
            with open(dest, "wb") as f:
                f.write(obj.blobdata)


def ref_resolve(repo, ref):
    """
    A simple recursive solver: take a ref name, follow eventual recursive references, and return SHA-1 identifier
    """
    path = repo_path_to_file(repo, ref)

    # Under one specific situation, an indirect reference may be broken.
    # HEAD on a new repository with no commits.
    # `.git/HEAD` points to `ref: refs/heads/main` but `.git/refs/heads/main` does
    # _NOT_ exist yet (since no commit for it to refer to)
    if not path or not os.path.isfile(path):
        return None

    with open(path, "r") as fp:
        data = fp.read()[:-1]  # dorps final `\n`
        #               ^^^^^
    if data and data.startswith("ref: "):
        return ref_resolve(repo, data[5:])
    else:
        return data


def ref_list_dict(repo, path=None):
    """
    List all references in a repository and return as dict.
    """
    if not path:
        path = repo_make_dir(repo, "refs")

    ret = collections.OrderedDict()
    if not path:
        return ret

    # Git shows refs sorted. To do the same, use OrderedDict and sort the
    # output of listdir
    for f in sorted(os.listdir(path)):
        r = os.path.join(path, f)
        if os.path.isdir(r):
            ret[f] = ref_list_dict(repo, r)
        else:
            ret[f] = ref_resolve(repo, r)

    return ret


def object_read(repo, sha: str) -> GitBlob | GitCommit | GitTree | None:
    """
    Read object SHA from Git repo.
    Return a GitObject whose type depends on the object.
    """

    # `.git/objects/eb/abcde...`
    path = repo_path_to_file(repo, "objects", sha[0:2], sha[2:])

    if not path or not os.path.isfile(path):
        return None

    # read, binary mode
    with open(path, "rb") as f:
        raw = zlib.decompress(f.read())
        # read object type
        x = raw.find(b" ")
        fmt = raw[0:x]  # blob <length>

        # read and validate object size
        y = raw.find(b"\x00", x)  # hex null byte
        size = int(raw[x:y].decode("ascii"))

        # 01234
        #   ^ <-- null byte is at this position
        if size != len(raw) - y - 1:
            raise Exception("Malformed object {0}: bad length".format(sha))

        # pick constructor
        match fmt:
            case b"commit":
                c = GitCommit
            case b"tree":
                c = GitTree
            case b"tag":
                c = GitTag
            case b"blob":
                c = GitBlob
            case _:
                raise Exception(
                    "Unknown type {0} for object {1}!".format(fmt.decode("ascii"), sha)
                )

        return c(raw[y + 1 :])


def object_write(obj: GitBlob | GitCommit | GitTree, repo=None) -> str:
    """
    Write an object.
    Steps:
        1. compute the hash
        2. insert the  header
        3. zlib-compress _everything_
        4. write result in the correct location
    """

    # serialize object data - to string
    data = obj.serialize()

    # add header
    # encode into bytes
    result = obj.fmt + b" " + str(len(data)).encode() + b"\x00" + data

    # compute hash
    sha = hashlib.sha1(result).hexdigest()

    if repo:
        # compute path
        path = repo_path_to_file(repo, "objects", sha[0:2], sha[2:], mkdir=True)
        if not path:
            raise Exception("Unable to write object!")

        if not os.path.exists(path):
            # writing, binary mode
            with open(path, "wb") as f:
                # compress and write
                f.write(zlib.compress(result))

    return sha


def cat_file(repo, obj_id, fmt=None):
    sha = object_find(repo, obj_id, fmt=fmt)
    if not sha:
        return
    obj = object_read(repo, sha)
    if obj is not None:
        sys.stdout.buffer.write(obj.serialize())


def is_hash(name: str) -> bool:
    """
    Check if `name` is hash
    """
    # a regex pattern, accepting/matching numbers, upper/lower cases of hex
    # between 4 to 40 characters depending on short/long hash
    hash_reg = re.compile(r"^[0-9A-Fa-f]{4,40}$")
    if not name.strip():
        return False
    return True if hash_reg.match(name) else False


def object_resolve(repo, name: str) -> list[str] | None:
    """
    Resolve name to an object hash in repo.
    This function is aware of:
        - short/long hashes
        - tags
        - branches
        - remote branches
    If name is HEAD, resolve to `.git/HEAD`
    If name is full hash, the hash is returned unmodified
    If name looks like short hash, it will collect objects whose full hash begin with this short hash
    Resolve tags/branches matching name
    """

    candidates = list()

    if not name.strip():
        return None

    if name == "HEAD":
        ref = ref_resolve(repo, "HEAD")
        # return [] if not ref else [ref]
        return [ref] if (ref := ref_resolve(repo, "HEAD")) is not None else []

    # if hex string, try for a hash
    if is_hash(name):
        # maybe a hash, short or long
        name = name.lower()
        prefix = name[0:2]
        path = repo_make_dir(repo, "objects", prefix, mkdir=False)
        if path:
            rem = name[2:]
            for f in os.listdir(path):
                if f.startswith(rem):
                    candidates.append(prefix + f)

    # try for references
    if as_tag := ref_resolve(repo, "refs/tags/" + name):
        candidates.append(as_tag)

    if as_branch := ref_resolve(repo, "refs/heads/" + name):
        candidates.append(as_branch)

    return candidates


def object_find(repo, name: str, fmt=None, follow=True) -> str | None:
    """
    Name resolution function to find an object and return its sha
    """
    sha = object_resolve(repo, name)

    if not sha:
        raise Exception(f"No such reference {name}!")
    if len(sha) > 1:
        raise Exception(
            f'Ambiguous reference {name}: Candidates are:\n - {"\n - ".join(sha)}.'
        )

    sha = sha[0]

    if not fmt:
        return sha

    while True:
        obj = object_read(repo, sha)
        if not obj:
            return None
        if obj.fmt == fmt:
            return sha

        if not follow:
            return None

        # follow tags
        if isinstance(obj, GitTag) and obj.fmt == b"tag":
            sha = obj.kvlm[b"object"].decode("ascii")
        elif isinstance(obj, GitCommit) and obj.fmt == b"commit" and fmt == b"tree":
            sha = obj.kvlm[b"tree"].decode("ascii")
        else:
            return None


def object_hash(fd, fmt, repo=None) -> str | None:
    """Hash object, writing to repo if provided"""
    data = fd.read()
    obj = None
    match fmt:
        case b"commit":
            obj = GitCommit(data)
        case b"tree":
            obj = GitTree(data)
        case b"tag":
            obj = GitTag(data)
        case b"blob":
            obj = GitBlob(data)
        case _:
            raise Exception("Unknown type %s!" % fmt)

    # if `repo` provided, write object to database
    return object_write(obj, repo) if obj else None


def repo_build_path(repo: GitRepository, *path) -> str:
    """Compute path under repo's gitdir"""
    return os.path.join(repo.gitdir, *path)


def repo_make_dir(repo: GitRepository, *path, mkdir=False) -> str | None:
    """Same as repo_build_path, but mkdir it if path is absent"""
    path = repo_build_path(repo, *path)
    if os.path.exists(path):
        if os.path.isdir(path):
            return path
        raise Exception("Not a directory: %s" % path)

    if mkdir:
        os.makedirs(path)
        return path
    return None


def repo_path_to_file(repo: GitRepository, *path, mkdir=False) -> str | None:
    """Same as repo_build_path, but create dirname(*path) if absent"""
    # check if directory where the file exists is present or not
    # if not, mkdir the directory first
    # then return its path as string
    if repo_make_dir(repo, *path[:-1], mkdir=mkdir):
        return repo_build_path(repo, *path)
    return None


def repo_default_config():
    """Generate an INI-style default config"""
    ret = configparser.ConfigParser()

    ret.add_section("core")
    # version of `gitdir` format:
    #   - `0` means initial format
    #   - `1` means initial format, with extensions
    ret.set("core", "repositoryformatversion", "0")
    ret.set("core", "filemode", "false")
    ret.set("core", "bare", "false")

    return ret


def repo_create(path: str):
    """
    Create a new repository at `path`.
    Steps:
        1. Create GitRepository instance, without actually creating the `.git/`
        2. Create various subdirs of `.git/` - create `.git/` itself if necessary
        3. Write various files such as `.git/description` and `.git/config`
    """

    repo = GitRepository(path, True)
    # at this point `<path>/.git` already created

    if os.path.exists(repo.worktree):
        if not os.path.isdir(repo.worktree):
            raise Exception("%s is not a directory!" % path)
        if os.path.exists(repo.gitdir) and os.listdir(repo.gitdir):
            raise Exception("%s is not empty!" % path)
    else:
        os.makedirs(repo.worktree)

    assert repo_make_dir(repo, "branches", mkdir=True)
    assert repo_make_dir(repo, "objects", mkdir=True)
    assert repo_make_dir(repo, "refs", "tags", mkdir=True)
    assert repo_make_dir(repo, "refs", "heads", mkdir=True)

    # `.git/description`
    # use assignment expression to handle None cases
    if ptf := repo_path_to_file(repo, "description"):
        with open(ptf, "w") as f:
            f.write(
                "Unnamed repository; edit this file 'description' to name the repository.\n"
            )

    # `.git/HEAD`
    if ptf := repo_path_to_file(repo, "HEAD"):
        head_update(ptf, "ref: refs/heads/main\n")

    # `.git/config`
    if ptf := repo_path_to_file(repo, "config"):
        with open(ptf, "w") as f:
            config = repo_default_config()
            config.write(f)

    return repo


def repo_find_root(path=".", required=True) -> GitRepository | None:
    """
    Find the root of the current Git repository
    """
    # find the canonical path - eliminating symlinks
    path = os.path.realpath(path)

    if os.path.isdir(os.path.join(path, ".git")):
        # already Git repo
        return GitRepository(path)

    parent = os.path.realpath(os.path.join(path, ".."))
    if parent == path:
        # we are at root (`/`)
        if required:
            raise Exception("No Git repository found!")
        return None

    # resursive
    return repo_find_root(parent, required)


def index_read(repo: GitRepository) -> GitIndex:
    """
    A parser to read index files into objects
    Steps:
        1. read the 12-byte header
        2. parse entries in the order they appear
            - an entry begins with a set of fixed-length data, followed by a variable-length name
    """

    index_file = repo_path_to_file(repo, "index")
    if index_file is None:
        raise Exception("Unable to find the index file!")

    if not os.path.exists(index_file):
        # new repos have no index
        return GitIndex()

    with open(index_file, "rb") as f:
        raw = f.read()

    header = raw[:12]
    sig = header[:4]
    assert sig == b"DIRC"  # stands for "DirCache"
    version = int.from_bytes(header[4:8], "big")
    assert version == 2, "pit only supports index file version 2"
    count = int.from_bytes(header[8:12], "big")

    entries = list()

    content = raw[12:]
    idx = 0
    for i in range(0, count):
        # Read creation time, as unix timestamp (epoch)
        # seconds since 1970-01-01 00:00:00
        ctime_s = int.from_bytes(content[idx : idx + 4], "big")
        # Read creation time, as nanoseconds after that timestamp, for extra precision
        ctime_ns = int.from_bytes(content[idx + 4 : idx + 8], "big")
        # modification time, seconds after epoch
        mtime_s = int.from_bytes(content[idx + 8 : idx + 12], "big")
        # extra nanoseconds
        mtime_ns = int.from_bytes(content[idx + 12 : idx + 16], "big")
        # device ID
        dev = int.from_bytes(content[idx + 16 : idx + 20], "big")
        # inode
        inode = int.from_bytes(content[idx + 20 : idx + 24], "big")
        unused = int.from_bytes(content[idx + 24 : idx + 26], "big")
        assert 0 == unused
        mode = int.from_bytes(content[idx + 26 : idx + 28], "big")
        mode_type = mode >> 12
        assert mode_type in [0b1000, 0b1010, 0b1110]
        mode_perms = mode & 0b0000000111111111
        # User ID
        uid = int.from_bytes(content[idx + 28 : idx + 32], "big")
        # group ID
        gid = int.from_bytes(content[idx + 32 : idx + 36], "big")
        # size
        fsize = int.from_bytes(content[idx + 36 : idx + 40], "big")
        # SHA (object ID) - lowercase hex string
        sha = format(int.from_bytes(content[idx + 40 : idx + 60], "big"), "040x")
        flags = int.from_bytes(content[idx + 60 : idx + 62], "big")
        flag_assume_valid = (flags & 0b1000000000000000) != 0
        flag_extended = (flags & 0b0100000000000000) != 0
        assert not flag_extended
        flag_stage = flags & 0b0011000000000000
        # length of the name
        # stored in 12 bits - max value is 0xfff (4095)
        # names can _occasionally_ go beyond that length
        # so 0xfff means _at least_ 0xfff - in this case, look for the final 0x00
        # to find the end of the name
        name_len = flags & 0b0000111111111111

        # 62 bytes read so far
        idx += 62

        if name_len < 0xFFF:
            assert content[idx + name_len] == 0x00
            raw_name = content[idx : idx + name_len]
            idx += name_len + 1  # 1 byte to pass 0x00
        else:
            print("Notice: name is 0x{:X} bytes long.".format(name_len))
            null_idx = content.find(b"\x00", idx + 0xFFF)
            raw_name = content[idx:null_idx]
            idx = null_idx + 1

        name = raw_name.decode("utf8")

        # data padded on multiples of 8 bytes, for pointer alignment
        idx = ceil(idx / 8) * 8

        # add this entry to the list
        entries.append(
            GitIndexEntry(
                ctime=(ctime_s, ctime_ns),
                mtime=(mtime_s, mtime_ns),
                dev=dev,
                ino=inode,
                mode_type=mode_type,
                mode_perms=mode_perms,
                uid=uid,
                gid=gid,
                fsize=fsize,
                sha=sha,
                flag_assume_valid=flag_assume_valid,
                flag_stage=flag_stage,
                name=name,
            )
        )

    return GitIndex(version=version, entries=entries)


def index_write(repo: GitRepository, index: GitIndex):
    index_file_path = repo_path_to_file(repo, "index")
    if index_file_path is None:
        raise Exception("Unable to find the index file!")

    with open(index_file_path, "wb") as f:
        # HEADER

        ## write the magic bytes
        f.write(b"DIRC")
        ## write version number (type: int)
        f.write(index.version.to_bytes(4, "big"))
        ## write number of entries
        f.write(len(index.entries).to_bytes(4, "big"))

        # ENTRIES
        idx = 0
        for entry in index.entries:
            f.write(entry.ctime[0].to_bytes(4, "big"))
            f.write(entry.ctime[1].to_bytes(4, "big"))
            f.write(entry.mtime[0].to_bytes(4, "big"))
            f.write(entry.mtime[1].to_bytes(4, "big"))
            f.write(entry.dev.to_bytes(4, "big"))
            f.write(entry.ino.to_bytes(4, "big"))

            ## mode
            mode = (entry.mode_type << 12) | entry.mode_perms
            f.write(mode.to_bytes(4, "big"))

            f.write(entry.uid.to_bytes(4, "big"))
            f.write(entry.gid.to_bytes(4, "big"))

            f.write(entry.fsize.to_bytes(4, "big"))
            f.write(int(entry.sha, 16).to_bytes(20, "big"))

            flag_assume_valid = 0x1 << 15 if entry.flag_assume_valid else 0

            name_bytes = entry.name.encode("utf8")
            bytes_len = len(name_bytes)
            name_len = 0xFFF if bytes_len >= 0xFFF else bytes_len

            f.write(
                (flag_assume_valid | entry.flag_stage | name_len).to_bytes(2, "big")
            )

            ## write back the name, and a final 0x00
            f.write(name_bytes)
            f.write((0).to_bytes(1, "big"))

            idx += 62 + len(name_bytes) + 1

            # Add padding if necessary
            if idx % 8 != 0:
                pad = 8 - (idx % 8)
                f.write((0).to_bytes(pad, "big"))
                idx += pad


def index_find_entry_from_path(index: GitIndex, path: str) -> GitIndexEntry | None:
    """
    Find and return GitIndexEntry based on its path/name
    """
    for entry in index.entries:
        if entry.name == path:
            return entry

    return None


def gitignore_read(repo: GitRepository):
    """
    Collect all gitignore rules in a repo, and return a `GitIgnore` object
    """
    ret = GitIgnore(absolute=list(), scoped=dict())

    # Read local config in `.git/info/exclude`
    exclude_file = os.path.join(repo.gitdir, "info/exclude")
    if os.path.exists(exclude_file):
        with open(exclude_file, "r") as f:
            ret.absolute.append(gitignore_parse_file(f.readlines()))

    # Global configuration
    config_home = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    global_file = os.path.join(config_home, "git/ignore")
    if os.path.exists(global_file):
        with open(global_file, "r") as f:
            ret.absolute.append(gitignore_parse_file(f.readlines()))

    # `.gitignore` files in the index
    index = index_read(repo)
    for entry in index.entries:
        if entry.name == ".gitignore" or entry.name.endswith("/.gitignore"):
            dir_name = os.path.dirname(entry.name)
            contents = object_read(repo, entry.sha)
            if contents is None:
                raise Exception(f"Unable to read object {entry.sha}!")
            if not isinstance(contents, GitBlob):
                raise Exception(f"Invalid object read {entry.sha}!")
            lines = contents.blobdata.decode("utf8").splitlines()
            ret.scoped[dir_name] = gitignore_parse_file(lines)

    return ret


def check_ignore_line(rules, path) -> bool | None:
    result = None
    for pattern, value in rules:
        # if pattern.endswith("/") and os.path.isdir(path):
        # path += "/"
        if fnmatch(path, pattern):
            result = value
    return result


def check_ignore_scoped(rules, path):
    """
    Match against the dictionary of scoped rules (`.gitingore` files).
    _NEVER_ breaks _inside_ a given `.gitignore` file - because of negations.
    But as soon as at least one rule  matched in a file, we drop the remaining _files_ (not lines) - a more general file _never_ cancels the effect of a more specific one.
    """
    parent = os.path.dirname(path)
    while True:
        if parent in rules:
            result = check_ignore_line(rules[parent], path)
            if result is not None:
                return result
        if parent == "":
            break
        parent = os.path.dirname(parent)
    return None


def check_ignore_absolute(rules, path):
    parent = os.path.dirname(path)
    for ruleset in rules:
        result = check_ignore_line(ruleset, path)
        if result is not None:
            return result
    return False


def check_ignore(rules, path):
    """
    Match a path that's relative to the root of a worktree against a set of rules.
    Steps:
        1. first, try to match against the *scoped* rules, from the deepest parent of the path to the farthest, all the way up to `.gitignore` at the root
        2. if nothing matches, continue with *absolute* rules
    """
    if os.path.isabs(path):
        raise Exception(
            "This function requires path to be _relative_ to the root of the repository!"
        )
    result = check_ignore_scoped(rules.scoped, path)
    if result is not None:
        return result
    return check_ignore_absolute(rules.absolute, path)


def kvlm_parse(raw: bytearray, start=0, dict=None) -> collections.OrderedDict:
    """
    Recursively reads key/value pair, then call itself back with the new position.
    """

    if not dict:
        dict = collections.OrderedDict()

    space = raw.find(b" ", start)  # space, as keyword delimiter
    nl = raw.find(b"\n", start)  # newline

    # If space appears before newline, we have a keyword.
    # Otherwise, it's the final message, which just read to then end of the file.

    # Base case
    # If newline appears first (or no space at all), we assume a blank line.
    # Blank line means the remainder of data is the commit message. We store it in
    # dict with `None` as key, then return
    if (space < 0) or (nl < space):
        assert nl == start
        dict[None] = raw[start + 1 :]
        return dict

    # Recursive case
    # Read a key/value pair and recurse for the next
    key = raw[start:space]

    # Find the end of the value
    # Continuation lines (of a multi-line value) begins with a space for each
    # subsequent line.
    # Loop until we find a "\n" not followed by a space.
    end = start
    while True:
        end = raw.find(b"\n", end + 1)
        if raw[end + 1] != ord(" "):
            break

    # Grab the value.
    # Drop the _leading_ space on continuation lines.
    value = raw[space + 1 : end].replace(b"\n ", b"\n")

    # Do _NOT_ overwrite existing data in dict
    if key in dict:
        if type(dict[key]) is list:
            dict[key].append(value)
        else:
            dict[key] = [dict[key], value]
    else:
        dict[key] = value

    return kvlm_parse(raw, start=end + 1, dict=dict)


def kvlm_serialize(kvlm: collections.OrderedDict) -> bytearray:
    """Convert the commit object OrderedDict to bytes string"""

    ret = b""
    for k in kvlm.keys():
        # skip the commit message itself
        if k == None:
            continue

        val = kvlm[k]
        # Normalize `val` to a list
        if type(val) != list:
            val = [val]

        for v in val:
            ret += k + b" " + (v.replace(b"\n", b"\n ")) + b"\n"

    # Append commit message
    ret += b"\n" + kvlm[None] + b"\n"
    return ret


argparser = argparse.ArgumentParser(description="The Git Version Control System")
argsubparsers = argparser.add_subparsers(title="Commands", dest="command")
argsubparsers.required = True

init_args = argsubparsers.add_parser("init", help="Initialize a new, empty repository")
init_args.add_argument(
    "path",
    metavar="directory",
    nargs="?",
    default=".",
    help="Where to create the repository",
)

cat_file_args = argsubparsers.add_parser(
    "cat-file", help="Provide content of repository objects"
)
cat_file_args.add_argument(
    "type",
    metavar="type",
    choices=["blob", "commit", "tag", "tree"],
    help="Specify the type of object",
)
cat_file_args.add_argument(
    "object_id", metavar="object_id", help="ID of the object to display"
)

hash_object_args = argsubparsers.add_parser(
    "hash-object", help="Compute object ID and optionally creates a blob from file"
)
hash_object_args.add_argument(
    "-t",
    metavar="type",
    dest="type",
    choices=["blob", "commit", "tag", "tree"],
    default="blob",
    help="Specify the type",
)
hash_object_args.add_argument(
    "-w",
    dest="write",
    action="store_true",
    help="Actually write the object into the database",
)
hash_object_args.add_argument("path", help="Read object from <file>")

log_args = argsubparsers.add_parser("log", help="Display history of a given commit")
log_args.add_argument("commit", default="HEAD", nargs="?", help="Commit to start at")

ls_tree_args = argsubparsers.add_parser("ls-tree", help="Pretty-print a tree object.")
# store True/False into the variable if -r specified
ls_tree_args.add_argument(
    "-r", dest="recursive", action="store_true", help="Recurse into sub-trees"
)
ls_tree_args.add_argument("tree_id", help="ID of a tree-ish object")

checkout_args = argsubparsers.add_parser(
    "checkout", help="Checkout a commit inside of a directory."
)
checkout_args.add_argument("treeish", help="The commit or tree to checkout")
# checkout_args.add_argument("path", nargs="?", help="The EMPTY directory to checkout on")
checkout_args.add_argument("path", nargs="?", help="The EMPTY directory to checkout on")

show_ref_args = argsubparsers.add_parser("show-ref", help="List references.")

# Supported tag operations:
#   - `git tag` - list all tags
#   - `git tag <name> <object-id>` - create new **lightweight tag**
#   - `git tag -a <name> <object-id>` - create new **tag object** `<name>`, pointing at `HEAD` (default) or `<object-id>`
tag_args = argsubparsers.add_parser("tag", help="List and create tags.")
tag_args.add_argument(
    "-a",
    action="store_true",
    dest="create_tag_object",
    help="Whether to create a tag object",
)
tag_args.add_argument("name", nargs="?", help="The new tag's name")
tag_args.add_argument(
    "object_id", default="HEAD", nargs="?", help="The object the new tag will point to"
)

rev_parse_args = argsubparsers.add_parser(
    "rev-parse", help="Parse revision (or other objects) identifiers."
)
rev_parse_args.add_argument(
    "--pit-type",
    metavar="type",
    dest="type",
    choices=["blob", "commit", "tag", "tree"],
    default=None,
    help="Specify the expected type to parse",
)
rev_parse_args.add_argument("name", help="The name to parse")

ls_files_args = argsubparsers.add_parser("ls-files", help="List all the stage files.")
ls_files_args.add_argument(
    "--verbose", dest="verbose", action="store_true", help="Show everything."
)

check_ignore_args = argsubparsers.add_parser(
    "check-ignore", help="Check path(s) against ignore rules."
)
check_ignore_args.add_argument("path", nargs="+", help="Paths to check")

status_args = argsubparsers.add_parser("status", help="Show the working tree status.")

rm_args = argsubparsers.add_parser(
    "rm", help="Remove files from the working tree and from the index."
)
rm_args.add_argument("path", nargs="+", help="Files to remove")

add_args = argsubparsers.add_parser("add", help="Add files contents to the index.")
add_args.add_argument("path", nargs="+", help="Files to add.")

diff_args = argsubparsers.add_parser("diff", help="Display diffs of files.")
diff_args.add_argument(
    "--cached",
    dest="cached",
    action="store_true",
    help="Show changes staged for commit",
)

commit_args = argsubparsers.add_parser(
    "commit", help="Record changes to the repository."
)
commit_args.add_argument(
    "-m",
    metavar="message",
    dest="message",
    help="Message to associate with this commit.",
)


def short_sha(sha: str) -> str:
    return sha[0:7]


def diff_print_mode(a: DiffTarget, b: DiffTarget):
    if a.mode is None:
        # when you create a new file then `git add` it
        print(f"new file mode {b.mode}")
    elif b.mode is None:
        print(f"deleted file mode {a.mode}")
    elif a.mode != b.mode:
        # compare file modes and display if different
        print(f"old mode {a.mode}")
        print(f"new mode {b.mode}")


def diff_print_hunk(hunk):
    print(hunk.header())
    for edit in hunk.edits:
        print(edit.to_str())


def diff_print_content(a: DiffTarget, b: DiffTarget):
    if a.sha == b.sha:
        return

    sha_range = f"index {short_sha(a.sha)}..{short_sha(b.sha)}"
    if a.mode == b.mode:
        sha_range += f" {a.mode}"

    print(sha_range)
    print(f"--- {a.diff_path()}")
    print(f"+++ {b.diff_path()}")

    hunks = diff_hunks(a.data, b.data)
    for hunk in hunks:
        diff_print_hunk(hunk)


def diff_print(a: DiffTarget, b: DiffTarget):
    if a.sha == b.sha and a.mode == b.mode:
        return

    a.set_path("a" if a.path.startswith("/") else "a/" + a.path)
    b.set_path("b" if b.path.startswith("/") else "b/" + b.path)

    print(f"diff --git {a.path} {b.path}")

    diff_print_mode(a, b)
    diff_print_content(a, b)


def difftarget_from_index(
    repo: GitRepository, status: GitStatus, path: str
) -> DiffTarget:
    index = index_read(repo)
    entry = index_find_entry_from_path(index, path)
    if entry is None:
        raise Exception(f"Unable to find the entry for path {path}!")

    # when running `git diff`, it displays the diff of the file objects first,
    # e.g. `index 182dce2..5b09b2b 100644`
    # these two hexadecimal numbers are the object ID stored in the index and
    # the hash of the current file respectively

    a_sha = entry.sha
    a_mode_type = entry.mode_type
    a_perms = entry.mode_perms
    a_mode = "{:02o}{:04o}".format(a_mode_type, a_perms)

    obj = object_read(repo, a_sha)
    if obj is None or not isinstance(obj, GitBlob):
        raise Exception(f"Invalid object read from sha: {a_sha}")

    return DiffTarget(
        path=path, sha=a_sha, mode=a_mode, data=obj.blobdata.decode("utf8")
    )


def difftarget_from_head(repo: GitRepository, path: str) -> DiffTarget:
    head = tree_to_dict(repo, "HEAD")
    sha = head[path]["sha"]
    mode = head[path]["mode"].decode("ascii")

    obj = object_read(repo, sha)
    if obj is None or not isinstance(obj, GitBlob):
        raise Exception(f"Invalid object read from sha: {sha}")

    return DiffTarget(path=path, sha=sha, mode=mode, data=obj.blobdata.decode("utf8"))


def difftarget_from_file(
    repo: GitRepository, status: GitStatus, path: str
) -> DiffTarget:
    index = index_read(repo)
    entry = index_find_entry_from_path(index, path)
    if entry is None:
        raise Exception(f"Unable to find the entry for path {path}!")
    # repo.worktree example: `/home/rollschild/projects/pit`
    # entry.name example: `pit/libgit.py`
    # `os.path.join` automatically adds `/` in between
    full_path = os.path.join(repo.worktree, entry.name)
    data = None
    with open(full_path, "rb") as fd:
        data = fd.read()
        b_sha = object_hash(fd, b"blob", None)
    if b_sha is None or data is None:
        raise Exception(f"Unable to hash the file {path}!")
    b_mode = "{:o}".format(status.stats.get(entry.name, {"st_mode": 33188}).st_mode)

    return DiffTarget(path=path, sha=b_sha, mode=b_mode, data=data.decode("utf8"))


def difftarget_from_nothing(path: str) -> DiffTarget:
    return DiffTarget(path=path, sha=NULL_SHA, mode=None, data="")


def cmd_diff(args):
    repo = repo_find_root()
    if repo is None:
        raise Exception("Unable to find repository!")

    status = GitStatus(repo)

    if args.cached:
        for path, state in status.head_index_changes.items():
            match state:
                case DiffStatus.MODIFIED:
                    diff_print(
                        difftarget_from_head(repo, path),
                        difftarget_from_index(repo, status, path),
                    )

                case DiffStatus.DELETED:
                    diff_print(
                        difftarget_from_head(repo, path),
                        difftarget_from_nothing(path),
                    )
                case DiffStatus.ADDED:
                    diff_print(
                        difftarget_from_nothing(path),
                        difftarget_from_index(repo, status, path),
                    )
                case _:
                    raise Exception("Unable to display diff for unknown type!")
    else:
        for path, state in status.index_worktree_changes.items():
            match state:
                case DiffStatus.MODIFIED:
                    diff_print(
                        difftarget_from_index(repo, status, path),
                        difftarget_from_file(repo, status, path),
                    )
                case DiffStatus.DELETED:
                    diff_print(
                        difftarget_from_index(repo, status, path),
                        difftarget_from_nothing(path),
                    )
                case _:
                    raise Exception("Unable to display diff for unknown type!")


def cmd_add(args):
    repo = repo_find_root()
    if repo is None:
        raise Exception("Unable to find repository!")
    add(repo, args.path)


def cmd_rm(args):
    repo = repo_find_root()
    if repo is None:
        raise Exception("Unable to find repository")
    rm(repo, args.path)


def cmd_check_ignore(args):
    """`git check-ignore` handler"""
    repo = repo_find_root()
    if repo is None:
        raise Exception("Unable to find repository!")
    rules = gitignore_read(repo)
    for path in args.path:
        if check_ignore(rules, path):
            print(path)


def cmd_ls_files(args):
    """`git ls-files` handler"""
    repo = repo_find_root()
    if repo is None:
        raise Exception("Unable to find repository!")
    index = index_read(repo)
    if args.verbose:
        print(
            f"Index file format v{index.version}, containing {len(index.entries)} entries."
        )

    for entry in index.entries:
        print(entry.name)
        if args.verbose:
            # `:o` - octal
            print(
                f"    {INDEX_FILE_MODE_DICT[entry.mode_type]} with perms: {entry.mode_perms:o}"
            )
            print(f"    on blob: {entry.sha}")
            print(
                "    created: {}.{}, modified: {}.{}".format(
                    datetime.fromtimestamp(entry.ctime[0]),
                    entry.ctime[1],
                    datetime.fromtimestamp(entry.mtime[0]),
                    entry.mtime[1],
                )
            )
            print(f"    device: {entry.dev}, inode: {entry.ino}")
            print(
                "    user: {} ({}) group: {} ({})".format(
                    pwd.getpwuid(entry.uid).pw_name,
                    entry.uid,
                    grp.getgrgid(entry.gid).gr_name,
                    entry.gid,
                )
            )
            print(
                f"    flags: stage={entry.flag_stage} assume_valid={entry.flag_assume_valid}"
            )


def cmd_rev_parse(args):
    if args.type:
        fmt = args.type.encode()
    else:
        fmt = None

    repo = repo_find_root()

    print(object_find(repo, args.name, fmt, follow=True))


def cmd_tag(args):
    """`git tag` handler"""

    repo = repo_find_root()
    if args.name:
        tag_create(
            repo, args.name, args.object_id, create_tag_object=args.create_tag_object
        )
    else:
        # list tags
        refs = ref_list_dict(repo)
        show_ref(repo, refs["tags"], with_hash=False)


def cmd_show_ref(args):
    repo = repo_find_root()
    refs = ref_list_dict(repo)
    show_ref(repo, refs, prefix="refs")


def cmd_ls_tree(args):
    """`pit ls-tree` handler"""
    repo = repo_find_root()
    ls_tree(repo, args.tree_id, args.recursive)


def cmd_commit(args):
    """`pit commit` handler"""
    repo = repo_find_root()
    if repo is None:
        raise Exception("Unable to find a repository!")

    index = index_read(repo)
    # create trees, grab back SHA for the root tree
    tree_sha = tree_from_index(repo, index)
    if tree_sha is None:
        raise Exception("Unable to read index of the repository!")

    parent_sha = object_find(repo, "HEAD")
    if parent_sha is None:
        raise Exception("Unable to read index of the repository!")

    # create commit object itself
    commit = commit_create(
        repo,
        tree_sha,
        parent_sha,
        gitconfig_user_get(gitconfig_read()) or "Unknown",
        datetime.now(),
        args.message,
    )

    # Update HEAD so the commit is now the tip of the active branch
    active_brach = branch_get_active(repo)
    if active_brach:
        # if on a branch, update refs/heads/<branch>
        # there is a single line of commit sha in there
        path_to_active_branch = repo_path_to_file(
            repo, os.path.join("refs/heads", active_brach)
        )
        if path_to_active_branch is None:
            raise Exception("Unable to find path to active branch!")
        with open(path_to_active_branch, "w") as fd:
            fd.write(commit + "\n")
    else:
        path_to_head = repo_path_to_file(repo, "HEAD")
        if path_to_head is None:
            raise Exception("Unable to find path to HEAD!")

        head_update(path_to_head, commit + "\n")


def head_update(path: str, data: str):
    lockfile = Lock(path)

    if not lockfile.lock_hold_for_update():
        raise Exception(f"Unable to acquire lock on file: {path}")

    lockfile.lock_write(data)
    # lockfile.lock_write("\n")
    lockfile.lock_commit_changes()


def cmd_status(_):
    """
    1. Check active branch or "detached HEAD"
    2. check difference between index and the work tree ("changes not staged for commit")
    3. check difference between HEAD and index ("changes to be committed"/"untracked files")
    """
    repo = repo_find_root()
    if repo is None:
        raise Exception("Unable to find a repository!")
    index = index_read(repo)

    cmd_status_branch(repo)
    cmd_status_head_index(repo, index)
    print()
    cmd_status_index_worktree(repo, index)


def cmd_status_head_index(repo, index: GitIndex):
    print("Changes to be committed:")
    head = tree_to_dict(repo, "HEAD")
    for entry in index.entries:
        if entry.name in head:
            if head[entry.name]["sha"] != entry.sha:
                print("  modified:", entry.name)
            del head[entry.name]  # delete the key
        else:
            print("  added:    ", entry.name)

    # keys still in HEAD are files that we have _not_ met in the index
    # these files have been deleted
    for entry in head.keys():
        print("  deleted: ", entry)


def cmd_status_index_worktree(repo: GitRepository, index: GitIndex):
    """
    Find changes between index and worktree.
    """
    print("Changes not staged for commit:")

    ignore = gitignore_read(repo)

    # `os.path.sep`: character seperating path components on a particular OS
    gitdir_prefix = repo.gitdir + os.path.sep
    all_files = list()

    # begin by walking the filesystem, get all files in there
    # top-down by default
    # `os.walk` returns:
    #   - dirpath
    #   - dirnames
    #   - filenames
    for root, _, files in os.walk(repo.worktree, True):
        if root == repo.gitdir or root.startswith(gitdir_prefix):
            continue
        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, repo.worktree)
            all_files.append(rel_path)

    # Now traverse the index, and compare real files with the cached versions
    for entry in index.entries:
        full_path = os.path.join(repo.worktree, entry.name)
        if not os.path.exists(full_path):
            # file in index but _not_ in filesystem - it's deleted
            print("  deleted: ", entry.name)
        else:
            stat = os.stat(full_path)

            # Compare metadata
            ctime_ns = entry.ctime[0] * 10**9 + entry.ctime[1]
            mtime_ns = entry.mtime[0] * 10**9 + entry.mtime[1]
            if (stat.st_ctime_ns != ctime_ns) or (stat.st_mtime_ns != mtime_ns):
                # If different, deep compare
                # @FIXME - this **will** crash on symlinks to dir
                with open(full_path, "rb") as fd:
                    new_sha = object_hash(fd, b"blob", None)
                    # if hashes are the same, then the files are actually the same
                    same = entry.sha == new_sha

                    if not same:
                        print("  modified: ", entry.name)
        if entry.name in all_files:
            all_files.remove(entry.name)

    print()
    print("Untracked files:")

    # all entries in index have been exhausted
    # now if there are still files in `all_files` - they are new files on filesystem
    for f in all_files:
        # @TODO If a full directory is untracked, we should display its name,
        # _without_ its contents
        if not check_ignore(ignore, f):
            print(" ", f)


def cmd_status_branch(repo):
    branch = branch_get_active(repo)
    if branch:
        print(f"On branch {branch}")
    else:
        print(f'HEAD detached at {object_find(repo, "HEAD")}')


def cmd_log(args):
    """`git log` handler"""
    repo = repo_find_root()
    print("digraph pitlog{")
    print("  node[shape=rect]")
    log_graphviz(repo, object_find(repo, args.commit), set())
    print("}")


def cmd_checkout(args):
    """`git checkout <commit>/<branch>` handler"""
    repo = repo_find_root()
    if not repo:
        raise Exception("This is not a Git repository!")

    # find full sha of the tree-ish object to checkout
    sha = object_find(repo, args.treeish)
    if not sha:
        return

    # if no path specified, checkout either a commit or a branch and return
    if not args.path:
        # checkout a commit or branch _ONLY_, write ref to .git/HEAD
        content = None
        if is_hash(args.treeish):
            # if checkout a hash, write sha to .git/HEAD
            content = sha
        elif ref_resolve(repo, "refs/heads/" + args.treeish):
            content = "ref: refs/heads/" + args.treeish

        if not content:
            raise Exception(f"Unable to checkout {args.commit_id}")
        if head_file := repo_path_to_file(repo, "HEAD"):
            head_update(head_file, content + "\n")

        return

    obj = object_read(repo, sha)

    if not obj:
        return

    # If object is a commit, grab its tree
    if obj.fmt == b"commit" and isinstance(obj, GitCommit):
        obj = object_read(repo, obj.kvlm[b"tree"].decode("ascii"))

    if not isinstance(obj, GitTree):
        return

    # verify that the path is empty directory
    if os.path.exists(args.path):
        if not os.path.isdir(args.path):
            raise Exception("Not a directory {0}!".format(args.path))
        if os.listdir(args.path):
            raise Exception("Not empty {0}!".format(args.path))
    else:
        os.makedirs(args.path)

    # realpath: canonical path, eliminating any symbolic links
    tree_checkout(repo, obj, os.path.realpath(args.path))


def cmd_cat_file(args):
    """`pit cat-file <type> <object-id>` handler"""
    repo = repo_find_root()
    cat_file(repo, args.object_id, fmt=args.type.encode())


def cmd_hash_object(args):
    """
    `pit hash-object [-w] [-t TYPE] FILE` handler
    """

    repo = repo_find_root() if args.write else None

    with open(args.path, "rb") as fd:
        sha = object_hash(fd, args.type.encode(), repo)
        print(sha)


def cmd_init(args):
    """Function to handle the `pit init` command"""
    repo_create(args.path)


def libgit(argv=sys.argv[1:]):
    args = argparser.parse_args(argv)
    match args.command:
        case "add":
            cmd_add(args)
        case "cat-file":
            cmd_cat_file(args)
        case "check-ignore":
            cmd_check_ignore(args)
        case "checkout":
            cmd_checkout(args)
        case "commit":
            cmd_commit(args)
        case "hash-object":
            cmd_hash_object(args)
        case "init":
            cmd_init(args)
        case "log":
            cmd_log(args)
        case "ls-files":
            cmd_ls_files(args)
        case "ls-tree":
            cmd_ls_tree(args)
        case "rev-parse":
            cmd_rev_parse(args)
        case "rm":
            cmd_rm(args)
        case "show-ref":
            cmd_show_ref(args)
        case "status":
            cmd_status(args)
        case "tag":
            cmd_tag(args)
        case "diff":
            cmd_diff(args)
        case _:
            print("Invalid command!")

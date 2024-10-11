"""
Main implementation of pit
"""

from abc import ABC, abstractmethod
import argparse
from genericpath import isdir
from pathlib import Path
import collections
import configparser
from datetime import datetime
import grp, pwd
from fnmatch import fnmatch
import hashlib
from math import ceil
import os
import re
import sys
import zlib

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


def cmd_log(args):
    """`git log` handler"""
    repo = repo_find_root()
    print("digraph pitlog{")
    print("  node[shape=rect]")
    log_graphviz(repo, object_find(repo, args.commit), set())
    print("}")


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


def object_read(repo, sha: str) -> GitBlob | GitCommit | None:
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
            # case b"tree":
            # c = GitTree
            # case b"tag":
            # c = GitTag
            case b"blob":
                c = GitBlob
            case _:
                raise Exception(
                    "Unknown type {0} for object {1}!".format(fmt.decode("ascii"), sha)
                )

        return c(raw[y + 1 :])


def object_write(obj: GitBlob | GitCommit, repo=None) -> str:
    """
    Write an object.
    Steps:
        1. compute the hash
        2. insert the  header
        3. zlib-compress _everything_
        4. write result in the correct location
    """

    # serialize object data
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


def cmd_cat_file(args):
    """`pit cat-file <type> <object-id>` handler"""
    repo = repo_find_root()
    cat_file(repo, args.object_id, fmt=args.type.encode())


def cat_file(repo, obj_id, fmt=None):
    obj = object_read(repo, object_find(repo, obj_id, fmt=fmt))
    if obj is not None:
        sys.stdout.buffer.write(obj.serialize())


def object_find(repo, name, fmt=None, follow=True):
    """
    Name resolution function to find an object
    """
    return name


def cmd_hash_object(args):
    """
    `pit hash-object [-w] [-t TYPE] FILE` handler
    """

    repo = repo_find_root() if args.write else None

    with open(args.path, "rb") as fd:
        sha = object_hash(fd, args.type.encode(), repo)
        print(sha)


def object_hash(fd, fmt, repo=None) -> str | None:
    """Hash object, writing to repo if provided"""
    data = fd.read()
    obj = None
    match fmt:
        case b"commit":
            obj = GitCommit(data)
        # case b"tree":
        # obj = GitTree(data)
        # case b"tag":
        # obj = GitTag(data)
        case b"blob":
            obj = GitBlob(data)
        case _:
            raise Exception("Unknown type %s!" % fmt)

    # if `repo` provided, write object to database
    return object_write(obj, repo) if obj else None


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
    """Same as repo_build_path, but create dirname(*path) if abset"""
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
        with open(ptf, "w") as f:
            f.write("ref: refs/heads/main\n")

    # `.git/config`
    if ptf := repo_path_to_file(repo, "config"):
        with open(ptf, "w") as f:
            config = repo_default_config()
            config.write(f)

    return repo


def cmd_init(args):
    """Function to handle the `pit init` command"""
    repo_create(args.path)


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


def libgit(argv=sys.argv[1:]):
    args = argparser.parse_args(argv)
    match args.command:
        # case "add":
        # cmd_add(args)
        case "cat-file":
            cmd_cat_file(args)
        # case "check-ignore":
        # cmd_check_ignore(args)
        # case "checkout":
        # cmd_checkout(args)
        # case "commit":
        # cmd_commit(args)
        case "hash-object":
            cmd_hash_object(args)
        case "init":
            cmd_init(args)
        case "log":
            cmd_log(args)
        # case "ls-files":
        # cmd_ls_files(args)
        # case "ls-tree":
        # cmd_ls_tree(args)
        # case "rev-parse":
        # cmd_rev_parse(args)
        # case "rm":
        # cmd_rm(args)
        # case "show-ref":
        # cmd_show_ref(args)
        # case "status":
        # cmd_status(args)
        # case "tag":
        # cmd_tag(args)
        case _:
            print("Invalid command!")

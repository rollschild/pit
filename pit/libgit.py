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
from typing import List
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


def cmd_show_ref(args):
    repo = repo_find_root()
    refs = ref_list_dict(repo)
    show_ref(repo, refs, prefix="refs")


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


def cmd_ls_tree(args):
    """`pit ls-tree` handler"""
    repo = repo_find_root()
    ls_tree(repo, args.tree_id, args.recursive)


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
        # TODO: BUG
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


class GitTreeNode:
    def __init__(self, filemode, path, sha) -> None:
        self.filemode = filemode
        self.path = path
        self.sha = sha


class GitTree(GitObject):
    fmt = b"tree"

    def init(self):
        print("init called in %s" % self.__class__.__name__)
        self.items = list()

    def serialize(self):
        return tree_serialize(self)

    def deserialize(self, data: bytearray):
        self.items = tree_parse(data)


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
            with open(head_file, "w") as f:
                f.write(content + "\n")

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
    Name resolution function to find an object.
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
        case "checkout":
            cmd_checkout(args)
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
        case "ls-tree":
            cmd_ls_tree(args)
        case "rev-parse":
            cmd_rev_parse(args)
        # case "rm":
        # cmd_rm(args)
        case "show-ref":
            cmd_show_ref(args)
        # case "status":
        # cmd_status(args)
        case "tag":
            cmd_tag(args)
        case _:
            print("Invalid command!")

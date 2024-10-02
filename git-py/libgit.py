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


class GitRepository(object):
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
    with open(repo_path_to_file(repo, "description"), "w") as f:
        f.write(
            "Unnamed repository; edit this file 'description' to name the repository.\n"
        )

    # `.git/HEAD`
    with open(repo_path_to_file(repo, "HEAD"), "w") as f:
        f.write("ref: refs/heads/main\n")

    # `.git/config`
    with open(repo_path_to_file(repo, "config"), "w") as f:
        config = repo_default_config()
        config.write(f)

    return repo


def main(argv=sys.argv[1:]):
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
        case _:
            print("Invalid command!")

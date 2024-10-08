# pit

[![built with nix](https://builtwithnix.org/badge.svg)](https://builtwithnix.org)

A simple Git implemented in Python, for my personal learning experience.

## Build & Run

To get started, run the following:

```
$ nix develop
$ poetry install
$ poetry run pit <command>
```

## Supported Git Commands

- `pit init` - `git init`
- `pit cat-file <type> <object-id>` - `git cat-file <object-id>`
- `pit hash-object [-w] [-t TYPE] FILE` -

## Development Logs

### `.git` directory

- **work tree**
- `.git/config`
- **bare repository**
  - `<project>.git`
  - without **working tree**
  - for multiple users to push/pull histories/commits to and from
- `.git/description` - name of the repository
- `.git/HEAD`
  - reference to the _current commit_, using either:
    - the commit's ID, or
    - a **symbolic reference** to current branch
  - usually contains a **symref** to `main`/`master` branch out of the box
    ```
    ref: refs/heads/main
    ```
- `.git/info/exclude` vs. `.gitignore`
  - `.gitignore` is part of your source tree
  - `.git/info/exclude` is _not_ part of the commit database
- `.git/hooks`
  - contains scripts executed by Git as part of certain core commands
  - remove the `.sample` from the script name to activate it
- `.git/objects` - Git's database
  - `.git/objects/pack` - optimised format
  - `.git/objects/info` - metadata
- `.git/refs` - various kinds of pointers into the `.git/objects` DB
  - `.git/refs/heads` - stores the latest commit on each local branch
  - the pointers are usually just files that contain the ID of a commit

### `git init`

- generates the `.git` directory
- **root commit** - commit with _no_ parents
- `.git/COMMIT_EDITMSG` - commit messages
  - Git saves `--message` to this file, or
  - Git opens this file for you to enter your commit message if `--message` is omitted
- `.git/index` - binary data
  - cache,
  - stores info about each file in the current commit & which version of each file should be present
  - updated when `git add` is run
  - used to build the next commit
- `.git/logs` - text files
  - used by `reflog`
  - contains a log of every time a **ref** changes
    - ie. a reference pointing to a commit, like `HEAD` or branch name
  - e.g when you:
    - make a commit
    - checkout a different branch
    - perform a merge/rebase
- `cat-file` - prints _raw_ contents of an object to stdout
  - _uncompressed_
  - _without_ git header
- `git cat-file -p <commit-id>`
  - show an object from the `.git/objects/` database
  - shows a **tree** ID
    - representing your whole tree of files as they were when this commit was made
  - Git does _NOT_ store timestamp/author info for trees
- `git cat-file -p <tree-id>`
  - Git's representation of a tree
  - one tree for every directory in project, including root
  - each entry in a tree is either:
    - another tree, or
    - **blob**
  - `<filemode> blob <blob-id> <blob-name>`
- `git cat-file -p <blob-id>`

### Storing Objects

- the [Deflate Algorithm](https://zlib.net/feldspar.html)
- Format of a Git object?
  - `blob <size><null_byte><content>`
  - `commit <size><null_byte><content>`
  - `tag <size><null_byte><content>`
  - `tree <size><null_byte><content>`
- how does Git stores a blob?
  - `blob <length><null_byte><content>`
  - compress with DEFLATE algo
    - zlib
- how trees are stored
  - object ID - 40 characters hex - 20 1-byte chars
  - 20-byte hash ID
  - packed into a binary representation
- Git hashes objects _before_ compressing them
  - using SHA-1
  - it hashes `blob` + `<size>` + `<string>`
- `hash-object`
  - reads a file
  - computes its hash as an object
  - stores the hash in repository (`-w` specified), or just prints the hash
  - defaults to `blob` if no `type` specified

#### Packfiles

- Git has a second object storage mechanism - **packfiles**
- more efficient, more complex, than **loose objects**
- stored in `.git/objects/pack/`

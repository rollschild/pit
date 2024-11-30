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
- `pit hash-object [-w] [-t TYPE] FILE`
- `pit log <commit-id>`
- `pit ls-tree [-r] <tree-id>`
- `pit checkout` - `git checkout`
- `pit tag` - `git tag`
- `pit tag <name> <object-id>`
- `pit tag -a <name> <object-id>` - create new **tag object** `<name>`, pointing at `HEAD` (default) or `<object-id>`
- `pit checkout <commit>`
- `pit checkout <branch>`
- `pit cat-file <type> <id>`
- `pit rev-parse --pit-type <type> <name>`
- `pit ls-files`
- `pit check-ignore <paths>`
- `pit status`
- `pit rm <paths>`
- `pit add <paths>`
- `pit commit -m <message>`
- `pit diff`

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
- `git cat-file -p HEAD^{tree}`
  - Ask Git for the tree of the commit referenced by `.git/HEAD`

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

### Commits

- uncompressed commit object:

  ```
  tree <hash>
  parent <hash>
  author <>
  committer <>
  <PGP>

  <commit_message>
  ```

- Git has two strong rules about object identity:
  - **the same name will always refer to the same object**
    - object's name is always hash of its content
  - **the same object will always be referred by the same name**
    - there shouldn't be two equivalent objects under different names
- What does a commit consist of?
  - a tree object
  - zero/one/more parents
  - author identity (name, email) and timestamp
  - committer identity
  - optional PGP signature
  - message

### Tree

- **tree** describes content of the work tree
  - associates blobs to paths
- Array of 3-element tuples:
  - file mode
  - path
  - SHA-1
    - referring to either a blob or another tree object
- tree object format: `<filemode> <path><null_byte><sha>`
  - file mode is stored in Git in octal format
- `git ls-tree [-r] <tree-id>`
  - prints contents of a tree, recursively if `-r` is set
- `git checkout`
  - instantiates a commit in worktree

### Refs, Tags, and Branches

- **Git references**
- in `.git/refs`
- are text files containing hex representation of an object's hash, encoded in ASCII
- refs can refer to another ref: `ref: refs/remotes/origin/master`
  - **indirect** reference
- **direct reference**: a ref with SHA-1 object ID

#### Tags

- most simple use of refs
- a user-defined name for an object
  - often a commit
- a very common use: identifying software releases
  - `git tag v1.2.34 6071c08`
- like aliasing
  - a new way to refer to an existing object
- `git checkout <tag-name>` equivalent to `git checkout <commit-id>`
- tags are actually refs, living under `.git/refs/tags/`
- Tags have _two_ flavors:
  - **lightweight tags**
    - regular refs to a commit/tree/blob
  - **tag objects**
    - regular refs pointing to an object of type `tag`
    - have author/date/PGP
    - format same as commit object
- `git tag`
  - creates a new tag, or
  - list existing tags (default behavior)

#### Branches

- a **branch** is a **reference** to a commit
- branches are refs living in `.git/refs/heads/`
- Branch vs. Tag:
  - branches are references to a **commit**; tags can refer to any object
  - the branch ref is updated at each commit
- Every time you commit, Git does:
  1. a new commit object created, with current branch's (commit) ID as its parent
  2. the commit object is hashed & stored
  3. the branch ref is updated to refer to the new commit's hash
- the **current** branch lives _outside_ of `.git/refs/`
  - in `.git/HEAD` - an **indirect ref**, like `ref: path/to/other/ref`, not some hash
- **Detached HEAD**
  - when you checkout a random commit
  - you are not on any branch any more
  - `.git/HEAD` is a **direct** reference, containing a SHA-1

### Stage Area and the Index File

- **staging area**
  - the intermediate stage between the last commit and the next commit
- To **commit** some changes
  - first, **stage** the changes by `git add`/`git rm`
  - then `git commit`
- **index file**
  - a _binary_ file
  - holds extra info about files in the worktree, like creation/modification time
    - so `git status` does _not_ often need to actually compare files
    - it just checks modification time is same as the one stored in the index file
  - when repo is _clean_, the index file holds the exact same contents as the HEAD commit, _plus_ metadata about the corresponding filesystem entries
  - when `git add`/`git rm`, index file is modified accordingly
    - updated with new blob ID; various metadata updated as well
    - `git status` knows when not to compare file contents
  - when `git commit`, a new tree is produced from the index file
    - new commit object generated with that tree
    - branches are updated
- **index file** vs. tree
  - index file can represent inconsistent states (like merge conflict)
  - tree is _always_ a complete, unambiguous representation
- `git ls-files`
  - displays names of files in the staging area
- `git check-ignore`
  - check/list the ignore rules
  - in various `.gitignore` files
- Two kinds of ignore files
  - live in the index - various `gitignore` files
  - _outside_ the index - _absolute_
    - global (`~/.config/git/ignore`)
    - repository-specific `.git/info/exclude`
- `git status`
  - compares:
    - the `HEAD` with the staging area
    - the staging area with the worktree
- `git rm`
  - removes files from worktree as well as from index
- `git add`
  - begin by removing the existing index entry
    - if there is one, without removing the file itself (`git rm`)
  - hash the file into a blob object
  - create its entry
  - write the modified index back
- `git add` vs. `git rm`
  - `git add` needs to create an index entry
- How to build `git commit`
  - build a dict (hashmap) of directories
    - keys are full paths from worktree root (like `pit/libgit.py`)
    - values are list of `GitIndexEntry` - files in the directory
  - traverse this list, bottom up
  - at each directory, build tree with its contents
  - write new tree to the repo
  - add the tree to the directory's parent
  - iterate over the next directory

### The Myers Diff Algorithm

- being greedy
- finding the **Shortest Edit Script (SES)**
- finding the **Longest Common Subsequence**
- when `git rm` a file, the `git diff` shows:
  ```console
  diff --git a/some_file b/some_file
  deleted file mode 100644
  index <hash>...0000000
  --- a/some_file
  +++ /dev/null
  ```
- if file mode has been changed,
  ```console
  diff --git a/some_file b/some_file
  old mode 100644
  new mode 100755
  ```
- screenshot of progress so far: diff with headers _only_
  ![pit diff](./assets/pit_diff_headers_only.png)

- `git diff --cached` or `git diff --staged`
  - changes staged for commit
  - diff between the `HEAD` tree and the index

# Proto-RepoTemplate Conventions

The project should always be written in Nim. Please follow these guidelines and conventions.

## Function Structure

Maintainability above all.

Keep functions short and avoid nesting at all costs!
Write helper functions/templates and call them in succession from "high level" functions instead! 


```nim
proc myFunc1(): void =
  ...

proc myFunc2(): void =
  ...

proc highLevelFunc(): int =
  myFunc1()
  myFunc2()
  ...
```

## Function Syntax

Please call all Nim function either with 
```
funcX(param1, param2)
``` 
or 
```
param1.funcX(param2)
```

Please refrain from using 
```
funcX: 
  param1, param2
```
unless it is absolutely needed. In which case, you have to specifically explain this way of function usage in the comment above it.

## Folder Structure (Dependency Levels)

Organize modules so each level depends on (at least some) parts from the previous level.

```
src/lib/level0
src/lib/level1
src/lib/level2
src/lib/level3
```

## Naming and Parameter Rules

- Parameter names should use the first letter of what they represent.
- Explain parameter meaning below the function declaration with a `##` doc comment.
- Arrays, sequences, openArrays, and tables should use capital letters like `A`.
  - Example: an array of records -> `R`
- Some parameters should always use a special name, like `dir` for directory and `args` for arguments. Do that for the most generic ones. In these cases an uppercase letter is not needed, even though these are arrays. 
- State objects to be mutated use `S`. If multiple, use `S0`, `S1`, `S2`, ...
- Math-heavy functions use `a,b,c` or `x,y,z` (then `x1`, `x2`, `x3`, ...).
- For arrays/lists in math functions, use uppercase letters like `X,Y,Z` or `A,B,C`.
- `t` is reserved for temporary variables inside functions.
- `i,j,k` are indices; `l,m,n` are lengths.
- Use `while` for complex loops; use `for` for simple one-call loops.
- If a function has only one parameter, you may use its first letter unless it collides with index identifiers.

## Result Variables

For clarity, you may assign to a temporary variable and set `result` at the end.

```nim
proc myProc(a, b: uint8): uint8 =
  var
    veryImportantNumber: uint8 # this is basically the result
  veryImportantNumber = callSomeOtherFunc(a, b)
  veryImportantNumber = veryImportantNumber + callYetAnotherFunc(a)
  result = veryImportantNumber
```

## Declarations and Formatting

Declare variables at the start of the proc, not in the middle of loops or blocks.

```nim
var
  t1: string
  t2: int
  t3: uint8
```

Always indent `var`, `let`, `const`, and `type` when declaring multiple values.

```nim
const
  c1: string = "hey"
  c2: int = 0
  c3: uint8 = 0
var
  t1: string = "this value is known already, but needs to be changed later"
  t2: int # this value is not yet known, but we reserve the space for it
  t3: uint8 # same here
let
  t4: string = "holla"
  t5: int = 0
```

Use `const` whenever possible; otherwise use `var`. If you already know the value, assign it immediately:

```nim
var
  t1: string = "Assign value immediately like it should be"
```

Not:

```nim
var
  t1: string
t1 = "Why assign later?"
```

## Performance

Where possible avoid complex object types with many references/pointers. 
Instead try to use arrays or sequences. Do not allocate new memory inside loops. 
Always have the loop access a local function variable and store its value there.
Let functions return their value and assign it to another variable afterwards, instead of performing 
operations directly on a var parameter.

Bad example:
```
var uint8 = 4

proc myFunc(x: var uint8): void =
  x = 3 * 15 + x

```
Good example:
```
var uint8 = 4

proc myFunc(x: uint8): uint8 =
  result = 3 * 15 + x

x = myFunc(x)

```



## Project Layout

Prefer understanding, long-term maintainability, and modularity over efficiency.

- The actual project belongs in `src`. If it is missing, create it.
- Expose submodules inside each repo under `submodules/`, but keep the actual local checkouts as sibling repos outside the parent repo whenever possible.
- Every repo must include a `.iron/` folder next to `src/` for repo-coordination metadata and templates.
- Every module (`.nim` file) must have a description at the top explaining what it does.
  - Prefer visual hints like arrows (`<- ->`), ASCII art boxes, and separators (`|`, `-`).

The `src` folder should be structured by levels:
- Highest level: helpers, types, utilities
- Each dependency on a file inside `src` increases the level

Example structure:

```
src/utils.nim
src/types.nim
src/level1/module1.nim <- depends on utils or types
src/level1/module2.nim <- depends on utils or types
src/level1/level2/module3.nim <- depends on module1 or module2
...
```

## Reuse and Compression

If you write three similar helper functions across modules, move them into `utils` and overload or use generics (`when`/`case`) instead. Do this regularly to keep the project lean and avoid unneeded bloat.

## Documentation

Update the README when you make bigger project changes.

At the bottom of the README of a project, include a cleaner, more formatted version of these conventions so maintainers can quickly understand the programming style.

## Tools and Tests

- Add a `tools` folder when needed (for submodule builders or other pre-compile time utilities).
- Always include a `test` folder with unit tests for important functions.
- After changing code or dependencies, run tests and fix errors.

## iron Folder (Repo Coordination)

Every repo must have a `.iron/` folder located next to `src/`.

- Store repo-coordination configs and templates there.
- Use `Proto-RepoTemplate/.iron/` as the template source.
- The local submodule override file lives at `.iron/.local.gitmodules.toml` and should be ignored by git.

## Dependencies and External Projects

If you need an entirely different project as a dependency (because a library or bindings are missing), ask before starting a new project in a sibling folder. Include estimated complexity and time.

Prefer Nim and nimble only. No Python, bash, or PowerShell.

Submodule checkouts should live in the shared workspace root as sibling repos, not as second nested clones inside the parent repo.
Use `.iron/.local.gitmodules.toml` to map each declared submodule path to the local sibling repo, and let iron create the local links automatically.

## C Bindings (cNimWrapper)

We have a cNimWrapper in the parent directory where all projects live. It should accurately create bindings for C libraries. If you need bindings for a C-only repo, you may use it and clone the repo without asking.

## Shared Utils (Fylgia-Utils)

There is a repo called "Fylgia-Utils" (git URL: https://github.com/siriuslee69/fylgia-utils).
- It may contain tools and other things you will reuse.
- You may add it via nimble.
- Put generic helper functions there when appropriate.

## Shared SIMD library (SIMD-Nexus)

There is a repo called SIMD-Nexus which exports high-level bindings for nimsimd. 
It also features utility functions like simd string searching.
Use it where possible via generic function types, such that you can switch between them depending on target system. 

## Nimsuggest

Do not write pre-compile time import statements that prevent nimsuggest from checking functions.

## .iron/PROGRESS.md

Inside each project, keep `.iron/PROGRESS.md` up to date and track:
0. Current commit message (update after every change)
1. Features to implement (total)
2. Features already implemented
3. Features in progress
And also:
1. Last big change or problem encountered
2. How you tried to fix it, and whether it worked

## .nimble Tasks

Create a `.nimble` file with tasks for:
1. Test runs (call after each change)
2. Builders

## Configs

Prefer `.toml` for config files across all repos.
Every project that is supposed to run standalone should have a `config.toml` file for important runtime settings.
Every project that is supposed to be run by a user/client may additionally have a `user.config.toml`.
Every project that is supposed to be run as a dependency should expose a publish-safe TOML bridge config for integration.

## Compatibility

In general, all the projects are meant to run on Linux and Windows. Specifically Windows 11 and NixOS. 
Both should have first-class support and run out of the box. Make sure to always include a custom nix shell 
and an install commands that can be run by the user for MSYS2 on Windows 11. 
It should compile automatically for each OS differently, unless otherwise specified.
The compiling user should be prompted if there are missing dependencies on whether to run these.

## Git

1. Add a nimble task that auto-pushes with a commit message from `.iron/PROGRESS.md` (see `proto_conventions.nimble` in this repo).
2. Add a `.gitignore` that excludes `builds` and `.exe` files.
3. Add a `submodules/` folder to each repo for linked submodule entry paths, but keep the actual local checkouts as sibling repos outside the parent repo.

## Repo Examples (App vs Library)

This repo includes one `src` folder for app repos and another for library repos. Identify which type your new repo is.
- Libraries do not need a frontend (at most a CLI).
- There should be no frontend/backend separation for libraries.
- If a repo has interface + libraries, its `src` folder should be split into `interfaces` and `lib`.

You may follow the general structure of the rest of this Proto-RepoTemplate repo and the example files.

## Issue Playbook

Create an issue playbook at the bottom of the README.md which lists common issues/workaround for bugs and problems that have been encountered and could not be fixed or are only fixed superficially. Some of them may be at risk of greater degradation when they are just patching other imported and broken submodules/repos. The users should know of these in advance.

## Conventions

Keep a copy of this `.iron/` folder and its contents in each repo.
Make sure `.iron/.local.config.toml` only contains machine-local values, and `.iron/.local.gitmodules.toml` only contains local submodule path overrides.


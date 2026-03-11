# Proto Conventions
The project should always be written in Nim unless stated otherwise. Please follow these guidelines and conventions.

## All functions and custom types need custom pragmas.
These tags and pragma definitions live inside the .iron folder.
The tags type is repo specific and should be extended/fit respectively.

## No let declarations!
Instead use var or const at the beginning of a function.
Give variables a default value and reassign later if needed.
Avoid declaring inside loops at all costs.

## No loop nesting! No if-statement nesting!
Instead, inline functions via pragma or use templates!

## No unnecessary, repeating "var", "const" or "type" identifiers in each new line!
Always define vars, consts and types in indented blocks!

## No complex logic! Build modular, parallel, multipass logic.
Adhere to the mantra: Perceive data -> build truth state -> act on parsed data

### Perceiving data - means to parse data and extract information.
This should be done via rather small functions (role: `parser`) which look for a specific information each. 
They should output one or all of the following:
1. Was the information present at all? (return bool/number)
2. Where was the information? (return number)
3. What was the information? (return string/enum/bool/number)

### Building a truth state about the data - means to build a state from the output of all parser functions that acted on it:
This should be an object/tuple that can hold all the parsers extracted information. (role: `truthstate`)
There should be one function which calls all parsers (simultaneously or in specific order) to fill this truth state. (role: `truthBuilder`)
The truth state ITSELF can be used by one of these parsers as well to add to the truth state. (role: `metaparser`)

### Acting on the parsed data - means to output new data or change existing data/states.
These functions (role: `actor`) should parse the truthstate object and output/change data outside of the truth state.
A big function (role: `orchestrator`) which usually loops or runs on change, will first call the truthbuilder, which calls the parsers. Then the orchestrator will call the actors to perform based on the truthstate.
There may be more than one orchestrator (one for parsers, one for actors) and there may be orchestrators that call other orchestrators (role: `metaOrchestrator`).

## Some structural examples

How to avoid nesting with highlevel functions:

```nim
proc myFunc1(): void {.inline.} =
  ...

proc myFunc2(): void {.inline.} =
  ...

proc highLevelFunc(): int =
  myFunc1()
  myFunc2()
  ...
```

## Function Syntax

Avoid colon syntax for function calls. 

Good example:
```
funcX(param1, param2)
``` 
or 
```
param1.funcX(param2)
```

Bad example
```
funcX: 
  param1, param2
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
    t: uint8 = 0 #this is basically the result, with an initialized default value
  t = callSomeOtherFunc(a, b)
  t = t + callYetAnotherFunc(a)
  result = t
```

## Declarations and Formatting

Always indent `var`, `let`, `const`, and `type` into blocks when declaring multiple values.

```nim
const
  c1: string = "hey" #use const where possible
  c2: int = 23
  c3: uint8 = 4
var
  t1: string = "" #initialize if possible to default values
  t2: int = 0
  t3: uint8 = 0
let
  t4: string = "holla" #avoid let definitions, unless for user inputs
  t5: int = 0
```
## Project Layout

The root of a repo should be structured into
```
/.iron <- folder for Iron-RepoCoordinator
/nix <-nix shell/dependencies (not always needed, only when UI or other dependencies required)
/src/lib <- actual repo content 
/src/interfaces <- guis/uis/clis (not always needed, libraries will at max use a cli)
/submodules <- submodules
/tests 
```

Order modules by dependency level:

```
src/lib/types.nim
src/lib/level0/moduleX.nim <- depends on types only
src/lib/level1/moduleXY.nim <- depends at least on moduleX
src/lib/level2/moduleTZ.nim <- depends at least on moduleXY
...
```

In some libraries it might make sense to instead sort modules by role/name. 
That is especially the case, if a repo is a collection of many tiny algorithms/parsers/helpers.
In these cases, you can sort them like by module first instead of by dependency level.

Every (`.nim` file) must have a description at the top explaining what it does.
Prefer visual hints like arrows (`<- ->`), ASCII art boxes, and separators (`|`, `-`).

## Reuse and Compression

If you write three similar helper functions across modules, move them into `utils` and overload or use generics (`when`/`case`) instead. Do this regularly to keep the project lean and avoid unneeded bloat.

## Documentation

Update the README when you make bigger project changes.

At the bottom of the README of a project, include a cleaner, more formatted version of these conventions so maintainers can quickly understand the programming style.

## Tools and Tests

- Add a `tools` folder when needed (for submodule builders or other pre-compile time utilities).
- Always include a `test` folder with unit tests for important functions.
- After changing code or dependencies, run tests and fix errors.

## .iron Folder (Repo Coordination)

Every repo must have a `.iron/` folder located next to `src/`.

- Store repo-coordination configs and templates there.
- Use `Proto-RepoTemplate/.iron/` as the template source.
- The local submodule override file lives at `.iron/.local.gitmodules.toml` and should be ignored by git.

## C Bindings (cNimWrapper)

We have a cNimWrapper in the parent directory where all projects live. It should accurately create bindings for C libraries. If you need bindings for a C-only repo, you may use it and clone the repo without asking.

## Shared Utils (Fylgia-Utils)

There is a repo called "Fylgia-Utils" (git URL: https://github.com/siriuslee69/fylgia-utils).
- It may contain tools and other things you will reuse.
- Put generic helper functions there when appropriate.

## Shared SIMD library (SIMD-Nexus)

There is a repo called SIMD-Nexus which exports high-level bindings for nimsimd. 
It also features utility functions like simd string searching.
Use where appropriate.

## Nimsuggest

Do not write pre-compile time import statements that prevent nimsuggest from checking functions.

## progress.md

Inside each project, create `progress.md` inside .iron (if it does not exist) and track:
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
3. Autopushing

## Configs

Every project should have a config.toml file which sets global vars inside the lib and an additional userconfig.toml 
if it is meant to be used as a client.

## Compatibility

In general, all the projects are meant to run on Linux and Windows. Specifically Windows 11 and NixOS. 
Both should have first-class support and run out of the box. 
You may follow the general structure of the rest of this proto-conventions repo and the example files.

## Issue Playbook

Create an issue playbook at the bottom of the README.md which lists common issues/workaround for bugs and problems that have been encountered and could not be fixed or are only fixed superficially. Some of them may be at risk of greater degradation when they are just patching other imported and broken submodules/repos. The users should know of these in advance.

## Conventions

Keep a copy of this .iron folder and its contents in each repo.
Make sure to change the path in the .md in .local.config.toml in the .iron folder accordingly.

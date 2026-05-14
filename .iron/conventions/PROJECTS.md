# Proto Conventions
The project should always be written in Nim unless stated otherwise. Please follow the conventions in the .md files in .iron/conventions.

## Project Layout

The root of a repo should be structured into
```
/.iron <- folder for Iron-RepoCoordinator
/nix <-nix shell/dependencies (not always needed, only when UI or other dependencies required)
/src/protocols <- actual repo content 
/src/clients <- guis/uis/clis (not always needed, libraries will at max use a cli)
/src/server <- server architecture - loop, networking, etc.
/submodules <- submodules
/tests 
```

Order modules in the protocols by dependency level:
 
```
src/protocols/types.nim
src/protocols/level0/moduleX.nim <- depends on types only
src/protocols/level1/moduleXY.nim <- depends at least on moduleX
src/protocols/level2/moduleTZ.nim <- depends at least on moduleXY
...
```

This is not needed in the server and client directory.

In some libraries it might make sense to instead sort modules by role/name. 
That is especially the case, if a repo is a collection of many tiny algorithms/parsers/helpers.
In these cases, you can group them by module first instead of by dependency level.

Every (`.nim` file) must have a description at the top explaining what it does.
Prefer visual hints like arrows (`<- ->`), ASCII art boxes, and separators (`|`, `-`).

Make sure to add nimble tasks for all the builds/examples/tests so I can run them easily without flags.


## Documentation

Update the README when you make bigger project changes.

At the bottom of the README of a project, include a cleaner, more formatted version of these conventions so maintainers can quickly understand the programming style.

## Nimsuggest

Do not write pre-compile time import statements that prevent nimsuggest from checking functions.

## progress.md

Inside each project, create `progress.md` inside .iron (if it does not exist) and track:

1. Current commit message (update after every change)
2. Features to implement (total)
3. Features already implemented
4. Features in progress

And also:

1. Last big change or problem encountered
2. How you tried to fix it, and whether it worked

## .nimble Tasks

Create a `.nimble` file with tasks for:
1. Test runs (call after each change)
2. Builders
3. Autopushing

## Configs

Every project should have a parser module for a config.toml file which sets global vars inside the lib and an additional parser for the userconfig.toml if it is meant to be used as a client.

## Compatibility

In general, all the projects are meant to run on Linux and Windows. Specifically Windows 11 and NixOS. 
Both should have first-class support and run out of the box. 
You may follow the general structure of the rest of this Proto-RepoTemplate repo and the example files.

## Issue Playbook

Create an issue playbook at the bottom of the README.md which lists common issues/workaround for bugs and problems that have been encountered and could not be fixed or are only fixed superficially. Some of them may be at risk of greater degradation when they are just patching other imported and broken submodules/repos. The users should know of these in advance.

## Conventions

Keep a copy of this .iron folder and its contents in each repo.
Make sure to change the path in .local.config.toml in the .iron folder accordingly.

## Production Readiness

When I tell you to make something production-ready, I expect the following:
1. Add correct licensing files for third party code or documents if necessary.
2. Add builds, assets and runtime dependencies etc. to .gitignore.
3. Add all dependencies that are required for this project via the nimble file and the submodules folder as a git submodule. They shouldn't live anyhwere else.
4. All API calls that are user/dev facing should be simple and intuitive and modular if possible. 
5. All API calls should have a sanitization function sitting behind them, if they handle raw user input.
6. The repo's .iron folder should be updated with the current .iron folder from Proto-RepoTemplate, except for the meta folder which may contain repo-custom code.
7. There should be a docs folder, which contains .md files on benchmarks, tests, code layout and structure with ASCII tables for better visualization and ASCII flow-charts. The same extensive treatment should be given to the CONTRIBUTING.md.
8. Clear up any unneeded code and artifacts from prior refactors, name changes, API changes or tests. Specifically functions/code/tests that seem to be duplicate in nature and have no clear seperate functions/roles within the repo. In these cases, determine which one seems more polished or newer and remove the other. If unsure, ask me first.
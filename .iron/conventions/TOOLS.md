# Proto Conventions
The project should always be written in Nim unless stated otherwise. Please follow the conventions in the .md files in .iron/conventions.

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

## Benchmarking and Evaluation 

Use Otter-RepoEvaluation for performance testing and optimization. Specifically its pragma otterBench.
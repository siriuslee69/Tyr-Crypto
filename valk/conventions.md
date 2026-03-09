# Proto Conventions

`proto-conventions` is the template source for the shared Nim repo layout in this workspace.

## Core Rules

- Keep the project in Nim unless there is a clear reason not to.
- Prefer maintainability and explicit structure over cleverness.
- Keep functions short and push detail into helpers instead of deep nesting.
- Use module headers and clear names so the repo stays readable in plain text and in Ratatoskr.

## Function Style

- Prefer `funcX(a, b)` or `a.funcX(b)` call syntax.
- Avoid the colon-call style unless the call would be harder to read otherwise.
- Use `result` directly for simple functions. Introduce a temporary only when it improves clarity.
- Keep side effects obvious. Parsing, IO, orchestration, and state mutation should be easy to locate.

## Naming

- Use short parameter names when the meaning is obvious in context.
- Use stable names like `dir`, `path`, `args`, and `ctx` for common concepts.
- Use `i`, `j`, `k` for indices and `l`, `m`, `n` for lengths when a loop is mechanical.
- Name mutable state objects consistently when there are multiple state values in scope.

## Layout

- Keep tracked source under `src/`.
- Use `src/lib/` for reusable library code.
- Use `src/interfaces/` for frontend/backend boundaries when the repo ships an app.
- Keep dependency direction shallow: lower levels should not import higher levels.
- Put optional helper repos in `submodules/` when the repo truly owns them.

Example:

```text
src/
  lib/
    level0/
    level1/
    level2/
  interfaces/
    backend/
    frontend/
valk/
tests/
```

## Documentation

Every production repo should keep these files current:

- `README.md`
  - repo boundary, neighboring repos, main state types, orchestrators, and examples.
- `CONTRIBUTING.md`
  - what belongs in the repo, what does not, key files/functions, review checklist, and verification commands.
- `valk/progress.md`
  - current commit message plus planned, in-progress, and finished work.
- `valk/valkyrie_config.template.md`
  - tracked, publish-safe template for the local Valkyrie config.
- `valk/valkyrie_config.md`
  - machine-local config copied from the template and ignored by git.

When documenting architecture, explain:

1. what the repo owns,
2. what it explicitly does not own,
3. the main state types,
4. the main orchestrator functions,
5. which loops call those orchestrators,
6. normal examples of use,
7. where disk, process, or network boundaries live.

## Tests and Tasks

- Keep smoke or unit coverage in `tests/`.
- Run tests after changing code or repo wiring.
- Add nimble tasks for the test path and the main entrypoints.
- Keep task paths in sync with the real source tree.

## Valk Repo Metadata

Every repo should have a `valk/` folder next to `src/`.

- Use `proto-conventions/valk/` as the template source.
- Keep tracked files inside `valk/` publish-safe.
- Track `valk/valkyrie_config.template.md` as the publish-safe template.
- Keep the live local config at `valk/valkyrie_config.md` and ignore it in git.
- Do not commit absolute local paths in tracked config files.

## Split-Repo Guidance

For fractured projects such as `Server`, `Client`, and `Protocols`:

- keep the protocols repo generic and side-effect light,
- keep callbacks and state machines in the client/server repos,
- make repo ownership explicit in docs,
- avoid hiding cross-repo boundaries behind vague helper layers.

## Dependencies

- Prefer Nim and nimble-first solutions.
- Add a sibling repo dependency only when the boundary is justified.
- If you pull in an external helper repo, document why the dependency exists.

Useful shared repos in this workspace include:

- `Fylgia-Utils` for generic helpers worth centralizing.
- `SIMD-Nexus` for SIMD-oriented utilities when the target benefits from them.
- `cNimWrapper-Bindr` when a C-only dependency needs bindings.

## Compatibility

- Assume Windows 11 and NixOS are first-class targets unless stated otherwise.
- Keep local developer setup instructions concrete.
- If desktop tooling needs GTK or other system packages, document the shell/setup path.

## Publish Hygiene

Before pushing:

1. make sure tracked configs do not contain private local paths,
2. remove generated binaries and local cache files from version control,
3. keep `.gitignore` aligned with the actual build outputs,
4. update `README.md`, `CONTRIBUTING.md`, and `valk/` templates together when conventions change,
5. verify the repo still builds or tests through its documented commands.

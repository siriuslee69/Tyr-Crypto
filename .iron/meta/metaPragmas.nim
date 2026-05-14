## This file should be imported across all files inside src.
## Only the MetaTag values are meant to be changed. Keep the pragma names as-is.
## Use `tag(...)`, not `tags(...)`, because `tags` collides with Nim's built-in pragma.
type
    MetaRole* = enum
        helper, math,
        dataFetcher, decryptor, parser, truthBuilder, metaParser,
        actor, orchestrator, metaOrchestrator, encryptor, dataWriter,
        otherRole,
        rawData, preparedData,
        truthState, memory

    MetaInput* = enum
        user, llm, thirdParty, trusted
    MetaRisk* = enum
        `low`, `medium`, `high`
    MetaSpeed* = enum
        `fast`, `normal`, `long`, dataDependent
    MetaIssue* = tuple
        name: string # short description or name
        id: uint64 #issues id/reference
    MetaIssues* = seq[MetaIssue]
    MetaTag* = enum
        other #put your custom tags here
    MetaTags* = set[MetaTag]

template input*(x: set[MetaInput]) {.pragma.}
template role*(x: set[MetaRole]) {.pragma.}
template risk*(x: MetaRisk) {.pragma.}
template speed*(x: MetaSpeed) {.pragma.}
template issues*(x: MetaIssues) {.pragma.}
template tag*(x: MetaTags) {.pragma.}


## -----------------------------------------------------------
## NTRU/SABER Paper Downloader <- Nim lockfile restore entry
## -----------------------------------------------------------

import std/os

import ../../../tools/research_paper_downloader

when isMainModule:
  runResearchPaperDownloader(joinPath(parentDir(currentSourcePath()), "papers.lock.json"))

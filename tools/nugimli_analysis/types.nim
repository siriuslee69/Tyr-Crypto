## -----------------------------------------------------------------
## NuGimli Analysis Types <- measured security and timing outcomes
## -----------------------------------------------------------------

import otter_repo_evaluation

type
  AvalancheResult* = object
    meanRatio*: float64
    minRatio*: float64
    maxRatio*: float64
    maxOutputBias*: float64
    minChangedWords*: int
    maxChangedWords*: int
    samples*: int
    minInputBit*: int
    partialInputBit*: int
    maxPartialTrials*: int
    zeroInputBit*: int
    maxZeroTrials*: int
    zeroDifferences*: int

  DifferentialResult* = object
    pValue*: float64
    chiSquare*: float64
    maxBucket*: int
    expectedBucket*: float64
    meanRatio*: float64
    minChangedWords*: int
    samples*: int

  WeakPathResult* = object
    inputBit*: int
    samples*: int
    distinctDifferences*: int
    zeroDifferences*: int
    minDistance*: int
    maxDistance*: int
    minChangedWords*: int
    maxChangedWords*: int
    firstDifference*: string

  ComponentResult* = object
    count*: int
    sizes*: seq[int]

  StatisticalResult* = object
    passed*: int
    total*: int
    minPValue*: float64
    failedNames*: seq[string]

  DiffusionPoint* = object
    rounds*: int
    meanRatio*: float64
    minChangedWords*: int

  ProfileResult* = object
    name*: string
    bits*: int
    plaintext*: AvalancheResult
    key*: AvalancheResult
    differential*: DifferentialResult
    plaintextWeak*: WeakPathResult
    keyWeak*: WeakPathResult
    components*: ComponentResult
    statistical*: StatisticalResult
    diffusion*: seq[DiffusionPoint]
    performance*: seq[StableBenchResult]

## --------------------------------------------------------------------
## NuGimli Stream Types <- threaded campaign jobs and checkpoint data
## --------------------------------------------------------------------

type
  EntropySource* = enum
    esZero
    esPin0000
    esPassword
    esWeakRandom
    esSplitMix
    esCryptoRandom

  StreamMode* = enum
    smCounter
    smFeedback
    smCrossWidth

  AdapterMode* = enum
    amZeroPadTruncate
    amRepeat
    amXorFoldDomain

  FeedMode* = enum
    fmIndependentKey
    fmCoupledKey

  WideState* = object
    words*: array[64, uint32]
    wordCount*: int

  StreamCheckpoint* = object
    source*: EntropySource
    mode*: StreamMode
    adapter*: AdapterMode
    feedMode*: FeedMode
    route*: array[3, int]
    stage*: int
    widthBits*: int
    intervalStart*: uint64
    intervalEnd*: uint64
    sampledBytes*: uint64
    shannonEntropy*: float64
    minEntropy*: float64
    onesRatio*: float64
    serialCorrelation*: float64
    zeroByteRatio*: float64
    consecutiveRepeats*: uint64
    fingerprintCollisions*: uint64
    nistPassed*: int
    nistTotal*: int
    minPValue*: float64
    failedTestMask*: uint32

  StreamJob* = object
    source*: EntropySource
    mode*: StreamMode
    adapter*: AdapterMode
    feedMode*: FeedMode
    route*: array[3, int]
    baseBlocks*: uint64
    routeBlocks*: uint64
    material*: array[256, uint8]
    results*: seq[StreamCheckpoint]
    resultCount*: int

  StreamWorker* = object
    jobs*: seq[StreamJob]

  StreamCampaignResult* = object
    threads*: int
    baseBlocks*: uint64
    routeBlocks*: uint64
    elapsedSeconds*: float64
    checkpoints*: seq[StreamCheckpoint]

## ------------------------------------------------------------
## SPHINCS <- compatibility facade to the SPHINCS+ core folder
## ------------------------------------------------------------

import ./asymmetric/pq/sphincs/params
import ./asymmetric/pq/sphincs/operations

## Public Tyr SPHINCS+ surface. Low-level modules remain available under
## `asymmetric/pq/sphincs/` for tests, KATs, and profiling.

export params
export operations

## ------------------------------------------------------------
## SPHINCS <- compatibility facade to the SPHINCS+ core folder
## ------------------------------------------------------------

import ./asymmetric/pq/sphincs/params
import ./asymmetric/pq/sphincs/address
import ./asymmetric/pq/sphincs/context
import ./asymmetric/pq/sphincs/util
import ./asymmetric/pq/sphincs/hash
import ./asymmetric/pq/sphincs/merkle_utils
import ./asymmetric/pq/sphincs/wots
import ./asymmetric/pq/sphincs/fors
import ./asymmetric/pq/sphincs/merkle
import ./asymmetric/pq/sphincs/operations

## Temporary compatibility exports while the SPHINCS surface is still moving.
## TODO(security): stop re-exporting the low-level helpers once the public API
## is fixed so callers cannot bypass the checked high-level entrypoints.
export params
export address
export context
export util
export hash
export merkle_utils
export wots
export fors
export merkle
export operations

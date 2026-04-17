## ------------------------------------------------------------
## SPHINCS <- compatibility facade to the SPHINCS+ core folder
## ------------------------------------------------------------

import ./sphincs/params
import ./sphincs/address
import ./sphincs/context
import ./sphincs/util
import ./sphincs/hash
import ./sphincs/merkle_utils
import ./sphincs/wots
import ./sphincs/fors
import ./sphincs/merkle
import ./sphincs/operations

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

## -------------------------------------
## | OTP <- public surface
## -------------------------------------
##
## HOTP and TOTP one-time login codes. Authentication, not key derivation.
##
## The full implementation lives in `./otp/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.

import ./otp/otp

export otp

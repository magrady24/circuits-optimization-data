# This repository is for research purpose and not intended to industry usage.

Files up_to_33_part_[0..15].bin is about verifying that each integer in [0, 2^33) is a quadratic residue or not under curve BLS12-381 used by Zcash. One bit for each index indicates whether it is a quadratic residue.

AES_cost_calc.cpp is a helper tool for calculation of the number of constraints required for AES-128 encryption including the key schedule.

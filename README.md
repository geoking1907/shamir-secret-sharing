# Weighted Shamir's Secret Sharing Scheme

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)

A modified implementation of Shamir's Secret Sharing scheme with weighted participants, derivative-based shares, and cryptographic verification.

## Table of Contents
- [Key Features](#key-features)
- [Mathematical Background](#mathematical-background)
- [Usage](#usage)
- [Classes](#classes)
- [Security Considerations](#security-considerations)

## Key Features

- **Weighted Participants**: Assign different weights to participants based on their importance
- **Derivative-Based Shares**: Using polynomial derivatives for generating shares
- **Cryptographic Verification**: Ensure share integrity with cryptographic commitments
- **Dynamic Updates**: Modify participant weights without redistributing all shares
- **MITM Protection**: Generator verification prevents man-in-the-middle attacks

## Mathematical Background

The scheme extends Shamir's Secret Sharing using:

1. **Polynomial Construction**:
   ```
   P(x) = S + a₁x + a₂x² + ... + a_{T-1}x^{T-1} mod p
   ```
   Where `S` is the secret, `T` is the threshold, and `p` is a prime modulus.

2. **Derivative Shares**:
   Each participant with weight `w` receives `w` derivatives:
   ```
   Share = [P(x), P'(x), P''(x), ..., P^{(w-1)}(x)]
   ```

3. **Cryptographic Commitments**:
   ```
   Commitment = g^{derivative} mod p
   ```
   Using a generator `g` for verification without revealing shares.

## Usage

### Basic Secret Sharing
```python
# Initialize scheme
scheme = WeightedShamirSecretSharing(
    p=1031,          # Prime > secret
    T=10,            # Threshold weight
    weights=[3, 5, 2, 4],  # Participant weights
    secret=42         # Secret to protect
)

# Access participant
participant = scheme.participants[1]

# Verify share
if participant.verify_share():
    print("Share verified successfully!")

# Reconstruct secret
recovered_secret = scheme.reconstruct_secret([
    scheme.participants[1],
    scheme.participants[2],
    scheme.participants[4]
])
print(f"Recovered secret: {recovered_secret}")
```

### Dynamic Weight Updates
```python
# Update participant weight
scheme.update_participant_weight(participant_id=1, new_weight=4)

# Verify updated share
if participant.verify_share():
    print("Updated share verified!")
```

## Classes

### `WeightedShamirSecretSharing`
Core scheme implementation

**Attributes**:
- `p` (int): Prime field characteristic
- `T` (int): Reconstruction threshold
- `weights` (List[int]): Participant weights
- `g` (int): Cryptographic generator
- `participants` (Dict[int, Participant]): Managed participants

**Key Methods**:
- `generate_shares()`: Create shares for all participants
- `update_participant_weight()`: Modify participant weight
- `reconstruct_secret()`: Recover secret from shares
- `add_verification()`: Generate cryptographic commitments

### `Participant`
Represents a scheme participant

**Attributes**:
- `id` (int): Unique identifier
- `weight` (int): Participant weight
- `derivatives` (List[int]): Share derivatives
- `commitments` (List[int]): Cryptographic commitments
- `verified` (bool): Verification status

**Key Methods**:
- `verify_share()`: Validate share against commitments
- `provide_share()`: Retrieve verified share
- `update_derivatives()`: Update share components

## Security Considerations

1. **Prime Selection**:
   - Must be larger than secret and sum of weights
   - Recommended minimum 2048 bits for production

2. **Generator Requirements**:
   - Must be primitive root modulo p

3. **Weight Constraints**:
   - No single weight ≥ threshold T
   - ∑weights must be ≥ T

4. **Verification Best Practices**:
   - Always verify shares before reconstruction

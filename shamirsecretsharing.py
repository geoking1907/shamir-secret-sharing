import secrets
from typing import List, Tuple, Dict, Optional


class SecurityError(Exception):
    pass


class Participant:
    """
    Participant of the weighted secret sharing scheme.

    Attributes:
        id (int): Unique participant ID
        weight (int): Weight/importance of the participant in the system
        p (int): Prime number, field characteristic
        g (int): Group generator
        derivatives (List[int]): List of derivatives (participant's share)
        commitments (List[int]): Cryptographic commitments for verification
        verified (bool): Share verification status
    """

    def __init__(self,
                 id: int,
                 weight: int,
                 p: int,
                 g: int,
                 derivatives: Optional[List[int]] = None,
                 commitments: Optional[List[int]] = None):
        self.id = id
        self.weight = weight
        self.p = p
        self.g = g
        self.derivatives = derivatives or []
        self.commitments = commitments or []
        self.verified = False

    def __repr__(self) -> str:
        return f"Participant(id={self.id}, weight={self.weight}, verified={self.verified})"

    def verify_share(self) -> bool:
        """
        Verifies the authenticity of its share using cryptographic commitments.

        Returns:
            bool: True if the share is verified, otherwise False
        """
        if not self.commitments:
            raise ValueError("Commitments not available for verification")

        if len(self.derivatives) != len(self.commitments):
            raise SecurityError("Mismatch between derivatives and commitments count")

        self.verified = all(
            pow(self.g, deriv, self.p) == self.commitments[k]
            for k, deriv in enumerate(self.derivatives)
        )
        return self.verified

    def provide_share(self, max_derivatives: Optional[int] = None) -> Tuple[int, List[int]]:
        """
        Returns a share for restoring the secret.

        Parameters:
            max_derivatives (int): Maximum number of derivatives to provide

        Returns:
            Tuple[id, derivatives]: ID and list of derivatives
        """
        if not self.verified:
            raise SecurityError("Share not verified. Cannot provide unverified share")

        derivatives = self.derivatives
        if max_derivatives is not None and max_derivatives < len(derivatives):
            derivatives = derivatives[:max_derivatives]

        return (self.id, derivatives)

    def update_derivatives(self, new_derivatives: List[int], new_commitments: Optional[List[int]] = None):
        """
        Updates the derivatives and obligations of the participant
        """
        self.derivatives = new_derivatives
        if new_commitments:
            self.commitments = new_commitments
        self.verified = False


class WeightedShamirSecretSharing:
    """
    Weighted Shamir's Secret Sharing scheme implementation.

    Attributes:
        p (int): Prime number, field characteristic (must be greater than the secret)
        T (int): Minimal total weight required to reconstruct the secret
        weights (List[int]): Weights assigned to each participant
        secret (int): Secret value being protected
        g (int): Generator for the multiplicative group modulo p
        coeffs (List[int]): Coefficients of the polynomial (secret is coeffs[0])
        factorial_coeffs (Dict[Tuple[int, int], int]): Precomputed factorial coefficients for derivative calculations
        shares (List[Tuple[int, List[int]]]): Generated shares for participants (x, derivatives)
        verifiers (Dict[int, List[int]]): Cryptographic commitments for share verification
        participants (Dict[int, Participant]): Participant objects managed by the scheme
        n (int): Number of participants (derived from weights length)
    """

    def __init__(self, p: int, T: int, weights: List[int], secret: int, g: Optional[int] = None):
        """
        Initializes the weighted secret sharing scheme.

        Parameters:
            p (int): Prime number > secret (field characteristic)
            T (int): Reconstruction threshold (minimal total weight)
            weights (List[int]): Participant weights (length determines number of participants)
            secret (int): Secret value to protect
            g (Optional[int]): Generator for group (auto-calculated if None)

        Raises:
            ValueError: If any weight >= T or invalid parameters
            RuntimeError: If suitable generator not found
        """
        if any(w >= T for w in weights):
            raise ValueError("No single participant weight should be >= T")
        self.p = p  # prime
        self.g = g if g is not None else self.find_generator()
        self.T = T  # threshold
        self.weights = weights
        self.n = len(weights)
        self.secret = secret % p

        self.coeffs = [secret] + [secrets.randbelow(p - 2) + 1 for _ in range(T - 1)]

        self.factorial_coeffs = self._precompute_factorial_coeffs()

        self.shares = self.generate_shares()
        self.verifiers = {}
        self.add_verification()

        self.participants = self.create_participants()

    def _precompute_factorial_coeffs(self) -> Dict[Tuple[int, int], int]:
        """Pre-calculating factorial coefficients for optimization"""
        coeffs = {}
        for j in range(1, self.T):
            for k in range(j + 1):
                coeff = 1
                for i in range(k):
                    coeff = coeff * (j - i) % self.p
                coeffs[(j, k)] = coeff
        return coeffs

    def find_generator(self) -> int:
        """Finds a generator for the GF(p) field"""
        for candidate in (2, 3, 5, 6, 7, 11):
            if pow(candidate, (self.p - 1) // 2, self.p) != 1:
                return candidate

        factors = self._prime_factors(self.p - 1)
        for candidate in range(2, self.p):
            if all(pow(candidate, (self.p - 1) // f, self.p) != 1 for f in factors):
                return candidate
        raise RuntimeError(f"Generator not found for prime {self.p}")

    def _prime_factors(self, n: int) -> List[int]:
        """Returns the prime divisors of a number"""
        factors = []
        d = 2
        while d * d <= n:
            while n % d == 0:
                factors.append(d)
                n //= d
            d += 1
        if n > 1:
            factors.append(n)
        return list(set(factors))

    def add_verification(self):
        """Generates cryptographic commitments for verifying shares"""
        self.verifiers = {}
        for i, w in enumerate(self.weights):
            x = i + 1
            derivatives = self.shares[i][1]
            commitments = [pow(self.g, deriv, self.p) for deriv in derivatives]
            self.verifiers[x] = commitments

    def evaluate_derivative(self, x: int, k: int) -> int:
        """Calculates the k-th derivative at point x"""
        result = 0
        for j in range(k, self.T):
            # Используем предвычисленные коэффициенты
            coeff = self.factorial_coeffs.get((j, k), 1)
            term = self.coeffs[j] * coeff % self.p
            term = term * pow(x, j - k, self.p) % self.p
            result = (result + term) % self.p
        return result

    def generate_shares(self) -> List[Tuple[int, List[int]]]:
        """Generates shares for all participants"""
        shares = []
        for i, w in enumerate(self.weights):
            x = i + 1  # uid
            derivatives = [self.evaluate_derivative(x, k) for k in range(w)]
            shares.append((x, derivatives))
        return shares

    def create_participants(self) -> Dict[int, Participant]:
        """Creates and initializes scheme participants"""
        participants = {}
        for i, w in enumerate(self.weights):
            x = i + 1
            derivatives = self.shares[i][1]
            commitments = self.verifiers.get(x, [])

            participant = Participant(
                id=x,
                weight=w,
                p=self.p,
                g=self.g,
                derivatives=derivatives,
                commitments=commitments
            )

            try:
                participant.verify_share()
            except Exception as e:
                raise RuntimeError(f"Failed to verify participant {x} during creation") from e

            participants[x] = participant
        return participants

    def update_participant_weight(self, participant_id: int, new_weight: int):
        """Updates the participant's weight and recalculates the derivatives"""
        if new_weight >= self.T:
            raise ValueError("New weight cannot be >= threshold")

        idx = participant_id - 1
        if 0 <= idx < len(self.weights):
            self.weights[idx] = new_weight
        else:
            raise ValueError(f"Invalid participant ID: {participant_id}")

        x = participant_id
        new_derivatives = [self.evaluate_derivative(x, k) for k in range(new_weight)]

        for i, (x_share, _) in enumerate(self.shares):
            if x_share == x:
                self.shares[i] = (x, new_derivatives)
                break

        self.add_verification()

        if participant_id in self.participants:
            new_commitments = self.verifiers.get(x, [])
            self.participants[participant_id].update_derivatives(new_derivatives, new_commitments)

            try:
                self.participants[participant_id].verify_share()
            except Exception as e:
                raise RuntimeError(f"Failed to verify participant {participant_id} after update") from e

    def reconstruct_secret(self, provided_participants: List[Participant]) -> int:
        """
        Restores the secret based on the provided participants.

        Parameters:
            provided_participants (List[Participant]): List of participants to restore

        Returns:
            int: Restored secret
        """
        provided_shares = []
        for participant in provided_participants:
            try:
                share = participant.provide_share()
                provided_shares.append(share)
            except SecurityError as e:
                raise SecurityError(f"Participant {participant.id} has unverified share") from e

        return self._reconstruct_secret(provided_shares)

    def _reconstruct_secret(self, provided_shares: List[Tuple[int, List[int]]]) -> int:
        """The internal method of secret reconstruction"""
        if len({x for x, _ in provided_shares}) != len(provided_shares):
            raise ValueError("Duplicate participants detected")

        total_weight = sum(len(derivs) for _, derivs in provided_shares)
        if total_weight < self.T:
            raise ValueError(f"Insufficient total weight of participants ({total_weight}<{self.T})")

        equations = []
        for x, derivs in provided_shares:
            for k, value in enumerate(derivs):
                equation = []
                for j in range(self.T):
                    if j < k:
                        equation.append(0)
                    else:
                        coeff = 1
                        for i in range(k):
                            coeff = coeff * (j - i) % self.p
                        coeff = coeff * pow(x, j - k, self.p) % self.p
                        equation.append(coeff)
                equations.append((equation, value))

        return self.gaussian_elimination(equations)

    def gaussian_elimination(self, equations: List[Tuple[List[int], int]]) -> int:
        """Solves a system of linear equations using the Gauss method"""
        n = self.T
        matrix = [eq[0] + [eq[1]] for eq in equations]

        for col in range(n):
            pivot_row = col
            for r in range(col, len(matrix)):
                if matrix[r][col] % self.p != 0:
                    pivot_row = r
                    break
            else:
                raise ValueError(f"No pivot found for column {col}")

            matrix[col], matrix[pivot_row] = matrix[pivot_row], matrix[col]

            pivot = matrix[col][col]
            inv_pivot = pow(pivot, -1, self.p)
            for j in range(col, n + 1):
                matrix[col][j] = matrix[col][j] * inv_pivot % self.p

            for r in range(len(matrix)):
                if r == col:
                    continue
                factor = matrix[r][col]
                for j in range(col, n + 1):
                    matrix[r][j] = (matrix[r][j] - factor * matrix[col][j]) % self.p

        return matrix[0][n]


# EXAMPLE
if __name__ == "__main__":
    try:
        scheme = WeightedShamirSecretSharing(
            p=1031,
            T=10,
            weights=[3, 5, 2, 4],
            secret=42
        )

        participant = scheme.participants[1]

        if participant.verify_share():
            print("Доля верифицирована успешно!")
        else:
            print("Ошибка верификации доли!")

        scheme.update_participant_weight(participant_id=1, new_weight=4)

        recovered_secret = scheme.reconstruct_secret([
            scheme.participants[1],
            scheme.participants[2],
            scheme.participants[4]
        ])
        print(f"Восстановленный секрет: {recovered_secret}")
    except ValueError as e:
        print(f"\033[91mExpected error: {e}\033[0m")

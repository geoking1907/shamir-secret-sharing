import secrets
from typing import List, Tuple, Optional


class WeightedShamirSecretSharing:
    '''
        Input *p* - prime number, greater than your *secret*;
        *T* - minimal total weight required to reconstruct the secret message;
        *weights* - weights of participants;
        *secret* - your secret message.
    '''
    def __init__(self, p: int, T: int, weights: List[int], secret: int, g: Optional[int] = None):
        if any(w >= T for w in weights):
            raise ValueError("No single participant weight should be >= T")
        self.p = p  # prime
        self.g = g if g is not None else self.find_generator()
        self.T = T  # threshold
        self.weights = weights
        self.x_powers = {}
        self.n = len(weights)
        self.secret = secret % p
        self.coeffs = [secret] + [secrets.randbelow(p - 2) + 1 for _ in range(T - 1)]
        self.factorial_coeffs = {}
        for j in range(1, T):
            for k in range(j + 1):
                coeff = 1
                for i in range(k):
                    coeff = coeff * (j - i) % self.p
                self.factorial_coeffs[(j, k)] = coeff
        self.shares = self.generate_shares()
        self.verifiers = {}


    def find_generator(self) -> int:
        for candidate in (2, 3, 5, 6, 7, 11):
            if pow(candidate, (self.p - 1) // 2, self.p) != 1:
                return candidate
        raise RuntimeError(f"Generator not found for prime {self.p}")


    def add_verification(self):
        for i, w in enumerate(self.weights):
            x = i + 1
            derivatives = self.shares[i][1]
            commitments = []
            for deriv in derivatives:
                commitment = pow(self.g, deriv, self.p) # g^deriv mod p
                commitments.append(commitment)

            self.verifiers[x] = commitments


    def verify_share(self, x: int, derivatives: List[int]) -> bool:
        commitments = self.verifiers.get(x, [])

        for k, deriv_value in enumerate(derivatives):
            recreated_commit = pow(self.g, deriv_value, self.p)

            if k >= len(commitments) or recreated_commit != commitments[k]:
                return False
        return True


    def update_weight(self, participant_idx: int, new_weight: int):
        if new_weight >= self.T:
            raise ValueError("New weight >= T")

        self.weights[participant_idx] = new_weight
        x = participant_idx + 1
        derivatives = [self.evaluate_derivative(x, k) for k in range(new_weight)]
        self.shares[participant_idx] = (x, derivatives)

        if self.verifiers:
            self.verifiers[x] = [pow(self.g, d, self.p) for d in derivatives]


    def evaluate_derivative(self, x: int, k: int) -> int:
        if x not in self.x_powers:
            powers = [1]
            for exp in range(1, self.T):
                powers.append(powers[-1] * x % self.p)
            self.x_powers[x] = powers

        result = 0
        for j in range(k, self.T):
            exp = j - k
            term = self.coeffs[j] * self.factorial_coeffs.get((j, k), 1) % self.p
            term = term * self.x_powers[x][exp] % self.p
            result = (result + term) % self.p
        return result


    def generate_shares(self) -> List[Tuple[int, List[int]]]:
        shares = []
        for i, w in enumerate(self.weights):
            x = i + 1  # uid
            derivatives = [self.evaluate_derivative(x, k) for k in range(w)]
            shares.append((x, derivatives))
        return shares


    def reconstruct_secret(self, provided_shares: List[Tuple[int, List[int]]], g: int) -> int:
        if g != self.g:
            raise ValueError("Generator mismatch! Possible MITM attack")
        if len({x for x, _ in provided_shares}) != len(provided_shares):
            raise ValueError("Duplicate participants detected")
        total_weight = sum(len(derivs) for _, derivs in provided_shares)
        if total_weight < self.T:
            raise ValueError(f"Insufficient total weight of participants ({total_weight})")

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
        n = self.T
        matrix = [eq[0] + [eq[1]] for eq in equations]

        for col in range(n):
            max_row = max(range(col, len(matrix)), key=lambda r: abs(matrix[r][col]))
            matrix[col], matrix[max_row] = matrix[max_row], matrix[col]

            pivot = matrix[col][col]
            inv_pivot = pow(pivot, -1, self.p) if pivot != 0 else 0
            for j in range(col, n + 1):
                matrix[col][j] = matrix[col][j] * inv_pivot % self.p

            for r in range(len(matrix)):
                if r == col: continue
                factor = matrix[r][col]
                for j in range(col, n + 1):
                    matrix[r][j] = (matrix[r][j] - factor * matrix[col][j]) % self.p
        return matrix[0][n]


# EXAMPLE
if __name__ == "__main__":
    p = 1031  # prime number greater than your secret
    secret = 12

    try:
        dealer = WeightedShamirSecretSharing(p, 3, [1, 1, 1, 1, 1], secret)
        dealer.add_verification()
        shares = [dealer.shares[0], dealer.shares[1], dealer.shares[2]]
        recovered = dealer.reconstruct_secret(shares, 7)
        print(f"Reconstructed secret: {recovered} (expected {secret})")
    except ValueError as e:
        print(f"\033[91mExpected error: {e}\033[0m")

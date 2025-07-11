import secrets
from typing import List, Tuple


class ShamirSecretSharing:
    '''
        Input *p* - prime number, greater than your *secret*;
        *k* - minimal number of shares required to reconstruct the secret message;
        *n* - number of generated shares;
        *secret* - your secret message.
    '''
    def __init__(self, p: int, k: int, n: int, secret: int):
        self.p = p  # prime
        self.k = k  # threshold
        self.n = n
        self.secret = secret % p
        self.coeffs = [secret] + [secrets.randbelow(p - 2) + 1 for _ in range(k - 1)]
        self.shares = self.generate_shares()

    def generate_shares(self) -> List[Tuple[int, int]]:
        shares = []
        for i in range(self.n):
            x = i + 1  # uid
            y = 0
            for coeff in reversed(self.coeffs):
                y = (y * x + coeff) % self.p
            shares.append((x, y))
        return shares

    def reconstruct_secret(self, provided_shares: List[Tuple[int, int]]) -> int:
        if len(provided_shares) < self.k:
            raise ValueError("Insufficient number of participants.")

        x_s, y_s = zip(*shares)
        secret = 0

        for i in range(self.k):
            num = 1
            den = 1
            for j in range(self.k):
                if i == j:
                    continue
                num = (num * (0 - x_s[j])) % self.p
                den = (den * (x_s[i] - x_s[j])) % self.p

            inv_den = pow(den, -1, self.p)
            lagrange = (num * inv_den) % self.p

            secret = (secret + (y_s[i] * lagrange)) % self.p

        return secret


class WeightedShamirSecretSharing:
    '''
        Input *p* - prime number, greater than your *secret*;
        *T* - minimal total weight required to reconstruct the secret message;
        *weights* - weights of participants;
        *secret* - your secret message.
    '''
    def __init__(self, p: int, T: int, weights: List[int], secret: int):
        self.p = p  # prime
        self.T = T  # threshold
        self.weights = weights
        self.n = len(weights)
        self.secret = secret % p
        self.coeffs = [secret] + [secrets.randbelow(p - 2) + 1 for _ in range(T - 1)]
        self.shares = self.generate_shares()

    def evaluate_derivative(self, x: int, k: int) -> int:
        result = 0
        for j in range(k, self.T):
            term = self.coeffs[j]
            for i in range(k):
                term = term * (j - i) % self.p
            term = term * pow(x, j - k, self.p) % self.p
            result = (result + term) % self.p
        return result

    def generate_shares(self) -> List[Tuple[int, List[int]]]:
        shares = []
        for i, w in enumerate(self.weights):
            x = i + 1  # uid
            derivatives = [self.evaluate_derivative(x, k) for k in range(w)]
            shares.append((x, derivatives))
        return shares

    def reconstruct_secret(self, provided_shares: List[Tuple[int, List[int]]]) -> int:
        if sum(len(derivs) for _, derivs in provided_shares) < self.T:
            raise ValueError("Insufficient total weight of participants.")

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
            for r in range(col, len(matrix)):
                if matrix[r][col] % self.p != 0:
                    matrix[col], matrix[r] = matrix[r], matrix[col]
                    break

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
    secret = 123

    dealer = ShamirSecretSharing(p, 3, 5, secret)
    # successful reconstruction (3 participants)
    shares = [dealer.shares[0], dealer.shares[1], dealer.shares[2]]
    recovered = dealer.reconstruct_secret(shares)
    print("\033[1mShamir Secret Sharing\033[0m")
    print(f"Reconstructed secret: {recovered} (expected {secret})")
    # failed reconstruction (2 participants < k)
    try:
        shares = [dealer.shares[0], dealer.shares[1]]
        dealer.reconstruct_secret(shares)
    except ValueError as e:
        print(f"\033[91mExpected error: {e}\033[0m")


    wdealer = WeightedShamirSecretSharing(p, 5, [2, 1, 3], secret)
    # successful reconstruction (2+3>=5)
    shares = [wdealer.shares[0], wdealer.shares[2]]
    recovered = wdealer.reconstruct_secret(shares)
    print("\033[1mWeighted Shamir Secret Sharing\033[0m")
    print(f"Reconstructed secret: {recovered} (expected {secret})")
    # failed reconstruction (2+1<5)
    try:
        shares = [wdealer.shares[0], wdealer.shares[1]]
        wdealer.reconstruct_secret(shares)
    except ValueError as e:
        print(f"\033[91mExpected error: {e}\033[0m")

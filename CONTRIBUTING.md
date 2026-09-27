# Contributing to ReleaseIntegrityOracle

First off, thank you for considering contributing to ReleaseIntegrityOracle! 

## Development Setup

1. Clone the repository:
git clone https://github.com/dorinalunar/ReleaseIntegrityOracle.git
cd ReleaseIntegrityOracle

2. Set up a virtual environment:
python -m venv venv
source venv/bin/activate

3. Install dependencies:
pip install -r requirements.txt


## Running Tests

We use pytest for all smart contract simulations. All GenVM dependencies are mocked locally to ensure tests run fast and without network access.

pytest test_oracle.py -v


## Pull Request Process

1. Ensure your code strictly adheres to the Python 3.11 features supported by GenVM.
2. Run pytest and ensure all tests pass (including GitHub Actions CI).
3. If adding a new feature, include the corresponding test cases in test_oracle.py.
4. Update README.md if your PR changes the contract architecture or methods.
5. Submit the PR with a clear description of the problem and your solution.
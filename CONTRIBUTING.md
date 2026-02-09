# Contributing to LogLens

We love your input! We want to make contributing to LogLens as easy and transparent as possible.

## Development Process

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. Ensure the test suite passes
4. Make sure your code follows the existing style
5. Submit a pull request

## Setting Up Development Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/loglens
cd loglens

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (optional but recommended)
pre-commit install
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=loglens

# Run specific test file
pytest tests/test_parser.py

# Run only fast tests (skip slow/integration tests)
pytest -m "not slow"
```

## Code Style

We use:
- **Black** for code formatting
- **isort** for import sorting
- **mypy** for type checking
- **flake8** for linting

```bash
# Format code
black loglens/
isort loglens/

# Check types
mypy loglens/

# Lint
flake8 loglens/
```

## Pull Request Process

1. Update the README.md with details of changes if applicable
2. Update the docs/ with any new features
3. The PR title should follow conventional commits:
   - `feat:` for new features
   - `fix:` for bug fixes
   - `docs:` for documentation
   - `refactor:` for refactoring
   - `test:` for tests

## Adding New Features

### Adding a New Log Format

LogLens is designed to handle any log format without hardcoding. If you want to improve format detection:

1. Add test cases to `tests/test_detector.py`
2. The LLM should handle new formats automatically
3. If you need to add fallback heuristics, add them to `loglens/core/detector.py`

### Adding New Analysis Capabilities

1. Add the capability to `loglens/core/analyzer.py`
2. Update the prompts to include new security concepts
3. Add tests demonstrating the new capability

### Adding CLI Commands

1. Add the command to `loglens/cli.py`
2. Follow the existing command structure
3. Add usage examples to README.md

## Reporting Bugs

**Great Bug Reports** include:

- A quick summary and/or background
- Steps to reproduce
- What you expected would happen
- What actually happens
- Sample log data (if applicable, anonymized)
- Your environment (OS, Python version, etc.)

## Feature Requests

We love feature requests! Please:

1. Check if the feature already exists
2. Search existing issues to see if it's been requested
3. Create a new issue with:
   - Clear description of the feature
   - Why it would be useful
   - Example use cases

## Questions?

Feel free to:
- Open an issue
- Join our Slack (link TBD)
- Email: contact@humynx.com

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.

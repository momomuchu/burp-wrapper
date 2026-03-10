# Contributing

## Setup

```bash
git clone https://github.com/momomuchu/burp-wrapper.git
cd burp-wrapper
pip install -e ".[dev]"
```

## Workflow

1. Write tests first (`tests/tools/test_<tool>.py`)
2. Run tests to confirm they fail
3. Implement the tool module (`src/burp_wrapper/tools/<tool>.py`)
4. Run tests to confirm they pass
5. Lint with `ruff check src/ tests/`

## Adding a new tool

1. Create `src/burp_wrapper/tools/<tool>.py` extending `BaseTools`
2. Create `tests/tools/test_<tool>.py` with mocked API responses
3. Register the namespace in `client.py` as a `@cached_property`
4. Add to the table in `README.md`

## Tests

All tests mock the HTTP layer with `respx`. No running Burp instance needed.

```bash
pytest -v
```

## Code style

- Ruff for linting and formatting
- Type hints on all public methods
- Docstrings not required (method names are self-documenting)

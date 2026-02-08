After finishing a batch of changes, always run:
ruff check src/ tools/ test/
ruff format --check src/ tools/ test/
python3 -m pytest test

When writing tests, favor input/output results (integration) over specific implementation and number of calls. Avoid patching and mocking as much as possible.



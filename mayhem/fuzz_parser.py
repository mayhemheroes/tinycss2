#!/usr/bin/python3
import pdb

import atheris
from io import BytesIO
from contextlib import contextmanager
import logging
import sys

with atheris.instrument_imports():
    import tinycss2

# No logging
logging.disable(logging.CRITICAL)


# Disable stdout
@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = BytesIO()
    sys.stderr = BytesIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr

@atheris.instrument_func
def TestOneInput(data):
    # with nostdout():
    rules = tinycss2.parse_stylesheet_bytes(data)[0]
    for rule in rules:
        if isinstance(rule, tinycss2.ast.QualifiedRule):
            tinycss2.parse_declaration_list(rule.content)
            serialized = rule.serialize()



def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

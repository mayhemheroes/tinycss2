#!/usr/bin/python3
import atheris
from io import BytesIO
from contextlib import contextmanager
import logging
import sys

with atheris.instrument_imports():
    import tinycss2
    import tinycss2.ast
    import tinycss2.color3
    import tinycss2.nth

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


# @atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    with nostdout():
        rules = tinycss2.parse_stylesheet_bytes(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 10000)))[0]
        for rule in rules:
            if isinstance(rule, tinycss2.ast.QualifiedRule):
                tinycss2.parse_declaration_list(rule.content)
            if isinstance(rule, tinycss2.ast.Node) and not isinstance(rule, tinycss2.ast.ParseError):
                repr(rule.serialize())

        # Consume a string for parse_color
        color_css = fdp.ConsumeUnicode(25)
        # Consume a string for parse_nth
        nth_css = fdp.ConsumeUnicode(25)

        tinycss2.color3.parse_color(color_css)
        tinycss2.nth.parse_nth(nth_css)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

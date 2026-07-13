#!/usr/bin/python3
"""Atheris libFuzzer harness for tinycss2 (ported from the original integration).

Drives the stylesheet/declaration parsers, the serializer, and the color3/color4/color5
and nth micro-parsers.
"""
import atheris
import logging
import sys

with atheris.instrument_imports():
    import tinycss2
    import tinycss2.ast
    import tinycss2.color3
    import tinycss2.nth
    try:
        import tinycss2.color4
        import tinycss2.color5
    except ImportError:  # older tinycss2 without color4/color5
        tinycss2.color4 = None
        tinycss2.color5 = None

# No logging
logging.disable(logging.CRITICAL)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
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
    if tinycss2.color4 is not None:
        tinycss2.color4.parse_color(color_css)
    if tinycss2.color5 is not None:
        tinycss2.color5.parse_color(color_css)
    tinycss2.nth.parse_nth(nth_css)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

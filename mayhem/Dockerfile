# Build Stage
FROM fuzzers/atheris:2.0.7-python3.9

ADD . /src
WORKDIR /src
RUN python -m pip install .

CMD ["/src/mayhem/fuzz_stylesheet_parser.py"]
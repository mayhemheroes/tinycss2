# Build Stage
FROM fuzzers/atheris:2.0.7-python3.9

ADD ./mayhem/fuzz_parse.py /fuzz_parser.py
RUN pip install tinycss2

CMD ["/fuzz_parser.py"]

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ANALYZERS_DIR = os.path.join(BASE_DIR, "analyzers")

JAVASCRIPT_PARSER_PATH = os.path.join(ANALYZERS_DIR, "analyzer.js")
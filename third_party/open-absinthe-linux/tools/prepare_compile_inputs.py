#!/usr/bin/env python3
"""Materialize public legacy FairPlay compile inputs without downloading runtime resources."""

import argparse

from prepare_resources import prepare_fairplay


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    prepare_fairplay()

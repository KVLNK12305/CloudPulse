import pytest
import os
import sys

# Ensure services/detection-worker is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

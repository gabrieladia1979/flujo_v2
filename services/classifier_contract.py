"""Internal constants shared by classifier inference and audit tooling."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL_PATH = PROJECT_ROOT / "model" / "phisharg_xgboost.pkl"

# Preserve the existing production convention during the audit/evaluation stage.
# Training provenance is still required to prove the numeric label semantics.
PHISHING_CLASS_VALUE = 0
PRODUCTION_PHISHING_PROBABILITY_INDEX = 0

METADATA_FEATURE_COUNT = 3
SLOT_FEATURE_COUNT = 7
URL_FEATURE_COUNT = 11
READABILITY_FEATURE_COUNT = 1

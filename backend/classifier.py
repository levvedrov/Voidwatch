"""
RandomForest classifier trained on synthetic labeled process data.
Supplements rule-based scoring — does NOT replace it.

Pipeline:
  ProcessData → feature_vector → RF → malicious probability (0–1)
"""
from __future__ import annotations
import os
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import cross_val_predict
from sklearn.metrics import classification_report, confusion_matrix

from features import extract, FEATURE_NAMES

_DIR         = os.path.dirname(__file__)
MODEL_PATH   = os.path.join(_DIR, "voidwatch_rf.joblib")
SCALER_PATH  = os.path.join(_DIR, "voidwatch_scaler.joblib")
_VER_FILE    = os.path.join(_DIR, "voidwatch_model_ver.txt")
_MODEL_VER   = "v3-otrf"   # bump this whenever training data or features change

N_FEATURES = len(FEATURE_NAMES)
RNG = np.random.default_rng(42)

# Indices of continuous features that must NOT be binarized after noise injection
_CONTINUOUS_IDX = frozenset(
    i for i, name in enumerate(FEATURE_NAMES)
    if name in ("connection_count", "rule_score_norm")
)


# ---------------------------------------------------------------------------
# Synthetic training data
# ---------------------------------------------------------------------------

def _noise(n: int, scale: float = 0.08) -> np.ndarray:
    return RNG.normal(0, scale, (n, N_FEATURES))


def _repeat(template: list[float], n: int) -> np.ndarray:
    base = np.tile(template, (n, 1)).astype(float)
    noisy = np.clip(base + _noise(n), 0, None)
    for i in range(N_FEATURES):
        if i not in _CONTINUOUS_IDX:
            noisy[:, i] = (noisy[:, i] > 0.5).astype(float)
    return noisy


# Feature index map for readability
_F = {name: i for i, name in enumerate(FEATURE_NAMES)}


def _malicious_samples() -> np.ndarray:
    blocks = []

    # Office → PowerShell + encoded + network
    t = [0.0] * N_FEATURES
    t[_F["is_powershell"]] = 1; t[_F["has_encoded_cmd"]] = 1
    t[_F["is_office_parent"]] = 1; t[_F["connection_count"]] = 5
    t[_F["rule_score_norm"]] = 0.85
    blocks.append(_repeat(t, 120))

    # PS + encoded + EP bypass + hidden
    t = [0.0] * N_FEATURES
    t[_F["is_powershell"]] = 1; t[_F["has_encoded_cmd"]] = 1
    t[_F["has_ep_bypass"]] = 1; t[_F["has_hidden_window"]] = 1
    t[_F["rule_score_norm"]] = 0.75
    blocks.append(_repeat(t, 100))

    # PS + download + IEX + network
    t = [0.0] * N_FEATURES
    t[_F["is_powershell"]] = 1; t[_F["has_download_cmd"]] = 1
    t[_F["has_iex"]] = 1; t[_F["connection_count"]] = 3
    t[_F["rule_score_norm"]] = 0.80
    blocks.append(_repeat(t, 100))

    # mshta + network
    t = [0.0] * N_FEATURES
    t[_F["is_mshta"]] = 1; t[_F["connection_count"]] = 2
    t[_F["rule_score_norm"]] = 0.60
    blocks.append(_repeat(t, 80))

    # certutil download
    t = [0.0] * N_FEATURES
    t[_F["is_certutil"]] = 1; t[_F["has_download_cmd"]] = 1
    t[_F["rule_score_norm"]] = 0.55
    blocks.append(_repeat(t, 70))

    # regsvr32 Squiblydoo
    t = [0.0] * N_FEATURES
    t[_F["is_regsvr32"]] = 1; t[_F["connection_count"]] = 1
    t[_F["rule_score_norm"]] = 0.62
    blocks.append(_repeat(t, 70))

    # Unsigned + Temp + network
    t = [0.0] * N_FEATURES
    t[_F["from_temp"]] = 1; t[_F["connection_count"]] = 4
    t[_F["rule_score_norm"]] = 0.72; t[_F["is_signed"]] = 0
    blocks.append(_repeat(t, 80))

    # Registry persistence
    t = [0.0] * N_FEATURES
    t[_F["has_registry_persist"]] = 1
    t[_F["rule_score_norm"]] = 0.68
    blocks.append(_repeat(t, 70))

    # Scheduled task
    t = [0.0] * N_FEATURES
    t[_F["has_sched_task"]] = 1
    t[_F["rule_score_norm"]] = 0.62
    blocks.append(_repeat(t, 60))

    # Downloads + unsigned + network
    t = [0.0] * N_FEATURES
    t[_F["from_downloads"]] = 1; t[_F["connection_count"]] = 3
    t[_F["has_suspicious_port"]] = 1
    t[_F["rule_score_norm"]] = 0.70
    blocks.append(_repeat(t, 80))

    return np.vstack(blocks)


def _benign_samples() -> np.ndarray:
    blocks = []

    # Chrome
    t = [0.0] * N_FEATURES
    t[_F["from_program_files"]] = 1; t[_F["is_signed"]] = 1
    t[_F["connection_count"]] = 8; t[_F["is_browser_parent"]] = 0
    t[_F["rule_score_norm"]] = 0.02
    blocks.append(_repeat(t, 200))

    # svchost (System32, signed)
    t = [0.0] * N_FEATURES
    t[_F["from_system32"]] = 1; t[_F["is_signed"]] = 1
    t[_F["connection_count"]] = 2
    t[_F["rule_score_norm"]] = 0.01
    blocks.append(_repeat(t, 200))

    # explorer.exe
    t = [0.0] * N_FEATURES
    t[_F["from_system32"]] = 1; t[_F["is_signed"]] = 1
    t[_F["connection_count"]] = 0
    t[_F["rule_score_norm"]] = 0.0
    blocks.append(_repeat(t, 150))

    # VS Code / IDE (Program Files, signed, some network)
    t = [0.0] * N_FEATURES
    t[_F["from_program_files"]] = 1; t[_F["is_signed"]] = 1
    t[_F["connection_count"]] = 3
    t[_F["rule_score_norm"]] = 0.03
    blocks.append(_repeat(t, 150))

    # PowerShell normal (signed, System32, no flags)
    t = [0.0] * N_FEATURES
    t[_F["is_powershell"]] = 1; t[_F["from_system32"]] = 1
    t[_F["is_signed"]] = 1; t[_F["connection_count"]] = 0
    t[_F["rule_score_norm"]] = 0.10
    blocks.append(_repeat(t, 120))

    # Notepad, calc, etc.
    t = [0.0] * N_FEATURES
    t[_F["from_system32"]] = 1; t[_F["is_signed"]] = 1
    t[_F["rule_score_norm"]] = 0.0
    blocks.append(_repeat(t, 150))

    # Signed app with moderate network (Teams, Slack, etc.)
    t = [0.0] * N_FEATURES
    t[_F["from_program_files"]] = 1; t[_F["is_signed"]] = 1
    t[_F["connection_count"]] = 6
    t[_F["rule_score_norm"]] = 0.04
    blocks.append(_repeat(t, 130))

    return np.vstack(blocks)


# ---------------------------------------------------------------------------
# Classifier class
# ---------------------------------------------------------------------------

class ProcessClassifier:
    def __init__(self):
        self.rf: RandomForestClassifier | None = None
        self.scaler: StandardScaler | None = None

    def train(self) -> None:
        # train_otrf._load_folder() has the full OTRF parser (winlogbeat format,
        # tar.gz, EventID 5156, SHA256, ambiguous-label filtering).
        # Import locally so the module's sys.path.insert doesn't run at import time.
        from train_otrf import ATTACK_DIR, BENIGN_DIR, _load_folder

        X_syn_mal = _malicious_samples()
        X_syn_ben = _benign_samples()
        y_syn_mal = np.ones(len(X_syn_mal),  dtype=int)
        y_syn_ben = np.zeros(len(X_syn_ben), dtype=int)

        print("\n[classifier] Loading OTRF attack datasets …")
        X_atk, y_atk = _load_folder(ATTACK_DIR, fixed_label=None)

        print("[classifier] Loading OTRF benign datasets …")
        X_ben_otrf, y_ben_otrf = _load_folder(BENIGN_DIR, fixed_label=0)

        parts_X = [X_syn_mal, X_syn_ben]
        parts_y = [y_syn_mal, y_syn_ben]
        if X_atk.size:
            parts_X.append(X_atk)
            parts_y.append(y_atk)
        if X_ben_otrf.size:
            parts_X.append(X_ben_otrf)
            parts_y.append(y_ben_otrf)

        X = np.vstack(parts_X)
        y = np.concatenate(parts_y)

        mal_n = int(y.sum())
        ben_n = len(y) - mal_n
        print(f"[classifier] Total: {len(y)} samples ({mal_n} malicious / {ben_n} benign)")
        self.train_on(X, y)

    def train_on(self, X: np.ndarray, y: np.ndarray) -> None:
        """Fit on any externally supplied feature matrix and labels."""
        self.scaler = StandardScaler()
        X_s = self.scaler.fit_transform(X)

        self.rf = RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            min_samples_leaf=3,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self.rf.fit(X_s, y)

        # 5-fold cross-validated metrics
        y_pred = cross_val_predict(self.rf, X_s, y, cv=5)
        print("\n── Classifier metrics (5-fold CV) ──────────────────")
        print(classification_report(y, y_pred, target_names=["benign", "malicious"], digits=3))
        cm = confusion_matrix(y, y_pred)
        print(f"Confusion matrix:\n  TN={cm[0,0]}  FP={cm[0,1]}\n  FN={cm[1,0]}  TP={cm[1,1]}\n")

        joblib.dump(self.rf,     MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)

    def load_or_train(self) -> None:
        stored_ver = ""
        if os.path.exists(_VER_FILE):
            with open(_VER_FILE, encoding="utf-8") as f:
                stored_ver = f.read().strip()

        if (os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH)
                and stored_ver == _MODEL_VER):
            self.rf     = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
        else:
            self.train()
            with open(_VER_FILE, "w", encoding="utf-8") as f:
                f.write(_MODEL_VER)

    def predict_proba(self, proc, rule_score: float = 0.0) -> float:
        if self.rf is None or self.scaler is None:
            return 0.0
        vec = np.array([extract(proc, rule_score)])
        vec_s = self.scaler.transform(vec)
        return float(self.rf.predict_proba(vec_s)[0][1])

    def feature_importances(self) -> dict[str, float]:
        if self.rf is None:
            return {}
        return dict(zip(FEATURE_NAMES, self.rf.feature_importances_.tolist()))


classifier = ProcessClassifier()

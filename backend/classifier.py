"""
RandomForest classifier trained on synthetic labeled process data.
Supplements rule-based scoring — does NOT replace it.

Pipeline:
  ProcessData → feature_vector → RF → malicious probability (0–1)
"""
from __future__ import annotations
import csv
import datetime
import logging
import os
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import classification_report, confusion_matrix

from features import extract, FEATURE_NAMES

_DIR         = os.path.dirname(__file__)
_MODEL_DIR   = os.path.join(_DIR, "model")
MODEL_PATH   = os.path.join(_MODEL_DIR, "voidwatch_rf.joblib")
SCALER_PATH  = os.path.join(_MODEL_DIR, "voidwatch_scaler.joblib")
_VER_FILE    = os.path.join(_MODEL_DIR, "voidwatch_model_ver.txt")
_MODEL_VER   = "v4-behavioral"

_STATS_DIR        = os.path.join(_DIR, "stats")
_STATS_CSV        = os.path.join(_STATS_DIR, "training_history.csv")
_STATS_GRAPH      = os.path.join(_STATS_DIR, "training_curves.png")
_FEAT_IMP_GRAPH   = os.path.join(_STATS_DIR, "feature_importance.png")

_CSV_FIELDS = [
    "session", "timestamp",
    "n_train", "n_train_mal", "n_train_ben",
    "n_test",  "n_test_mal",  "n_test_ben", "n_test_scenarios", "is_scenario_eval",
    "precision_mal", "recall_mal", "f1_mal",
    "precision_ben", "recall_ben", "f1_ben",
    "accuracy", "tn", "fp", "fn", "tp",
]

N_FEATURES = len(FEATURE_NAMES)
RNG = np.random.default_rng(42)

# Only connection_count is continuous — rule_score_norm removed
_CONTINUOUS_IDX = frozenset(
    i for i, name in enumerate(FEATURE_NAMES)
    if name == "connection_count"
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
    blocks.append(_repeat(t, 120))

    # PS + encoded + EP bypass + hidden
    t = [0.0] * N_FEATURES
    t[_F["is_powershell"]] = 1; t[_F["has_encoded_cmd"]] = 1
    t[_F["has_ep_bypass"]] = 1; t[_F["has_hidden_window"]] = 1
    blocks.append(_repeat(t, 100))

    # PS + download + IEX + network
    t = [0.0] * N_FEATURES
    t[_F["is_powershell"]] = 1; t[_F["has_download_cmd"]] = 1
    t[_F["has_iex"]] = 1; t[_F["connection_count"]] = 3
    blocks.append(_repeat(t, 100))

    # mshta + network
    t = [0.0] * N_FEATURES
    t[_F["is_mshta"]] = 1; t[_F["connection_count"]] = 2
    blocks.append(_repeat(t, 80))

    # certutil download
    t = [0.0] * N_FEATURES
    t[_F["is_certutil"]] = 1; t[_F["has_download_cmd"]] = 1
    blocks.append(_repeat(t, 70))

    # regsvr32 Squiblydoo
    t = [0.0] * N_FEATURES
    t[_F["is_regsvr32"]] = 1; t[_F["connection_count"]] = 1
    blocks.append(_repeat(t, 70))

    # Unsigned + Temp + network
    t = [0.0] * N_FEATURES
    t[_F["from_temp"]] = 1; t[_F["connection_count"]] = 4; t[_F["is_signed"]] = 0
    blocks.append(_repeat(t, 80))

    # Registry persistence
    t = [0.0] * N_FEATURES
    t[_F["has_registry_persist"]] = 1
    blocks.append(_repeat(t, 70))

    # Scheduled task
    t = [0.0] * N_FEATURES
    t[_F["has_sched_task"]] = 1
    blocks.append(_repeat(t, 60))

    # Downloads + unsigned + network
    t = [0.0] * N_FEATURES
    t[_F["from_downloads"]] = 1; t[_F["connection_count"]] = 3
    t[_F["has_suspicious_port"]] = 1
    blocks.append(_repeat(t, 80))

    return np.vstack(blocks)


def _benign_samples() -> np.ndarray:
    blocks = []

    # Chrome / browser
    t = [0.0] * N_FEATURES
    t[_F["from_program_files"]] = 1; t[_F["is_signed"]] = 1
    t[_F["connection_count"]] = 8
    blocks.append(_repeat(t, 200))

    # svchost (System32, signed)
    t = [0.0] * N_FEATURES
    t[_F["from_system32"]] = 1; t[_F["is_signed"]] = 1
    t[_F["connection_count"]] = 2
    blocks.append(_repeat(t, 200))

    # explorer.exe
    t = [0.0] * N_FEATURES
    t[_F["from_system32"]] = 1; t[_F["is_signed"]] = 1
    t[_F["connection_count"]] = 0
    blocks.append(_repeat(t, 150))

    # VS Code / IDE (Program Files, signed, some network)
    t = [0.0] * N_FEATURES
    t[_F["from_program_files"]] = 1; t[_F["is_signed"]] = 1
    t[_F["connection_count"]] = 3
    blocks.append(_repeat(t, 150))

    # PowerShell normal (signed, System32, no flags)
    t = [0.0] * N_FEATURES
    t[_F["is_powershell"]] = 1; t[_F["from_system32"]] = 1
    t[_F["is_signed"]] = 1; t[_F["connection_count"]] = 0
    blocks.append(_repeat(t, 120))

    # Notepad, calc, system utilities
    t = [0.0] * N_FEATURES
    t[_F["from_system32"]] = 1; t[_F["is_signed"]] = 1
    blocks.append(_repeat(t, 150))

    # Teams / Slack / signed apps with network
    t = [0.0] * N_FEATURES
    t[_F["from_program_files"]] = 1; t[_F["is_signed"]] = 1
    t[_F["connection_count"]] = 6
    blocks.append(_repeat(t, 130))

    return np.vstack(blocks)


# ---------------------------------------------------------------------------
# Training stats helpers
# ---------------------------------------------------------------------------

def _save_training_stats(
    report: dict, cm: np.ndarray,
    n_train: int, n_train_mal: int, n_train_ben: int,
    n_test: int,  n_test_mal: int,  n_test_ben: int,
    n_test_scenarios: int, is_scenario_eval: bool,
    importances: dict[str, float],
) -> None:
    os.makedirs(_STATS_DIR, exist_ok=True)

    rows: list[dict] = []
    if os.path.exists(_STATS_CSV):
        with open(_STATS_CSV, newline="", encoding="utf-8") as f:
            existing = list(csv.DictReader(f))
            # discard rows from an older schema
            if existing and "n_train" in existing[0]:
                rows = existing

    session = int(rows[-1]["session"]) + 1 if rows else 1
    mal = report.get("malicious", {})
    ben = report.get("benign", {})
    rows.append({
        "session":          session,
        "timestamp":        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "n_train":          n_train,
        "n_train_mal":      n_train_mal,
        "n_train_ben":      n_train_ben,
        "n_test":           n_test,
        "n_test_mal":       n_test_mal,
        "n_test_ben":       n_test_ben,
        "n_test_scenarios": n_test_scenarios,
        "is_scenario_eval": int(is_scenario_eval),
        "precision_mal":    round(mal.get("precision", 0), 4),
        "recall_mal":       round(mal.get("recall", 0), 4),
        "f1_mal":           round(mal.get("f1-score", 0), 4),
        "precision_ben":    round(ben.get("precision", 0), 4),
        "recall_ben":       round(ben.get("recall", 0), 4),
        "f1_ben":           round(ben.get("f1-score", 0), 4),
        "accuracy":         round(report.get("accuracy", 0), 4),
        "tn":               int(cm[0, 0]),
        "fp":               int(cm[0, 1]),
        "fn":               int(cm[1, 0]),
        "tp":               int(cm[1, 1]),
    })

    with open(_STATS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    _plot_training_curves(rows)
    _plot_feature_importance(importances)
    print(f"[stats] Results    → {_STATS_CSV}")
    print(f"[stats] Curves     → {_STATS_GRAPH}")
    print(f"[stats] Importance → {_FEAT_IMP_GRAPH}")


def _plot_training_curves(rows: list[dict]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker

    sessions = [int(r["session"]) for r in rows]
    scenario_mask = [int(r.get("is_scenario_eval", 0)) for r in rows]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 9), sharex=True)
    fig.patch.set_facecolor("#0d0d0d")
    for ax in (ax1, ax2):
        ax.set_facecolor("#1a1a1a")
        ax.tick_params(colors="#cccccc")
        for spine in ax.spines.values():
            spine.set_color("#444444")

    # ── top: test-set metrics (solid = scenario eval, dashed = train fallback) ──
    prec = [float(r["precision_mal"]) for r in rows]
    rec  = [float(r["recall_mal"])    for r in rows]
    f1   = [float(r["f1_mal"])        for r in rows]
    for i, (s, p, r, f, sc) in enumerate(zip(sessions, prec, rec, f1, scenario_mask)):
        ls = "-" if sc else "--"
        mk = "o" if sc else "s"
        ax1.plot([s], [p], marker=mk, color="#4fc3f7", linestyle=ls, markersize=7, linewidth=2)
        ax1.plot([s], [r], marker=mk, color="#81c784", linestyle=ls, markersize=7, linewidth=2)
        ax1.plot([s], [f], marker=mk, color="#ffb74d", linestyle=ls, markersize=7, linewidth=2)
    if len(sessions) > 1:
        ax1.plot(sessions, prec, color="#4fc3f7", linewidth=1.5, alpha=0.6)
        ax1.plot(sessions, rec,  color="#81c784", linewidth=1.5, alpha=0.6)
        ax1.plot(sessions, f1,   color="#ffb74d", linewidth=1.5, alpha=0.6)
    from matplotlib.lines import Line2D
    legend_els = [
        Line2D([0],[0], color="#4fc3f7", marker="o", label="Precision"),
        Line2D([0],[0], color="#81c784", marker="o", label="Recall"),
        Line2D([0],[0], color="#ffb74d", marker="o", label="F1"),
        Line2D([0],[0], color="#888888", linestyle="-",  marker="o", label="Scenario eval"),
        Line2D([0],[0], color="#888888", linestyle="--", marker="s", label="Train fallback"),
    ]
    ax1.set_ylabel("Score", color="#cccccc")
    ax1.set_ylim(0, 1.05)
    ax1.set_title("Malicious class — held-out evaluation per session",
                  color="#ffffff", pad=8)
    ax1.legend(handles=legend_els, facecolor="#2a2a2a",
               labelcolor="#cccccc", edgecolor="#444444", fontsize=8)
    ax1.yaxis.set_major_formatter(ticker.FormatStrFormatter("%.2f"))
    ax1.grid(True, color="#333333", linestyle="--", alpha=0.6)

    # ── bottom: train vs test sample counts ──
    width = 0.2
    x = np.array(sessions, dtype=float)
    ax2.bar(x - 1.5*width, [int(r["n_train_mal"]) for r in rows], width, color="#ef5350", alpha=0.85, label="Train mal")
    ax2.bar(x - 0.5*width, [int(r["n_train_ben"]) for r in rows], width, color="#42a5f5", alpha=0.85, label="Train ben")
    ax2.bar(x + 0.5*width, [int(r.get("n_test_mal", 0)) for r in rows], width, color="#ef9a9a", alpha=0.85, label="Test mal")
    ax2.bar(x + 1.5*width, [int(r.get("n_test_ben", 0)) for r in rows], width, color="#90caf9", alpha=0.85, label="Test ben")
    ax2.set_xlabel("Session", color="#cccccc")
    ax2.set_ylabel("Samples", color="#cccccc")
    ax2.set_title("Train / test sample counts per session", color="#ffffff", pad=8)
    ax2.legend(facecolor="#2a2a2a", labelcolor="#cccccc", edgecolor="#444444", fontsize=8)
    ax2.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax2.grid(True, axis="y", color="#333333", linestyle="--", alpha=0.6)

    plt.tight_layout(pad=2.0)
    plt.savefig(_STATS_GRAPH, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)


def _plot_feature_importance(importances: dict[str, float]) -> None:
    if not importances:
        return
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    names  = list(importances.keys())
    values = list(importances.values())
    order  = sorted(range(len(values)), key=lambda i: values[i])
    names  = [names[i]  for i in order]
    values = [values[i] for i in order]

    fig, ax = plt.subplots(figsize=(9, 7))
    fig.patch.set_facecolor("#0d0d0d")
    ax.set_facecolor("#1a1a1a")
    ax.tick_params(colors="#cccccc")
    for spine in ax.spines.values():
        spine.set_color("#444444")

    colors = ["#ef5350" if v > 0.06 else "#42a5f5" if v > 0.03 else "#78909c" for v in values]
    ax.barh(names, values, color=colors, alpha=0.85)
    ax.set_xlabel("Importance", color="#cccccc")
    ax.set_title("Feature importances — current model", color="#ffffff", pad=8)
    ax.grid(True, axis="x", color="#333333", linestyle="--", alpha=0.6)

    plt.tight_layout(pad=1.5)
    plt.savefig(_FEAT_IMP_GRAPH, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)


# ---------------------------------------------------------------------------
# Classifier class
# ---------------------------------------------------------------------------

class ProcessClassifier:
    def __init__(self):
        self.rf: RandomForestClassifier | None = None
        self.scaler: StandardScaler | None = None

    def train(self) -> None:
        from train import ATTACK_DIR, BENIGN_DIR, _load_folder

        X_syn_mal = _malicious_samples()
        X_syn_ben = _benign_samples()
        y_syn_mal = np.ones(len(X_syn_mal),  dtype=int)
        y_syn_ben = np.zeros(len(X_syn_ben), dtype=int)

        print("\n[classifier] Loading OTRF attack datasets …")
        X_atk, y_atk, scen_atk = _load_folder(ATTACK_DIR, fixed_label=1)

        print("[classifier] Loading OTRF benign datasets …")
        X_ben_otrf, y_ben_otrf, scen_ben = _load_folder(BENIGN_DIR, fixed_label=0)

        X_test_parts: list[np.ndarray] = []
        y_test_parts: list[np.ndarray] = []
        test_scens:   list[str]        = []
        X_train_parts = [X_syn_mal, X_syn_ben]
        y_train_parts = [y_syn_mal, y_syn_ben]

        def _scenario_split(X, y, scens, label_prefix=""):
            unique = list(set(scens))
            if len(unique) < 2:
                X_train_parts.append(X); y_train_parts.append(y); return
            test_frac = max(1 / len(unique), 0.2)
            gss = GroupShuffleSplit(n_splits=1, test_size=test_frac, random_state=42)
            tr_idx, te_idx = next(gss.split(X, y, groups=scens))
            X_test_parts.append(X[te_idx]); y_test_parts.append(y[te_idx])
            test_scens.extend(label_prefix + scens[i] for i in te_idx)
            X_train_parts.append(X[tr_idx]); y_train_parts.append(y[tr_idx])

        if X_atk.size:
            _scenario_split(X_atk, y_atk, scen_atk)
        if X_ben_otrf.size:
            _scenario_split(X_ben_otrf, y_ben_otrf, scen_ben, label_prefix="ben_")

        X_test = np.vstack(X_test_parts)     if X_test_parts else None
        y_test = np.concatenate(y_test_parts) if y_test_parts else None

        X = np.vstack(X_train_parts)
        y = np.concatenate(y_train_parts)
        mal_n = int(y.sum()); ben_n = len(y) - mal_n
        print(f"[classifier] Training: {len(y)} samples ({mal_n} mal / {ben_n} ben)")
        self.train_on(X, y, X_test, y_test, test_scens)

    def train_on(
        self,
        X_train:        np.ndarray,
        y_train:        np.ndarray,
        X_test:         np.ndarray | None = None,
        y_test:         np.ndarray | None = None,
        test_scenarios: list[str]  | None = None,
    ) -> None:
        self.scaler = StandardScaler()
        X_s = self.scaler.fit_transform(X_train)

        self.rf = RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            min_samples_leaf=3,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self.rf.fit(X_s, y_train)

        has_test = X_test is not None and len(X_test) > 0
        if has_test:
            X_te_s = self.scaler.transform(X_test)
            y_pred = self.rf.predict(X_te_s)
            eval_y_true = y_test
            header = "── Held-out scenario evaluation ──────────────────"
            if test_scenarios:
                unique = sorted(set(test_scenarios))
                print(f"\n[classifier] Test scenarios ({len(unique)}): {', '.join(unique)}")
        else:
            y_pred     = self.rf.predict(X_s)
            eval_y_true = y_train
            header     = "── Training-set evaluation (no held-out scenarios) ─"

        report_str  = classification_report(eval_y_true, y_pred, target_names=["benign", "malicious"], digits=3, zero_division=0)
        report_dict = classification_report(eval_y_true, y_pred, target_names=["benign", "malicious"], output_dict=True, zero_division=0)
        cm          = confusion_matrix(eval_y_true, y_pred)
        print(f"\n{header}")
        print(report_str)
        print(f"Confusion matrix:\n  TN={cm[0,0]}  FP={cm[0,1]}\n  FN={cm[1,0]}  TP={cm[1,1]}\n")

        os.makedirs(_MODEL_DIR, exist_ok=True)
        joblib.dump(self.rf,     MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)

        n_train_mal = int(y_train.sum())
        n_test      = len(X_test)  if has_test else 0
        n_test_mal  = int(y_test.sum()) if has_test else 0
        _save_training_stats(
            report_dict, cm,
            len(y_train), n_train_mal, len(y_train) - n_train_mal,
            n_test, n_test_mal, n_test - n_test_mal,
            len(set(test_scenarios)) if test_scenarios else 0,
            has_test,
            self.feature_importances(),
        )

    def load(self) -> None:
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            self.rf     = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
        else:
            logging.getLogger(__name__).warning("Model not found — run train.py to generate it")

    def predict_proba(self, proc) -> float:
        if self.rf is None or self.scaler is None:
            return 0.0
        vec   = np.array([extract(proc)])
        vec_s = self.scaler.transform(vec)
        return float(self.rf.predict_proba(vec_s)[0][1])

    def feature_importances(self) -> dict[str, float]:
        if self.rf is None:
            return {}
        return dict(zip(FEATURE_NAMES, self.rf.feature_importances_.tolist()))


classifier = ProcessClassifier()

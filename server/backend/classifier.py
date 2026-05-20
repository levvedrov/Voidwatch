"""
HistGradientBoosting classifier trained on synthetic labeled process data.
Supplements rule-based scoring — does NOT replace it.

Pipeline:
  ProcessData → feature_vector → HistGBT → malicious probability (0–1)
"""
from __future__ import annotations
import csv
import datetime
import logging
import os
import numpy as np
import joblib
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, average_precision_score,
    roc_curve, precision_recall_curve,
)

from features import extract, FEATURE_NAMES

_DIR             = os.path.dirname(__file__)
_MODEL_DIR       = os.path.join(_DIR, "model")
MODEL_PATH       = os.path.join(_MODEL_DIR, "voidwatch_model.joblib")
SCALER_PATH      = os.path.join(_MODEL_DIR, "voidwatch_scaler.joblib")
CALIBRATOR_PATH  = os.path.join(_MODEL_DIR, "voidwatch_calibrator.joblib")
_VER_FILE        = os.path.join(_MODEL_DIR, "voidwatch_model_ver.txt")
_MODEL_VER       = "v5-hgbt"

_STATS_DIR        = os.path.join(_DIR, "stats")
os.makedirs(_STATS_DIR, exist_ok=True)
_STATS_CSV        = os.path.join(_STATS_DIR, "training_history.csv")
_STATS_GRAPH      = os.path.join(_STATS_DIR, "training_curves.png")
_FEAT_IMP_GRAPH   = os.path.join(_STATS_DIR, "feature_importance.png")
_ROC_PR_GRAPH     = os.path.join(_STATS_DIR, "roc_pr_curves.png")

_CSV_FIELDS = [
    "session", "timestamp",
    "n_train", "n_train_mal", "n_train_ben",
    "n_test",  "n_test_mal",  "n_test_ben", "n_test_scenarios", "is_scenario_eval",
    "precision_mal", "recall_mal", "f1_mal",
    "precision_ben", "recall_ben", "f1_ben",
    "accuracy", "roc_auc", "avg_precision",
    "tn", "fp", "fn", "tp",
]





# ---------------------------------------------------------------------------
# Training stats helpers
# ---------------------------------------------------------------------------

def _save_training_stats(
    report: dict, cm: np.ndarray,
    n_train: int, n_train_mal: int, n_train_ben: int,
    n_test: int,  n_test_mal: int,  n_test_ben: int,
    n_test_scenarios: int, is_scenario_eval: bool,
    importances: dict[str, float],
    roc_auc: float = 0.0,
    avg_precision: float = 0.0,
) -> None:
    os.makedirs(_STATS_DIR, exist_ok=True)

    rows: list[dict] = []
    if os.path.exists(_STATS_CSV):
        with open(_STATS_CSV, newline="", encoding="utf-8") as f:
            existing = list(csv.DictReader(f))
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
        "roc_auc":          round(roc_auc, 4),
        "avg_precision":    round(avg_precision, 4),
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

    sessions      = [int(r["session"]) for r in rows]
    scenario_mask = [int(r.get("is_scenario_eval", 0)) for r in rows]

    fig, axes = plt.subplots(3, 1, figsize=(10, 13), sharex=True)
    ax1, ax2, ax3 = axes
    fig.patch.set_facecolor("#0d0d0d")
    for ax in axes:
        ax.set_facecolor("#1a1a1a")
        ax.tick_params(colors="#cccccc")
        for spine in ax.spines.values():
            spine.set_color("#444444")

    # ── top: precision / recall / F1 ──
    prec = [float(r["precision_mal"]) for r in rows]
    rec  = [float(r["recall_mal"])    for r in rows]
    f1   = [float(r["f1_mal"])        for r in rows]
    for s, p, r, f, sc in zip(sessions, prec, rec, f1, scenario_mask):
        ls = "-"; mk = "o" if sc else "s"
        ax1.plot([s], [p], marker=mk, color="#4fc3f7", linestyle=ls, markersize=7, linewidth=2)
        ax1.plot([s], [r], marker=mk, color="#81c784", linestyle=ls, markersize=7, linewidth=2)
        ax1.plot([s], [f], marker=mk, color="#ffb74d", linestyle=ls, markersize=7, linewidth=2)
    if len(sessions) > 1:
        ax1.plot(sessions, prec, color="#4fc3f7", linewidth=1.5, alpha=0.6)
        ax1.plot(sessions, rec,  color="#81c784", linewidth=1.5, alpha=0.6)
        ax1.plot(sessions, f1,   color="#ffb74d", linewidth=1.5, alpha=0.6)
    from matplotlib.lines import Line2D
    ax1.legend(handles=[
        Line2D([0],[0], color="#4fc3f7", marker="o", label="Precision"),
        Line2D([0],[0], color="#81c784", marker="o", label="Recall"),
        Line2D([0],[0], color="#ffb74d", marker="o", label="F1"),
    ], facecolor="#2a2a2a", labelcolor="#cccccc", edgecolor="#444444", fontsize=8)
    ax1.set_ylabel("Score", color="#cccccc")
    ax1.set_ylim(0, 1.05)
    ax1.set_title("Malicious class — precision / recall / F1 per session",
                  color="#ffffff", pad=8)
    ax1.yaxis.set_major_formatter(ticker.FormatStrFormatter("%.2f"))
    ax1.grid(True, color="#333333", linestyle="--", alpha=0.6)

    # ── middle: AUC-ROC and AUC-PR trend ──
    roc_aucs = [float(r.get("roc_auc") or 0) for r in rows]
    avg_precs = [float(r.get("avg_precision") or 0) for r in rows]
    for s, ra, ap, sc in zip(sessions, roc_aucs, avg_precs, scenario_mask):
        mk = "o" if sc else "s"
        ax2.plot([s], [ra], marker=mk, color="#ce93d8", markersize=7, linewidth=2)
        ax2.plot([s], [ap], marker=mk, color="#f48fb1", markersize=7, linewidth=2)
    if len(sessions) > 1:
        ax2.plot(sessions, roc_aucs,  color="#ce93d8", linewidth=1.5, alpha=0.6)
        ax2.plot(sessions, avg_precs, color="#f48fb1", linewidth=1.5, alpha=0.6)
    ax2.legend(handles=[
        Line2D([0],[0], color="#ce93d8", marker="o", label="AUC-ROC"),
        Line2D([0],[0], color="#f48fb1", marker="o", label="AUC-PR"),
    ], facecolor="#2a2a2a", labelcolor="#cccccc", edgecolor="#444444", fontsize=8)
    ax2.set_ylabel("Score", color="#cccccc")
    ax2.set_ylim(0, 1.05)
    ax2.set_title("AUC-ROC and AUC-PR per session", color="#ffffff", pad=8)
    ax2.yaxis.set_major_formatter(ticker.FormatStrFormatter("%.2f"))
    ax2.grid(True, color="#333333", linestyle="--", alpha=0.6)

    # ── bottom: train vs test sample counts ──
    width = 0.2
    x = np.array(sessions, dtype=float)
    ax3.bar(x - 1.5*width, [int(r["n_train_mal"]) for r in rows], width, color="#ef5350", alpha=0.85, label="Train mal")
    ax3.bar(x - 0.5*width, [int(r["n_train_ben"]) for r in rows], width, color="#42a5f5", alpha=0.85, label="Train ben")
    ax3.bar(x + 0.5*width, [int(r.get("n_test_mal", 0)) for r in rows], width, color="#ef9a9a", alpha=0.85, label="Test mal")
    ax3.bar(x + 1.5*width, [int(r.get("n_test_ben", 0)) for r in rows], width, color="#90caf9", alpha=0.85, label="Test ben")
    ax3.set_xlabel("Session", color="#cccccc")
    ax3.set_ylabel("Samples", color="#cccccc")
    ax3.set_title("Train / test sample counts per session", color="#ffffff", pad=8)
    ax3.legend(facecolor="#2a2a2a", labelcolor="#cccccc", edgecolor="#444444", fontsize=8)
    ax3.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax3.grid(True, axis="y", color="#333333", linestyle="--", alpha=0.6)

    plt.tight_layout(pad=2.0)
    plt.savefig(_STATS_GRAPH, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)


def _plot_roc_pr(y_true: np.ndarray, y_proba: np.ndarray) -> None:
    """Save ROC and PR curves for the most recent evaluation set."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fpr, tpr, _ = roc_curve(y_true, y_proba)
    prec, rec, _ = precision_recall_curve(y_true, y_proba)
    auc_roc = roc_auc_score(y_true, y_proba)
    auc_pr  = average_precision_score(y_true, y_proba)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.patch.set_facecolor("#0d0d0d")
    for ax in (ax1, ax2):
        ax.set_facecolor("#1a1a1a")
        ax.tick_params(colors="#cccccc")
        for spine in ax.spines.values():
            spine.set_color("#444444")

    ax1.plot(fpr, tpr, color="#4fc3f7", linewidth=2, label=f"AUC-ROC = {auc_roc:.3f}")
    ax1.plot([0, 1], [0, 1], color="#555555", linestyle="--", linewidth=1)
    ax1.set_xlabel("False Positive Rate", color="#cccccc")
    ax1.set_ylabel("True Positive Rate", color="#cccccc")
    ax1.set_title("ROC Curve", color="#ffffff", pad=8)
    ax1.legend(facecolor="#2a2a2a", labelcolor="#cccccc", edgecolor="#444444")
    ax1.grid(True, color="#333333", linestyle="--", alpha=0.6)

    ax2.plot(rec, prec, color="#81c784", linewidth=2, label=f"AUC-PR = {auc_pr:.3f}")
    ax2.axhline(y=y_true.mean(), color="#555555", linestyle="--", linewidth=1, label="Baseline")
    ax2.set_xlabel("Recall", color="#cccccc")
    ax2.set_ylabel("Precision", color="#cccccc")
    ax2.set_title("Precision-Recall Curve", color="#ffffff", pad=8)
    ax2.legend(facecolor="#2a2a2a", labelcolor="#cccccc", edgecolor="#444444")
    ax2.grid(True, color="#333333", linestyle="--", alpha=0.6)

    plt.tight_layout(pad=2.0)
    plt.savefig(_ROC_PR_GRAPH, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"[stats] ROC/PR     → {_ROC_PR_GRAPH}")


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

    fig, ax = plt.subplots(figsize=(9, 8))
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
        self.model: HistGradientBoostingClassifier | None = None
        self.scaler: StandardScaler | None = None
        self.calibrator = None
        self._feature_importances: dict[str, float] = {}

    def train(self) -> None:
        from train import ATTACK_DIR, BENIGN_DIR, _load_folder

        print("\n[classifier] Loading OTRF attack datasets …")
        X_atk, y_atk, scen_atk = _load_folder(ATTACK_DIR, fixed_label=1)

        print("[classifier] Loading OTRF benign datasets …")
        X_ben_otrf, y_ben_otrf, scen_ben = _load_folder(BENIGN_DIR, fixed_label=0)

        X_test_parts: list[np.ndarray] = []
        y_test_parts: list[np.ndarray] = []
        test_scens:   list[str]        = []
        X_train_parts: list[np.ndarray] = []
        y_train_parts: list[np.ndarray] = []

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
        from sklearn.isotonic import IsotonicRegression
        from sklearn.model_selection import train_test_split as _tts

        self.scaler = StandardScaler()
        X_s = self.scaler.fit_transform(X_train)

        # Reserve 20% of training data for isotonic calibration
        X_s_clf, X_s_cal, y_clf, y_cal = _tts(
            X_s, y_train, test_size=0.20, random_state=42, stratify=y_train
        )

        # Class weights via sample_weight (HistGBT doesn't support class_weight param)
        sw = np.where(y_clf == 1, 4.0, 1.0)

        self.model = HistGradientBoostingClassifier(
            max_iter=300,
            max_depth=6,
            learning_rate=0.05,
            min_samples_leaf=10,
            max_leaf_nodes=31,
            random_state=42,
        )
        self.model.fit(X_s_clf, y_clf, sample_weight=sw)

        raw_cal = self.model.predict_proba(X_s_cal)[:, 1]
        self.calibrator = IsotonicRegression(out_of_bounds="clip")
        self.calibrator.fit(raw_cal, y_cal)

        # Permutation importance on calibration set (HistGBT has no split-based importances)
        from sklearn.inspection import permutation_importance as _perm_imp
        pi = _perm_imp(self.model, X_s_cal, y_cal, n_repeats=5, random_state=42, n_jobs=-1)
        self._feature_importances = dict(zip(FEATURE_NAMES, pi.importances_mean.tolist()))

        has_test = X_test is not None and len(X_test) > 0
        if has_test:
            X_te_s      = self.scaler.transform(X_test)
            raw_te      = self.model.predict_proba(X_te_s)[:, 1]
            y_proba_cal = self.calibrator.predict(raw_te)
            y_pred      = (y_proba_cal >= 0.5).astype(int)
            eval_y_true = y_test
            header      = "── Held-out scenario evaluation ──────────────────"
            if test_scenarios:
                unique = sorted(set(test_scenarios))
                print(f"\n[classifier] Test scenarios ({len(unique)}): {', '.join(unique)}")
        else:
            raw_tr      = self.model.predict_proba(X_s)[:, 1]
            y_proba_cal = self.calibrator.predict(raw_tr)
            y_pred      = (y_proba_cal >= 0.5).astype(int)
            eval_y_true = y_train
            header      = "── Training-set evaluation (no held-out scenarios) ─"

        report_str  = classification_report(eval_y_true, y_pred, target_names=["benign", "malicious"], digits=3, zero_division=0)
        report_dict = classification_report(eval_y_true, y_pred, target_names=["benign", "malicious"], output_dict=True, zero_division=0)
        cm          = confusion_matrix(eval_y_true, y_pred)
        print(f"\n{header}")
        print(report_str)
        print(f"Confusion matrix:\n  TN={cm[0,0]}  FP={cm[0,1]}\n  FN={cm[1,0]}  TP={cm[1,1]}\n")

        # AUC metrics (only meaningful with both classes present)
        auc_roc = avg_prec = 0.0
        if len(set(eval_y_true)) == 2:
            auc_roc  = float(roc_auc_score(eval_y_true, y_proba_cal))
            avg_prec = float(average_precision_score(eval_y_true, y_proba_cal))
            print(f"AUC-ROC: {auc_roc:.4f}   AUC-PR: {avg_prec:.4f}\n")
            if has_test:
                _plot_roc_pr(eval_y_true, y_proba_cal)

        if has_test:
            print("── Threshold analysis (operational view) ─────────")
            for thr in (0.40, 0.50, 0.60, 0.70, 0.80, 0.90):
                y_t = (y_proba_cal >= thr).astype(int)
                tp = int(((y_t == 1) & (eval_y_true == 1)).sum())
                fp = int(((y_t == 1) & (eval_y_true == 0)).sum())
                fn = int(((y_t == 0) & (eval_y_true == 1)).sum())
                prec_t = tp / (tp + fp) if (tp + fp) > 0 else 0.0
                rec_t  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
                f1_t   = 2 * prec_t * rec_t / (prec_t + rec_t) if (prec_t + rec_t) > 0 else 0.0
                print(f"  thr={thr:.2f}  prec={prec_t:.3f}  rec={rec_t:.3f}  f1={f1_t:.3f}  TP={tp}  FP={fp}  FN={fn}")
            print()

        os.makedirs(_MODEL_DIR, exist_ok=True)
        joblib.dump(self.model,      MODEL_PATH)
        joblib.dump(self.scaler,     SCALER_PATH)
        joblib.dump(self.calibrator, CALIBRATOR_PATH)
        with open(_VER_FILE, "w") as f:
            f.write(_MODEL_VER)

        n_train_mal = int(y_train.sum())
        n_test      = len(X_test)       if has_test else 0
        n_test_mal  = int(y_test.sum()) if has_test else 0
        _save_training_stats(
            report_dict, cm,
            len(y_train), n_train_mal, len(y_train) - n_train_mal,
            n_test, n_test_mal, n_test - n_test_mal,
            len(set(test_scenarios)) if test_scenarios else 0,
            has_test,
            self.feature_importances(),
            roc_auc=auc_roc,
            avg_precision=avg_prec,
        )

    def load(self) -> None:
        log = logging.getLogger(__name__)
        path = MODEL_PATH
        if not os.path.exists(path):
            legacy = os.path.join(_MODEL_DIR, "voidwatch_rf.joblib")
            if os.path.exists(legacy):
                path = legacy
        if not os.path.exists(path) or not os.path.exists(SCALER_PATH):
            log.warning("ML model not found — falling back to rules-only scoring. Run train.py to generate it.")
            return
        try:
            if os.path.exists(_VER_FILE):
                with open(_VER_FILE) as f:
                    on_disk = f.read().strip()
                if on_disk != _MODEL_VER:
                    log.warning(
                        "ML model version mismatch (on disk: %s, expected: %s) — "
                        "falling back to rules-only scoring. Re-run train.py.",
                        on_disk, _MODEL_VER,
                    )
                    return
            self.model  = joblib.load(path)
            self.scaler = joblib.load(SCALER_PATH)
            if os.path.exists(CALIBRATOR_PATH):
                self.calibrator = joblib.load(CALIBRATOR_PATH)
        except Exception as exc:
            log.error(
                "Failed to load ML model (%s) — falling back to rules-only scoring.", exc
            )
            self.model = self.scaler = self.calibrator = None

    def predict_proba(self, proc) -> float:
        if self.model is None or self.scaler is None:
            return 0.0
        try:
            vec   = np.array([extract(proc)])
            vec_s = self.scaler.transform(vec)
            raw   = float(self.model.predict_proba(vec_s)[0][1])
            if self.calibrator is not None:
                return float(self.calibrator.predict(np.array([raw]))[0])
            return raw
        except Exception:
            return 0.0

    def feature_importances(self) -> dict[str, float]:
        return self._feature_importances


classifier = ProcessClassifier()

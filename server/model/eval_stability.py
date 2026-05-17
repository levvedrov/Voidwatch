"""
ML stability evaluation — runs N random scenario splits and reports mean / std /
worst-case metrics to assess how reliable the classifier is across different
train/test partitions.

Run from the project root or server/model/:
    python server/model/eval_stability.py [--splits 15] [--seed 0]
"""
from __future__ import annotations

import argparse
import os
import sys
import warnings
from pathlib import Path
import numpy as np

_BACKEND = str(Path(__file__).resolve().parent.parent / "backend")
sys.path.insert(0, _BACKEND)

warnings.filterwarnings("ignore")


def _load_data():
    from train import ATTACK_DIR, BENIGN_DIR, _load_folder
    print("[eval] Loading attack data …", end=" ", flush=True)
    X_atk, y_atk, scen_atk = _load_folder(ATTACK_DIR, fixed_label=1)
    print(f"{len(y_atk)} events across {len(set(scen_atk))} scenarios")

    print("[eval] Loading benign data …", end=" ", flush=True)
    X_ben, y_ben, scen_ben = _load_folder(BENIGN_DIR, fixed_label=0)
    print(f"{len(y_ben)} events across {len(set(scen_ben))} scenarios")

    return X_atk, y_atk, scen_atk, X_ben, y_ben, scen_ben


def _split_by_scenario(X, y, scens, test_frac, rng_seed):
    from sklearn.model_selection import GroupShuffleSplit
    unique = list(set(scens))
    if len(unique) < 2:
        return X, y, np.empty((0, X.shape[1])), np.empty(0, dtype=int)
    gss = GroupShuffleSplit(n_splits=1, test_size=test_frac, random_state=rng_seed)
    tr_idx, te_idx = next(gss.split(X, y, groups=scens))
    return X[tr_idx], y[tr_idx], X[te_idx], y[te_idx]


def _train_and_eval(X_train, y_train, X_test, y_test):
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.isotonic import IsotonicRegression
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (
        roc_auc_score, average_precision_score,
        precision_score, recall_score, f1_score,
        confusion_matrix,
    )

    scaler = StandardScaler()
    X_s = scaler.fit_transform(X_train)

    X_s_clf, X_s_cal, y_clf, y_cal = train_test_split(
        X_s, y_train, test_size=0.20, random_state=0, stratify=y_train
    )
    sw = np.where(y_clf == 1, 4.0, 1.0)

    model = HistGradientBoostingClassifier(
        max_iter=300,
        learning_rate=0.05,
        max_depth=6,
        min_samples_leaf=5,
        l2_regularization=0.5,
        random_state=0,
    )
    model.fit(X_s_clf, y_clf, sample_weight=sw)

    # Isotonic calibration
    raw_cal = model.predict_proba(X_s_cal)[:, 1]
    cal = IsotonicRegression(out_of_bounds="clip")
    cal.fit(raw_cal, y_cal)

    X_test_s = scaler.transform(X_test)
    raw_prob  = model.predict_proba(X_test_s)[:, 1]
    prob      = cal.predict(raw_prob)
    pred      = (prob >= 0.5).astype(int)

    cm = confusion_matrix(y_test, pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    roc  = roc_auc_score(y_test, prob) if len(np.unique(y_test)) > 1 else float("nan")
    apr  = average_precision_score(y_test, prob) if len(np.unique(y_test)) > 1 else float("nan")
    prec = precision_score(y_test, pred, zero_division=0)
    rec  = recall_score(y_test, pred, zero_division=0)
    f1   = f1_score(y_test, pred, zero_division=0)

    return dict(roc_auc=roc, avg_precision=apr, precision=prec,
                recall=rec, f1=f1, tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp),
                n_test=len(y_test), n_test_mal=int(y_test.sum()),
                n_test_ben=int((y_test == 0).sum()))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--splits", type=int, default=15,
                        help="Number of random splits to evaluate (default: 15)")
    parser.add_argument("--seed", type=int, default=0,
                        help="Base random seed (default: 0)")
    args = parser.parse_args()

    X_atk, y_atk, scen_atk, X_ben, y_ben, scen_ben = _load_data()

    if len(y_atk) == 0:
        print("[eval] ERROR: No attack data found. Cannot evaluate.")
        sys.exit(1)

    metrics_keys = ["roc_auc", "avg_precision", "precision", "recall", "f1"]
    all_results: list[dict] = []

    print(f"\n[eval] Running {args.splits} random scenario splits …\n")
    header = f"{'Split':>5}  {'N-test':>6}  {'Mal':>5}  {'AUC-ROC':>7}  {'AUC-PR':>7}  {'Prec':>6}  {'Recall':>6}  {'F1':>6}  {'TP':>4}  {'FP':>4}  {'FN':>4}"
    print(header)
    print("-" * len(header))

    for i in range(args.splits):
        seed = args.seed + i

        atk_test_frac = max(1 / max(len(set(scen_atk)), 1), 0.2)
        ben_test_frac = max(1 / max(len(set(scen_ben)), 1), 0.2)

        Xa_tr, ya_tr, Xa_te, ya_te = _split_by_scenario(X_atk, y_atk, scen_atk, atk_test_frac, seed)
        Xb_tr, yb_tr, Xb_te, yb_te = _split_by_scenario(X_ben, y_ben, scen_ben, ben_test_frac, seed)

        X_train = np.vstack([p for p in [Xa_tr, Xb_tr] if len(p)])
        y_train = np.concatenate([p for p in [ya_tr, yb_tr] if len(p)])

        X_test_parts = [p for p in [Xa_te, Xb_te] if len(p)]
        y_test_parts = [p for p in [ya_te, yb_te] if len(p)]

        if not X_test_parts or not X_train.size:
            print(f"{i+1:>5}  SKIPPED (insufficient data for split)")
            continue

        X_test = np.vstack(X_test_parts)
        y_test = np.concatenate(y_test_parts)

        if len(np.unique(y_train)) < 2 or len(np.unique(y_test)) < 2:
            print(f"{i+1:>5}  SKIPPED (only one class in train or test set)")
            continue

        r = _train_and_eval(X_train, y_train, X_test, y_test)
        all_results.append(r)

        print(f"{i+1:>5}  {r['n_test']:>6}  {r['n_test_mal']:>5}  "
              f"{r['roc_auc']:>7.4f}  {r['avg_precision']:>7.4f}  "
              f"{r['precision']:>6.4f}  {r['recall']:>6.4f}  {r['f1']:>6.4f}  "
              f"{r['tp']:>4}  {r['fp']:>4}  {r['fn']:>4}")

    if not all_results:
        print("\n[eval] No results — not enough data for any split.")
        return

    print("\n" + "=" * len(header))
    print("STABILITY SUMMARY\n")

    for key in metrics_keys:
        vals = [r[key] for r in all_results if not np.isnan(r[key])]
        if not vals:
            continue
        mean  = np.mean(vals)
        std   = np.std(vals)
        worst = np.min(vals) if key in ("recall", "roc_auc", "avg_precision", "f1") else np.max(vals)
        label = "worst=min" if key in ("recall", "roc_auc", "avg_precision", "f1") else "worst=max"
        print(f"  {key:<15}  mean={mean:.4f}  std={std:.4f}  worst({label})={worst:.4f}")

    # FP / FN summary
    fps = [r["fp"] for r in all_results]
    fns = [r["fn"] for r in all_results]
    print(f"\n  {'false_positives':<15}  mean={np.mean(fps):.1f}  std={np.std(fps):.1f}  worst(max)={max(fps)}")
    print(f"  {'false_negatives':<15}  mean={np.mean(fns):.1f}  std={np.std(fns):.1f}  worst(max)={max(fns)}")

    roc_vals = [r["roc_auc"] for r in all_results if not np.isnan(r["roc_auc"])]
    if roc_vals:
        print(f"\n  Splits evaluated: {len(all_results)} / {args.splits}")
        print(f"  AUC-ROC range:    [{min(roc_vals):.4f}, {max(roc_vals):.4f}]")
        if np.mean(roc_vals) >= 0.90 and max(fns) <= 20:
            print("\n  [VERDICT] Model shows stable performance — suitable for deployment.")
        elif np.mean(roc_vals) >= 0.80:
            print("\n  [VERDICT] Model is acceptable but variance is notable. Add more training data.")
        else:
            print("\n  [VERDICT] Model needs more data before deployment.")


if __name__ == "__main__":
    main()

"""Train and evaluate the classifier.  Usage: python -m wids.train [train_name] [test_name]"""
import sys, json
import numpy as np, joblib
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, ConfusionMatrixDisplay
from .frames import read_pcap
from .features import extract, FEATURES


def load(name):
    frames = list(read_pcap(f"data/{name}.pcap"))
    labels = np.loadtxt(f"data/{name}.labels.csv", dtype=int)
    X, _, y = extract(frames, labels=labels)
    return X, y


def main(train="train", test="test"):
    Xtr, ytr = load(train)
    Xte, yte = load(test)
    print(f"train windows: {len(ytr)} ({ytr.sum()} attack) | test windows: {len(yte)} ({yte.sum()} attack)")

    models = {
        "DecisionTree": DecisionTreeClassifier(max_depth=5, random_state=0),
        "RandomForest": RandomForestClassifier(n_estimators=100, random_state=0),
    }
    summary = {}
    for name, m in models.items():
        m.fit(Xtr, ytr)
        pred = m.predict(Xte)
        acc = accuracy_score(yte, pred)
        summary[name] = acc
        print(f"\n== {name}: accuracy {acc:.4f}")
        print(classification_report(yte, pred, target_names=["normal", "attack"], digits=3))
        cm = confusion_matrix(yte, pred)
        print("confusion matrix [[TN FP],[FN TP]]:\n", cm)
        ConfusionMatrixDisplay(cm, display_labels=["normal", "attack"]).plot(cmap="Blues", values_format="d")
        plt.title(f"{name} (accuracy {acc:.3f})")
        plt.savefig(f"results/confusion_{name}.png", dpi=200, bbox_inches="tight"); plt.close()

    rf = models["RandomForest"]
    imp = sorted(zip(FEATURES, rf.feature_importances_), key=lambda t: -t[1])
    plt.figure(figsize=(6, 4))
    plt.barh([k for k, _ in imp][::-1], [v for _, v in imp][::-1])
    plt.xlabel("importance"); plt.title("Random Forest feature importance")
    plt.savefig("results/feature_importance.png", dpi=200, bbox_inches="tight"); plt.close()
    print("\nFeature importance:", [(k, round(v, 3)) for k, v in imp])

    joblib.dump(rf, "models/wids_rf.joblib")
    json.dump(summary, open("results/accuracy.json", "w"), indent=2)


if __name__ == "__main__":
    main(*sys.argv[1:3])

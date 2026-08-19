#!/usr/bin/env python3
"""Solve the mis1 model-fingerprint CTF task.

The handout provides labelled train conversations and unlabelled test
conversations.  Each prompt is answered by four models, so prediction is a
style-classification problem with a useful per-prompt constraint: the four
test answers for the same user prompt should receive labels 0, 1, 2, and 3.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LOCAL_DEPS = REPO_ROOT / ".work" / "pydeps"
if LOCAL_DEPS.exists():
    sys.path.insert(0, str(LOCAL_DEPS))

import numpy as np
from scipy import sparse
from scipy.optimize import linear_sum_assignment
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC


class StyleFeatures(BaseEstimator, TransformerMixin):
    """Small explicit features for model formatting habits."""

    def fit(self, texts, y=None):
        return self

    def transform(self, texts):
        rows = []
        numbered_re = re.compile(r"(^|\n)\s*\d+[.)]\s+")
        for text in texts:
            length = len(text)
            words = re.findall(r"[A-Za-z']+", text)
            first_word = words[0].lower() if words else ""
            lower = text.lower()
            rows.append(
                [
                    length / 5000,
                    len(words) / 800,
                    text.count("\n") / 80,
                    int(text.startswith(" ")),
                    int(text.startswith("  ")),
                    int(text.endswith("\n")),
                    int(text.endswith("\n\n")),
                    int(text.lstrip().startswith("#")),
                    int(text.lstrip().startswith("Title:")),
                    int(text.lstrip().startswith("Certainly")),
                    int(text.lstrip().startswith("Sure")),
                    int(text.lstrip().startswith("Here")),
                    text.count("**") / 20,
                    text.count("* ") / 20,
                    len(numbered_re.findall(text)) / 30,
                    text.count("\n\n") / 40,
                    text.count(":") / 80,
                    text.count(";") / 30,
                    text.count("—") / 10,
                    text.count("-") / 50,
                    lower.count("certainly") / 5,
                    lower.count("based on") / 5,
                    lower.count("in conclusion") / 3,
                    lower.count("comprehensive") / 5,
                    int(first_word == "title"),
                    int(first_word == "the"),
                    int(first_word == "to"),
                    int(first_word == "certainly"),
                    int(first_word == "in"),
                    int(first_word == "here"),
                    int(first_word == "as"),
                    (len(text) - len(text.lstrip(" "))) / 5,
                    (len(text) - len(text.rstrip("\n"))) / 5,
                    (sum(1 for c in text if c.isupper()) / max(1, length)) * 10,
                    (sum(1 for c in text if c.isdigit()) / max(1, length)) * 10,
                ]
            )
        return sparse.csr_matrix(np.asarray(rows, dtype=np.float32))


def assistant_text(row: dict) -> str:
    return row["conversation"][1]["content"]


def user_text(row: dict) -> str:
    return row["conversation"][0]["content"]


def build_features() -> FeatureUnion:
    return FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    analyzer="word",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=180_000,
                    sublinear_tf=True,
                    lowercase=True,
                ),
            ),
            (
                "char",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(3, 5),
                    min_df=3,
                    max_features=320_000,
                    sublinear_tf=True,
                    lowercase=False,
                ),
            ),
            (
                "style",
                Pipeline(
                    [
                        ("style", StyleFeatures()),
                        ("scale", StandardScaler(with_mean=False)),
                    ]
                ),
            ),
        ]
    )


def grouped_predictions(scores, classes, groups, indices):
    """Assign one label per row, using 0/1/2/3 exactly for 4-row groups."""

    pos = {idx: row for row, idx in enumerate(indices)}
    by_group = defaultdict(list)
    for idx in indices:
        by_group[groups[idx]].append(idx)

    predictions = {}
    class_list = list(classes)
    for group_indices in by_group.values():
        if len(group_indices) != 4:
            for idx in group_indices:
                row = scores[pos[idx]]
                predictions[idx] = class_list[int(np.argmax(row))]
            continue

        matrix = []
        for idx in group_indices:
            row_by_label = [0.0] * 4
            for class_pos, label in enumerate(class_list):
                row_by_label[int(label)] = scores[pos[idx], class_pos]
            matrix.append(row_by_label)

        rows, cols = linear_sum_assignment([[-value for value in row] for row in matrix])
        for row, label in zip(rows, cols):
            predictions[group_indices[row]] = int(label)

    return [predictions[idx] for idx in indices]


def validation_indices(groups):
    unique_groups = sorted(set(groups))
    valid_groups = {
        group
        for group in unique_groups
        if int(hashlib.sha1(group.encode()).hexdigest(), 16) % 5 == 0
    }
    train_idx = [idx for idx, group in enumerate(groups) if group not in valid_groups]
    valid_idx = [idx for idx, group in enumerate(groups) if group in valid_groups]
    return train_idx, valid_idx


def validate(train_rows):
    texts = [assistant_text(row) for row in train_rows]
    labels = [row["label"] for row in train_rows]
    groups = [user_text(row) for row in train_rows]
    train_idx, valid_idx = validation_indices(groups)

    features = build_features()
    model = LinearSVC(C=1.0, dual="auto", max_iter=1000, random_state=7)
    x_train = features.fit_transform([texts[idx] for idx in train_idx], [labels[idx] for idx in train_idx])
    model.fit(x_train, [labels[idx] for idx in train_idx])

    x_valid = features.transform([texts[idx] for idx in valid_idx])
    scores = model.decision_function(x_valid)
    direct = [model.classes_[int(np.argmax(row))] for row in scores]
    grouped = grouped_predictions(scores, model.classes_, groups, valid_idx)
    truth = [labels[idx] for idx in valid_idx]

    print(f"validation direct accuracy: {accuracy_score(truth, direct):.6f}")
    print(f"validation grouped accuracy: {accuracy_score(truth, grouped):.6f}")
    print("validation grouped confusion matrix:")
    print(confusion_matrix(truth, grouped))


def solve(input_dir: Path, output: Path, skip_validation: bool):
    train_rows = json.loads((input_dir / "train.json").read_text())
    test_rows = json.loads((input_dir / "test.json").read_text())

    if not skip_validation:
        validate(train_rows)

    train_texts = [assistant_text(row) for row in train_rows]
    train_labels = [row["label"] for row in train_rows]

    features = build_features()
    model = LinearSVC(C=1.0, dual="auto", max_iter=1000, random_state=7)
    x_train = features.fit_transform(train_texts, train_labels)
    model.fit(x_train, train_labels)

    test_texts = [assistant_text(row) for row in test_rows]
    test_groups = [user_text(row) for row in test_rows]
    test_idx = list(range(len(test_rows)))
    scores = model.decision_function(features.transform(test_texts))
    predictions = grouped_predictions(scores, model.classes_, test_groups, test_idx)
    answer = "".join(str(label) for label in predictions)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(answer + "\n")
    print(f"test rows: {len(test_rows)}")
    print(f"unique test prompts: {len(set(test_groups))}")
    print(f"answer length: {len(answer)}")
    print(f"answer sha256: {hashlib.sha256(answer.encode()).hexdigest()}")
    print(f"wrote: {output}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=REPO_ROOT / ".work" / "mis1-20260818",
        help="Directory containing train.json, test.json, and README.txt.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / ".work" / "mis1-20260818" / "answer.txt",
    )
    parser.add_argument("--skip-validation", action="store_true")
    args = parser.parse_args()
    solve(args.input_dir, args.output, args.skip_validation)


if __name__ == "__main__":
    main()

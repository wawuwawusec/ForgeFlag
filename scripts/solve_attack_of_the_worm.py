#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import NamedTuple


DEFAULT_IMAGE = "forgeflag-worm-replay:latest"
DEFAULT_PAYLOAD = ""
PAYLOAD_ENV = "FORGEFLAG_WORM_PAYLOAD"
SEARCH_SEED_ENV = "FORGEFLAG_WORM_SEARCH_SEED"
SEARCH_STEPS_ENV = "FORGEFLAG_WORM_SEARCH_STEPS"
SEARCH_CANDIDATE_TRIALS_ENV = "FORGEFLAG_WORM_SEARCH_CANDIDATE_TRIALS"
SEARCH_SHORT_ITERS_ENV = "FORGEFLAG_WORM_SEARCH_SHORT_ITERS"
SEARCH_LONG_ITERS_ENV = "FORGEFLAG_WORM_SEARCH_LONG_ITERS"
SEARCH_FINISH_ITERS_ENV = "FORGEFLAG_WORM_SEARCH_FINISH_ITERS"
SCORE_SNIPPET = r"""import json
import os

import numpy as np
from PIL import Image
import torch
import torch.nn as nn
from torchvision.models import resnet18

payload = os.environ.get("FORGEFLAG_WORM_PAYLOAD", "")
model = resnet18()
model.fc = nn.Linear(model.fc.in_features, 1)
model.load_state_dict(torch.load("model.pt"))
original = np.array(Image.open("worm.png"))
modified = original.copy()
pixel_count = 0
if payload.strip():
    for item in payload.strip().split(";"):
        x, y, r, g, b = map(int, item.split(","))
        modified[y, x] = [r, g, b]
        pixel_count += 1
x = torch.tensor(modified.transpose(2, 0, 1) / 255.0, dtype=torch.float32).unsqueeze(0)
with torch.no_grad():
    logit = model(x)
    probability = torch.sigmoid(logit)
print(json.dumps({
    "pixel_count": pixel_count,
    "logit": float(logit.item()),
    "probability": float(probability.item()),
    "is_adversarial": bool(probability.item() < 0.5),
}))
"""
UNSTABLE_SEARCH_SNIPPET = r"""import json
import os
from random import randrange, seed

import numpy as np
from PIL import Image
import torch
import torch.nn as nn
from torchvision.models import resnet18

search_seed = int(os.environ.get("FORGEFLAG_WORM_SEARCH_SEED", "1116"))
steps = int(os.environ.get("FORGEFLAG_WORM_SEARCH_STEPS", "30"))
candidate_trials = int(os.environ.get("FORGEFLAG_WORM_SEARCH_CANDIDATE_TRIALS", "30"))
short_iters = int(os.environ.get("FORGEFLAG_WORM_SEARCH_SHORT_ITERS", "15"))
long_iters = int(os.environ.get("FORGEFLAG_WORM_SEARCH_LONG_ITERS", "60"))
finish_iters = int(os.environ.get("FORGEFLAG_WORM_SEARCH_FINISH_ITERS", "500"))

model = resnet18()
model.fc = nn.Linear(model.fc.in_features, 1)
model.load_state_dict(torch.load("model.pt"))
original = np.array(Image.open("worm.png")).astype(np.float32)


def schedule(start, stop, count):
    if count <= 0:
        return []
    return np.logspace(start, stop, num=count)


def evaluate(image):
    x = torch.tensor(image.transpose(2, 0, 1) / 255.0, dtype=torch.float32).unsqueeze(0)
    with torch.no_grad():
        logit = model(x)
        probability = torch.sigmoid(logit)
    return float(logit.item()), float(probability.item())


def gradient_step(image):
    x = torch.tensor(image.transpose(2, 0, 1) / 255.0, dtype=torch.float32).unsqueeze(0)
    x.requires_grad = True
    model.zero_grad()
    probability = torch.sigmoid(model(x)).sum()
    (-probability).backward()
    return float(probability.item()), x.grad[0].detach().numpy().transpose(1, 2, 0)


def optimize(image, selected_pixels, learning_rates):
    mask = np.zeros((224 * 224, 3), dtype=np.float32)
    for pixel in selected_pixels:
        mask[pixel] = 1
    mask = mask.reshape((224, 224, 3))
    candidate = image.copy()
    score = None
    for learning_rate in learning_rates:
        score, gradient = gradient_step(candidate)
        candidate = np.clip(candidate - gradient * mask * learning_rate, 0, 255)
    if score is None:
        _, score = evaluate(candidate)
    return score, candidate


seed(search_seed)
baseline_logit, baseline_probability = evaluate(original)
selected = []
working = original.copy()
short_schedule = schedule(4, 3, short_iters)
long_schedule = schedule(4, 2, long_iters)
finish_schedule = schedule(4, 2, finish_iters)

for step in range(steps):
    candidates = []
    for _ in range(candidate_trials):
        while True:
            pixel = randrange(0, 224 * 224)
            if pixel not in selected:
                break
        score, _ = optimize(working, selected + [pixel], short_schedule)
        candidates.append((score, pixel))
    _, next_pixel = min(candidates, key=lambda item: item[0])
    selected.append(next_pixel)
    score, working = optimize(working, selected, long_schedule)
    print(json.dumps({"step": step + 1, "selected_pixel": next_pixel, "probability": score}), flush=True)

if finish_schedule:
    _, working = optimize(working, selected, finish_schedule)
final_image = working.astype(np.uint8)
final_logit, final_probability = evaluate(final_image)
changed_pixels = sorted(set(zip(*np.where((final_image.astype(np.int16) - original.astype(np.uint8).astype(np.int16)).any(axis=2)))))
payload = ";".join(
    f"{x},{y},{int(final_image[y, x, 0])},{int(final_image[y, x, 1])},{int(final_image[y, x, 2])}"
    for y, x in changed_pixels
)
print(json.dumps({
    "seed": search_seed,
    "steps": steps,
    "candidate_trials": candidate_trials,
    "unstable_pixels": selected,
    "baseline_probability": baseline_probability,
    "best_logit": final_logit,
    "best_probability": final_probability,
    "pixel_count": len(changed_pixels),
    "is_adversarial": final_probability < 0.5 and len(changed_pixels) <= 30,
    "payload": payload,
}), flush=True)
"""


class PixelChange(NamedTuple):
    x: int
    y: int
    r: int
    g: int
    b: int


class UnstableSearchConfig(NamedTuple):
    seed: int = 1116
    steps: int = 30
    candidate_trials: int = 30
    short_iters: int = 15
    long_iters: int = 60
    finish_iters: int = 500


def format_pixel_payload(changes: list[PixelChange]) -> str:
    return ";".join(f"{change.x},{change.y},{change.r},{change.g},{change.b}" for change in changes)


def parse_pixel_payload(payload: str) -> list[PixelChange]:
    if not payload.strip():
        return []
    changes: list[PixelChange] = []
    for item in payload.strip().split(";"):
        x, y, r, g, b = (int(part) for part in item.split(","))
        changes.append(PixelChange(x, y, r, g, b))
    return changes


def extract_flags(text: str) -> list[str]:
    return re.findall(r"UMDCTF\{[^}\r\n]+\}", text)


def build_docker_command(challenge_dir: Path, image: str, container_name: str, command: str = "python3 server.py") -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "-i",
        "-v",
        f"{challenge_dir.resolve()}:/chal",
        "-w",
        "/chal",
        image,
        "bash",
        "-lc",
        command,
    ]


def build_score_command(challenge_dir: Path, image: str, container_name: str, payload: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "-i",
        "-e",
        f"{PAYLOAD_ENV}={payload}",
        "-v",
        f"{challenge_dir.resolve()}:/chal",
        "-w",
        "/chal",
        image,
        "python3",
        "-c",
        SCORE_SNIPPET,
    ]


def build_unstable_search_command(challenge_dir: Path, image: str, container_name: str, config: UnstableSearchConfig) -> list[str]:
    env = {
        SEARCH_SEED_ENV: config.seed,
        SEARCH_STEPS_ENV: config.steps,
        SEARCH_CANDIDATE_TRIALS_ENV: config.candidate_trials,
        SEARCH_SHORT_ITERS_ENV: config.short_iters,
        SEARCH_LONG_ITERS_ENV: config.long_iters,
        SEARCH_FINISH_ITERS_ENV: config.finish_iters,
    }
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "-i",
    ]
    for name, value in env.items():
        command.extend(["-e", f"{name}={value}"])
    command.extend(
        [
            "-v",
            f"{challenge_dir.resolve()}:/chal",
            "-w",
            "/chal",
            image,
            "python3",
            "-c",
            UNSTABLE_SEARCH_SNIPPET,
        ]
    )
    return command


def image_exists(image: str) -> bool:
    result = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True)
    return result.returncode == 0


def build_replay_image(image: str) -> None:
    dockerfile = """\
FROM python:3.11.8-slim-bookworm
RUN pip install torch torchvision --no-cache --index-url https://download.pytorch.org/whl/cpu
WORKDIR /chal
"""
    subprocess.run(
        ["docker", "build", "-t", image, "-f", "-", "."],
        input=dockerfile,
        text=True,
        check=True,
    )


def run_bundled_solver(challenge_dir: Path, image: str, timeout: int) -> str:
    container_name = f"forgeflag-worm-solve-{uuid.uuid4().hex[:12]}"
    command = build_docker_command(challenge_dir, image, container_name, "python3 solve.py")
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"bundled solver failed rc={result.returncode}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
    for line in result.stdout.splitlines():
        if line.count(",") >= 4 and ";" in line:
            return line.strip()
    raise RuntimeError(f"bundled solver did not print a pixel payload\n{result.stdout}")


def run_server(challenge_dir: Path, image: str, payload: str, timeout: int) -> str:
    container_name = f"forgeflag-worm-server-{uuid.uuid4().hex[:12]}"
    command = build_docker_command(challenge_dir, image, container_name)
    result = subprocess.run(command, input=payload + "\n", capture_output=True, text=True, timeout=timeout)
    output = result.stdout + result.stderr
    if result.returncode != 0 and not extract_flags(output):
        raise RuntimeError(f"server replay failed rc={result.returncode}\n{output}")
    return output


def parse_score_output(output: str) -> dict[str, object]:
    for line in reversed(output.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        return json.loads(line)
    raise RuntimeError(f"score command did not print JSON\n{output}")


def parse_search_output(output: str) -> dict[str, object]:
    for line in reversed(output.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        parsed = json.loads(line)
        if "payload" in parsed or "best_probability" in parsed:
            return parsed
    raise RuntimeError(f"search command did not print final JSON\n{output}")


def format_search_result(result: dict[str, object]) -> str:
    return json.dumps(result, sort_keys=True, indent=2) + "\n"


def write_search_outputs(result: dict[str, object], search_output: Path | None, payload_output: Path | None) -> None:
    if search_output is not None:
        search_output.parent.mkdir(parents=True, exist_ok=True)
        search_output.write_text(format_search_result(result), encoding="utf-8")
    if payload_output is not None:
        payload = str(result.get("payload") or "")
        if not payload:
            raise ValueError("search result does not contain a payload to write")
        payload_output.parent.mkdir(parents=True, exist_ok=True)
        payload_output.write_text(payload + "\n", encoding="utf-8")


def parse_seed_list(value: str) -> list[int]:
    seen: set[int] = set()
    seeds: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        seed_value = int(part, 10)
        if seed_value in seen:
            continue
        seen.add(seed_value)
        seeds.append(seed_value)
    if not seeds:
        raise ValueError("seed list is empty")
    return seeds


def select_best_search_result(results: list[dict[str, object]]) -> dict[str, object]:
    if not results:
        raise ValueError("no search results to select from")
    return min(results, key=lambda item: float(item.get("best_probability", 1.0)))


def score_payload(challenge_dir: Path, image: str, payload: str, timeout: int) -> dict[str, object]:
    changes = parse_pixel_payload(payload)
    if len(changes) > 30:
        raise ValueError(f"server allows at most 30 changed pixels, got {len(changes)}")
    container_name = f"forgeflag-worm-score-{uuid.uuid4().hex[:12]}"
    result = subprocess.run(
        build_score_command(challenge_dir, image, container_name, payload),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise RuntimeError(f"score replay failed rc={result.returncode}\n{output}")
    return parse_score_output(output)


def search_unstable_pixels(challenge_dir: Path, image: str, config: UnstableSearchConfig, timeout: int) -> dict[str, object]:
    container_name = f"forgeflag-worm-search-{uuid.uuid4().hex[:12]}"
    result = subprocess.run(
        build_unstable_search_command(challenge_dir, image, container_name, config),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise RuntimeError(f"unstable-pixel search failed rc={result.returncode}\n{output}")
    return parse_search_output(output)


def search_multiple_seeds(
    challenge_dir: Path,
    image: str,
    seeds: list[int],
    base_config: UnstableSearchConfig,
    timeout: int,
) -> dict[str, object]:
    results: list[dict[str, object]] = []
    for seed_value in seeds:
        result = search_unstable_pixels(
            challenge_dir,
            image,
            base_config._replace(seed=seed_value),
            timeout,
        )
        results.append(result)
        if result.get("is_adversarial"):
            break
    best = dict(select_best_search_result(results))
    best["all_results"] = results
    best["searched_seeds"] = seeds[: len(results)]
    return best


def read_payload_argument(payload: str | None, payload_file: Path | None) -> str | None:
    if payload and payload_file:
        raise ValueError("pass either --payload or --payload-file, not both")
    if payload_file is not None:
        return payload_file.read_text(encoding="utf-8").strip()
    return payload


def solve(
    challenge_dir: Path,
    image: str = DEFAULT_IMAGE,
    payload: str | None = None,
    build_image: bool = False,
    regenerate: bool = False,
    timeout: int = 360,
) -> dict[str, object]:
    for required in ("model.pt", "server.py", "worm.png", "flag.txt"):
        if not (challenge_dir / required).exists():
            raise FileNotFoundError(f"missing {required} under {challenge_dir}")

    if build_image and not image_exists(image):
        build_replay_image(image)
    if not image_exists(image):
        raise RuntimeError(f"Docker image {image!r} is missing; rerun with --build-image")

    selected_payload = payload or DEFAULT_PAYLOAD
    generated = False
    if not selected_payload and not regenerate:
        raise RuntimeError("no cached payload is available yet; pass --payload or --regenerate")
    if regenerate:
        if not (challenge_dir / "solve.py").exists():
            raise FileNotFoundError(f"missing bundled solve.py under {challenge_dir}; pass --payload")
        selected_payload = run_bundled_solver(challenge_dir, image, timeout=timeout)
        generated = True

    changes = parse_pixel_payload(selected_payload)
    if len(changes) > 30:
        raise ValueError(f"server allows at most 30 changed pixels, got {len(changes)}")

    output = run_server(challenge_dir, image, selected_payload, timeout=timeout)
    return {
        "challenge": "attack of the worm",
        "pixel_count": len(changes),
        "payload": selected_payload,
        "payload_generated": generated,
        "service_output": output,
        "flags": extract_flags(output),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay UMDCTF attack of the worm with bounded adversarial pixel changes.")
    parser.add_argument("--challenge-dir", type=Path, default=Path(".forgeflag/heldout-cache/umdctf2024/misc/attack-of-the-worm"))
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--build-image", action="store_true", help="Build the CPU PyTorch replay image if it is missing.")
    parser.add_argument("--regenerate", action="store_true", help="Run the bundled gradient solver instead of using the cached payload.")
    parser.add_argument("--payload", help="Semicolon-separated x,y,r,g,b pixel payload to replay.")
    parser.add_argument("--payload-file", type=Path, help="Read a semicolon-separated pixel payload from a file.")
    parser.add_argument("--score-only", action="store_true", help="Evaluate a payload with the exact server preprocessing/model path without submitting it to server.py.")
    parser.add_argument("--search-unstable", action="store_true", help="Run a bounded unstable-pixel gradient search and print the best candidate JSON.")
    parser.add_argument("--search-seed", type=int, default=1116)
    parser.add_argument("--search-seeds", help="Comma-separated seeds for repeated unstable-pixel search; best result is printed and persisted.")
    parser.add_argument("--search-steps", type=int, default=30)
    parser.add_argument("--candidate-trials", type=int, default=30)
    parser.add_argument("--search-short-iters", type=int, default=15)
    parser.add_argument("--search-long-iters", type=int, default=60)
    parser.add_argument("--search-finish-iters", type=int, default=500)
    parser.add_argument("--search-output", type=Path, help="Write the final unstable-pixel search JSON to this path.")
    parser.add_argument("--payload-output", type=Path, help="Write the final unstable-pixel payload string to this path.")
    parser.add_argument("--timeout", type=int, default=360)
    args = parser.parse_args()

    try:
        payload = read_payload_argument(args.payload, args.payload_file)
        if args.score_only:
            if args.build_image and not image_exists(args.image):
                build_replay_image(args.image)
            if not image_exists(args.image):
                raise RuntimeError(f"Docker image {args.image!r} is missing; rerun with --build-image")
            selected_payload = payload or DEFAULT_PAYLOAD
            if not selected_payload:
                raise RuntimeError("no payload is available to score; pass --payload or --payload-file")
            score = score_payload(args.challenge_dir, args.image, selected_payload, args.timeout)
            print(json.dumps(score, sort_keys=True))
            return 0 if score.get("is_adversarial") else 1
        if args.search_unstable:
            if args.build_image and not image_exists(args.image):
                build_replay_image(args.image)
            if not image_exists(args.image):
                raise RuntimeError(f"Docker image {args.image!r} is missing; rerun with --build-image")
            search = search_unstable_pixels(
                args.challenge_dir,
                args.image,
                UnstableSearchConfig(
                    seed=args.search_seed,
                    steps=args.search_steps,
                    candidate_trials=args.candidate_trials,
                    short_iters=args.search_short_iters,
                    long_iters=args.search_long_iters,
                    finish_iters=args.search_finish_iters,
                ),
                args.timeout,
            ) if not args.search_seeds else search_multiple_seeds(
                args.challenge_dir,
                args.image,
                parse_seed_list(args.search_seeds),
                UnstableSearchConfig(
                    seed=args.search_seed,
                    steps=args.search_steps,
                    candidate_trials=args.candidate_trials,
                    short_iters=args.search_short_iters,
                    long_iters=args.search_long_iters,
                    finish_iters=args.search_finish_iters,
                ),
                args.timeout,
            )
            write_search_outputs(search, args.search_output, args.payload_output)
            print(json.dumps(search, sort_keys=True))
            return 0 if search.get("is_adversarial") else 1
        result = solve(
            args.challenge_dir,
            image=args.image,
            payload=payload,
            build_image=args.build_image,
            regenerate=args.regenerate,
            timeout=args.timeout,
        )
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"challenge: {result['challenge']}")
    print("method: sparse adversarial pixel replay against local ResNet18 worm classifier")
    print(f"pixel_count: {result['pixel_count']}")
    print(f"payload_generated: {result['payload_generated']}")
    print("payload:")
    print(result["payload"])
    print("service_output:")
    print(str(result["service_output"]).strip())
    flags = result["flags"]
    if not flags:
        return 1
    for flag in flags:
        print(f"flag: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

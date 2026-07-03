#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Mapping


DEFAULT_ARCHIVE = Path(
    ".forgeflag/heldout-cache/nus-welcome-ctf-2024/misc/EE2026/distribution/graded_post_lab_assignment_1.zip"
)

ANODE_VALUE_MAP = {
    frozenset({"AN3"}): "0",
    frozenset({"AN2"}): "1",
    frozenset({"AN3", "AN2"}): "2",
    frozenset({"AN1"}): "3",
    frozenset({"AN3", "AN1"}): "4",
    frozenset({"AN2", "AN1"}): "5",
    frozenset({"AN3", "AN2", "AN1"}): "6",
    frozenset({"AN0"}): "7",
    frozenset({"AN3", "AN0"}): "8",
    frozenset({"AN2", "AN0"}): "9",
}

# EE2026's assignment table uses custom seven-segment glyphs. These are the two
# glyphs present in the recovered design: initial ValueA and password-gated B.
SEGMENT_VALUE_A_MAP = {
    (0, 1, 1, 0, 0, 1, 0): "2",
}
SEGMENT_ALPHABET_MAP = {
    (0, 1, 0, 1, 0, 1, 1): "G",
}


class Instance:
    def __init__(self, name: str, cell: str, init: int | None = None, init_text: str | None = None) -> None:
        self.name = name
        self.cell = cell
        self.init = init
        self.init_text = init_text


class EdifNetlist:
    def __init__(
        self,
        instances: dict[str, Instance],
        inst_ports: dict[tuple[str, str], str],
        top_ports: dict[str, str],
    ) -> None:
        self.instances = instances
        self.inst_ports = inst_ports
        self.top_ports = top_ports


def extract_edif_from_project(project_zip: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="forgeflag-ee2026-") as tmp:
        with zipfile.ZipFile(project_zip) as outer:
            dcp_name = _choose_dcp(outer.namelist())
            dcp_path = Path(tmp) / "main.dcp"
            dcp_path.write_bytes(outer.read(dcp_name))
        with zipfile.ZipFile(dcp_path) as dcp:
            return dcp.read("main.edf").decode("utf-8", errors="replace")


def _choose_dcp(names: list[str]) -> str:
    preferred = [
        "graded_post_lab_assignment_1/graded_post_lab_assignment_1.runs/synth_1/main.dcp",
        "graded_post_lab_assignment_1/graded_post_lab_assignment_1.runs/impl_1/main_routed.dcp",
    ]
    for name in preferred:
        if name in names:
            return name
    for name in names:
        if name.endswith(".dcp"):
            return name
    raise ValueError("Vivado project archive does not contain a DCP checkpoint")


def parse_edif(edif: str) -> EdifNetlist:
    instances = _parse_instances(edif)
    inst_ports: dict[tuple[str, str], str] = {}
    top_ports: dict[str, str] = {}
    for net_name, body in _iter_net_blocks(edif):
        for port, inst in re.findall(r"\(portref\s+([^\s()]+)\s+\(instanceref\s+([^\s()]+)\)\)", body):
            inst_ports[(inst, port)] = net_name
        for port in re.findall(r"\(portref\s+([^\s()]+)\)", re.sub(r"\(portref\s+[^\s()]+\s+\(instanceref\s+[^\s()]+\)\)", "", body)):
            top_ports[port] = net_name
    return EdifNetlist(instances=instances, inst_ports=inst_ports, top_ports=top_ports)


def _parse_instances(edif: str) -> dict[str, Instance]:
    instances: dict[str, Instance] = {}
    lines = edif.splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped.startswith("(instance "):
            index += 1
            continue
        name = stripped.split()[1]
        block_lines = [lines[index]]
        depth = lines[index].count("(") - lines[index].count(")")
        index += 1
        while index < len(lines) and depth > 0:
            block_lines.append(lines[index])
            depth += lines[index].count("(") - lines[index].count(")")
            index += 1
        block = "\n".join(block_lines)
        cell_match = re.search(r"\(cellref\s+([^\s()]+)", block)
        init_match = re.search(r'\(property\s+INIT\s+\(string\s+"([^"]+)"\)\)', block)
        init_text = init_match.group(1) if init_match else None
        instances[name] = Instance(
            name=name,
            cell=cell_match.group(1) if cell_match else "",
            init=int(init_text.split("'h", 1)[1], 16) if init_text and "'h" in init_text else None,
            init_text=init_text,
        )
    return instances


def _iter_net_blocks(edif: str) -> list[tuple[str, str]]:
    nets: list[tuple[str, str]] = []
    lines = edif.splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped.startswith("(net "):
            index += 1
            continue
        name_match = re.match(r'\(net\s+(?:\(rename\s+[^\s()]+\s+"([^"]+)"\)|([^\s()]+))', stripped)
        net_name = name_match.group(1) or name_match.group(2) if name_match else f"net_{index}"
        block_lines = [lines[index]]
        depth = lines[index].count("(") - lines[index].count(")")
        index += 1
        while index < len(lines) and depth > 0:
            block_lines.append(lines[index])
            depth += lines[index].count("(") - lines[index].count(")")
            index += 1
        nets.append((net_name, "\n".join(block_lines)))
    return nets


def evaluate_outputs(netlist: EdifNetlist, switches: Mapping[str, int]) -> dict[str, int]:
    cache: dict[str, int] = {}
    for name, value in switches.items():
        cache[netlist.inst_ports[(f"{name}_IBUF_inst", "O")]] = value

    for (inst, port), net in netlist.inst_ports.items():
        if inst == "GND" and port == "G":
            cache[net] = 0
        if inst == "VCC" and port == "P":
            cache[net] = 1

    def eval_net(net: str) -> int:
        if net in cache:
            return cache[net]
        for (inst_name, port), candidate in netlist.inst_ports.items():
            if candidate != net or port != "O":
                continue
            inst = netlist.instances.get(inst_name)
            if inst is None:
                continue
            if inst.cell == "LUT5" or inst.cell == "LUT6":
                value = eval_lut(inst.init or 0, [eval_net(netlist.inst_ports[(inst_name, f"I{i}")]) for i in range(int(inst.cell[-1]))])
                cache[net] = value
                return value
            if inst.cell == "OBUF":
                value = eval_net(netlist.inst_ports[(inst_name, "I")])
                cache[net] = value
                return value
            if inst.cell == "INV":
                value = 1 - eval_net(netlist.inst_ports[(inst_name, "I")])
                cache[net] = value
                return value
        raise ValueError(f"could not evaluate net {net}")

    outputs: dict[str, int] = {}
    for port, net in netlist.top_ports.items():
        if port.startswith(("A", "B", "C", "D", "E", "F", "G", "AN", "LD")):
            outputs[port] = eval_net(net)
    return outputs


def eval_lut(init: int, inputs: list[int]) -> int:
    index = sum((bit & 1) << pos for pos, bit in enumerate(inputs))
    return (init >> index) & 1


def recover_password(netlist: EdifNetlist) -> tuple[str, dict[str, int]]:
    matches: list[dict[str, int]] = []
    for value in range(1 << 10):
        switches = {f"SW{i}": (value >> i) & 1 for i in range(10)}
        if evaluate_outputs(netlist, switches).get("LD15") == 1:
            matches.append(switches)
    if len(matches) != 1:
        raise ValueError(f"expected one password combination, found {len(matches)}")
    switches = matches[0]
    digits = "".join(str(i) for i in range(10) if switches[f"SW{i}"])
    return digits.ljust(5, "X"), switches


def decode_value_a(netlist: EdifNetlist) -> str:
    initial = {f"SW{i}": 0 for i in range(10)}
    vector = segment_vector(evaluate_outputs(netlist, initial))
    try:
        return SEGMENT_VALUE_A_MAP[vector]
    except KeyError as exc:
        raise ValueError(f"unknown EE2026 ValueA segment vector {vector}") from exc


def decode_alphabet_b(netlist: EdifNetlist, switches: Mapping[str, int]) -> str:
    vector = segment_vector(evaluate_outputs(netlist, switches))
    try:
        return SEGMENT_ALPHABET_MAP[vector]
    except KeyError as exc:
        raise ValueError(f"unknown EE2026 AlphabetB segment vector {vector}") from exc


def decode_value_c(netlist: EdifNetlist, switches: Mapping[str, int]) -> str:
    outputs = evaluate_outputs(netlist, switches)
    enabled = frozenset(port for port in ("AN3", "AN2", "AN1", "AN0") if outputs[port] == 0)
    try:
        return ANODE_VALUE_MAP[enabled]
    except KeyError as exc:
        raise ValueError(f"unknown EE2026 ValueC anode pattern {sorted(enabled)}") from exc


def segment_vector(outputs: Mapping[str, int]) -> tuple[int, ...]:
    return tuple(outputs[name] for name in ("A", "B", "C", "D", "E", "F", "G"))


def solve_project(project_zip: Path = DEFAULT_ARCHIVE) -> dict[str, object]:
    edif = extract_edif_from_project(project_zip)
    netlist = parse_edif(edif)
    password, switches = recover_password(netlist)
    value_a = decode_value_a(netlist)
    alphabet_b = decode_alphabet_b(netlist, switches)
    value_c = decode_value_c(netlist, switches)
    student_id = f"{value_a}{password.lower()}{alphabet_b}{value_c}"
    lut_inits = sorted(inst.init_text for inst in netlist.instances.values() if inst.init_text)
    return {
        "student_id": student_id,
        "value_a": value_a,
        "password": password,
        "alphabet_b": alphabet_b,
        "value_c": value_c,
        "switches_on": [name for name, value in sorted(switches.items()) if value],
        "lut_inits": lut_inits,
        "flag": f"grey{{{student_id}}}",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay NUS Welcome CTF EE2026 by extracting and simulating the Vivado EDIF netlist.")
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE, help="Path to graded_post_lab_assignment_1.zip")
    args = parser.parse_args()

    result = solve_project(args.archive)
    print("challenge: EE2026")
    print(f"artifact: {args.archive}")
    print("method: extract main.dcp from Vivado archive, read main.edf, evaluate LUT netlist")
    print(f"value_a: {result['value_a']}")
    print(f"password: {result['password']}")
    print(f"switches_on: {','.join(result['switches_on'])}")
    print(f"alphabet_b: {result['alphabet_b']}")
    print(f"value_c: {result['value_c']}")
    print(f"student_id: {result['student_id']}")
    print(f"lut_inits: {', '.join(result['lut_inits'])}")
    print(f"flag: {result['flag']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

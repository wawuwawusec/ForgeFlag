from __future__ import annotations

from forgeflag.domain import ChallengeCategory


DEFAULT_CTF_CHALLENGE_ASSUMPTION = (
    "This is a local or authorized CTF challenge. Attachments are local or explicitly provided by the user. "
    "The goal is solving the challenge, reproducing the flag, and preserving replay evidence."
)


def ctf_scope_evidence(category: ChallengeCategory | str) -> dict[str, object]:
    value = category.value if isinstance(category, ChallengeCategory) else str(category)
    if value == ChallengeCategory.WEB.value:
        return web_ctf_scope_evidence()
    if value == ChallengeCategory.REVERSE.value:
        return reverse_ctf_scope_evidence()
    if value == ChallengeCategory.PWN.value:
        return pwn_ctf_scope_evidence()
    if value == ChallengeCategory.CRYPTO.value:
        return crypto_ctf_scope_evidence()
    if value == ChallengeCategory.FORENSICS.value:
        return forensics_ctf_scope_evidence()
    if value == ChallengeCategory.TRAFFIC.value:
        return traffic_ctf_scope_evidence()
    if value == ChallengeCategory.MISC.value:
        return misc_ctf_scope_evidence()
    if value == ChallengeCategory.INFRA.value:
        return infra_ctf_scope_evidence()
    if value == ChallengeCategory.RECON.value:
        return recon_ctf_scope_evidence()
    return generic_ctf_scope_evidence(value)


def generic_ctf_scope_evidence(category: str = "unknown") -> dict[str, object]:
    return {
        "research_context": "local_or_authorized_ctf_lab",
        "category": category,
        "default_mode": "challenge evidence, reproducible replay steps, and bounded tooling",
        "allowed_targets": ["local artifacts", "owned fixtures", "explicitly authorized CTF/lab targets"],
        "boundary": "no unscoped or real-world unauthorized use",
        "preferred_wording": ["challenge evidence", "local artifact", "authorized CTF target", "replay steps"],
        "default_user_assumption": DEFAULT_CTF_CHALLENGE_ASSUMPTION,
    }


def web_ctf_scope_evidence() -> dict[str, object]:
    return {
        "research_context": "local_or_authorized_ctf_lab",
        "category": "web",
        "default_mode": "scoped request/response evidence before payloads",
        "allowed_targets": ["local fixtures", "explicitly authorized CTF web targets"],
        "boundary": "no unscoped scanning or real-world unauthorized use",
        "preferred_wording": ["challenge route", "scoped request", "response evidence", "authorized target"],
    }


def reverse_ctf_scope_evidence() -> dict[str, object]:
    return {
        "research_context": "local_or_authorized_ctf_lab",
        "category": "reverse",
        "default_mode": "local artifact analysis and validation-logic recovery",
        "allowed_targets": ["provided binaries", "firmware", "ROMs", "challenge attachments"],
        "boundary": "analyze local artifacts; do not frame as real-world malware or intrusion work unless the challenge says so",
        "preferred_wording": ["local binary", "static evidence", "validation logic", "solve script"],
    }


def pwn_ctf_scope_evidence() -> dict[str, object]:
    return {
        "research_context": "local_or_authorized_ctf_lab",
        "category": "pwn",
        "default_mode": "local crash reproduction and proof-of-solve harnesses",
        "allowed_targets": ["local vulnerable binaries", "explicitly authorized CTF services"],
        "boundary": "no persistence, lateral movement, or use against systems outside the challenge",
        "preferred_wording": ["challenge service", "local crash reproduction", "offset evidence", "proof-of-solve harness"],
    }


def crypto_ctf_scope_evidence() -> dict[str, object]:
    return {
        "research_context": "local_or_authorized_ctf_lab",
        "category": "crypto",
        "default_mode": "local parameter extraction, primitive classification, and reproducible solve scripts",
        "allowed_targets": ["challenge text", "local attachments", "provided public parameters"],
        "boundary": "do not frame as unauthorized decryption of third-party data",
        "preferred_wording": ["challenge parameters", "known plaintext", "solver script", "replay evidence"],
    }


def forensics_ctf_scope_evidence() -> dict[str, object]:
    return {
        "research_context": "local_or_authorized_ctf_lab",
        "category": "forensics",
        "default_mode": "local artifact triage, metadata review, carving, and evidence preservation",
        "allowed_targets": ["registered attachments", "owned fixture files", "provided disk/memory/log artifacts"],
        "boundary": "analyze provided files only; do not imply collection from unrelated systems",
        "preferred_wording": ["local artifact", "metadata evidence", "carved output", "registered attachment"],
    }


def traffic_ctf_scope_evidence() -> dict[str, object]:
    return {
        "research_context": "local_or_authorized_ctf_lab",
        "category": "traffic",
        "default_mode": "offline packet-capture analysis and stream reconstruction",
        "allowed_targets": ["provided pcap/pcapng/cap attachments", "owned fixture captures"],
        "boundary": "offline capture analysis only unless an explicit authorized lab target is configured",
        "preferred_wording": ["packet capture", "stream evidence", "offline analysis", "protocol reconstruction"],
    }


def misc_ctf_scope_evidence() -> dict[str, object]:
    return {
        "research_context": "local_or_authorized_ctf_lab",
        "category": "misc",
        "default_mode": "local puzzle routing, decoding, archive/image/audio analysis, and deterministic scripts",
        "allowed_targets": ["challenge text", "local puzzle artifacts", "owned fixtures"],
        "boundary": "keep sandbox and serialization work as local proof-of-solve reproduction",
        "preferred_wording": ["puzzle artifact", "local decode", "bounded reproduction", "challenge script"],
    }


def infra_ctf_scope_evidence() -> dict[str, object]:
    return {
        "research_context": "local_or_authorized_ctf_lab",
        "category": "infra",
        "default_mode": "scoped lab asset inventory and evidence graphing",
        "allowed_targets": ["explicitly authorized CTF lab networks", "local services"],
        "boundary": "no persistence, lateral movement, or activity outside declared lab scope",
        "preferred_wording": ["authorized lab", "scoped asset", "evidence graph", "declared boundary"],
    }


def recon_ctf_scope_evidence() -> dict[str, object]:
    return {
        "research_context": "local_or_authorized_ctf_lab",
        "category": "recon",
        "default_mode": "passive challenge triage before specialist routing",
        "allowed_targets": ["challenge metadata", "local artifacts", "explicitly allowlisted targets"],
        "boundary": "avoid broad probing; escalate only through scoped specialist solvers",
        "preferred_wording": ["challenge triage", "category hint", "scoped metadata", "specialist routing"],
    }

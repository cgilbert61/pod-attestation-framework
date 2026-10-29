"""Phase 0 Worked Example: A single synthetic file attested end-to-end by hand — hashed, classified, signed — plus verification and tamper rejection."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from engine.classifier import PresidioClassifier
from registry.signing import (
    Keyring,
    SignatureVerificationError,
    build_attestation_statement,
    compute_file_sha256,
    sign_statement,
    verify_dsse_envelope,
)


def run_phase0_worked_example(work_dir: Path | None = None) -> dict[str, object]:
    base_dir = work_dir or Path(tempfile.mkdtemp(prefix="pod_phase0_"))
    base_dir.mkdir(parents=True, exist_ok=True)

    # 1. Create synthetic file
    synthetic_file = base_dir / "synthetic_clinical_summary.txt"
    synthetic_file.write_text(
        "Synthetic Clinical Study Brief\n"
        "Cohort Contact: researcher.jane@example.org\n"
        "Internal Project Tag: PROJ-GENOME9\n",
        encoding="utf-8",
    )

    # 2. Compute SHA-256 fingerprint
    file_sha256 = compute_file_sha256(synthetic_file)

    # 3. Classify content (types and counts only, never values)
    classifier = PresidioClassifier()
    verdict = classifier.classify_text(synthetic_file.read_text(encoding="utf-8"))

    # 4. Generate local operator keys (Ed25519) & build in-toto Statement v1
    keyring = Keyring(base_dir / "keys")
    key_meta = keyring.generate_key(algorithm="Ed25519", operator_id="phase0-operator")

    locator = "file:///synthetic/synthetic_clinical_summary.txt"
    statement = build_attestation_statement(
        locator=locator,
        content_sha256=file_sha256,
        tier=verdict.tier,
        owner="clinical-data-steward@example.org",
        object_type="document",
        display_name=synthetic_file.name,
        environment="synthetic",
        confidence=verdict.confidence,
        sensitive_categories=[c.to_dict() for c in verdict.sensitive_categories],
        size_bytes=synthetic_file.stat().st_size,
    )

    # 5. Sign into a DSSE envelope
    envelope = sign_statement(statement, keyring)
    envelope_path = base_dir / "synthetic_clinical_summary.dsse.json"
    envelope_path.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")

    # 6. Verify valid record + untampered file
    verification = verify_dsse_envelope(
        envelope=envelope,
        keyring=keyring,
        expected_content_sha256=compute_file_sha256(synthetic_file),
    )

    # 7. Verify tampered file copy FAILS verification
    tampered_file = base_dir / "synthetic_clinical_summary.tampered.txt"
    tampered_file.write_text(
        synthetic_file.read_text(encoding="utf-8") + "\nInjected unauthorized line\n",
        encoding="utf-8",
    )
    tampered_file_rejected = False
    try:
        verify_dsse_envelope(
            envelope=envelope,
            keyring=keyring,
            expected_content_sha256=compute_file_sha256(tampered_file),
        )
    except SignatureVerificationError:
        tampered_file_rejected = True

    # 8. Verify tampered DSSE payload FAILS verification
    tampered_envelope = json.loads(json.dumps(envelope))
    tampered_envelope["payload"] = tampered_envelope["payload"][:-4] + "AAAA"
    tampered_envelope_rejected = False
    try:
        verify_dsse_envelope(envelope=tampered_envelope, keyring=keyring)
    except SignatureVerificationError:
        tampered_envelope_rejected = True

    return {
        "locator": locator,
        "file_sha256": file_sha256,
        "tier": verdict.tier,
        "sensitive_categories": [c.to_dict() for c in verdict.sensitive_categories],
        "keyid": key_meta["keyid"],
        "verified": verification.verified,
        "tampered_file_rejected": tampered_file_rejected,
        "tampered_envelope_rejected": tampered_envelope_rejected,
        "envelope_path": str(envelope_path),
    }


if __name__ == "__main__":
    result = run_phase0_worked_example(Path("./examples/out_phase0"))
    print(json.dumps(result, indent=2))

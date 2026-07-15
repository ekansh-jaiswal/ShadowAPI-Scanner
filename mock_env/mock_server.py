"""
mock_env/mock_server.py
=======================
SwasthyaConnect – Fictional Indian Digital Health Gateway (Mock)
================================================================
A Flask server simulating a health-API gateway for the Shadow API Scanner demo.

DOCUMENTED endpoints (present in openapi_spec.yaml):
  GET  /api/v1/patients/{id}          – requires Bearer token
  POST /api/v1/appointments           – requires Bearer token
  GET  /api/v1/doctors/{id}           – requires Bearer token
  GET  /api/v1/health                 – public

SHADOW / UNDOCUMENTED endpoints (NOT in the spec – what the scanner should find):
  GET    /api/v1/patient-records/{id}            – BOLA-vulnerable, no ownership check
  GET    /api/v1/internal/debug/patient/{id}     – no auth, excessive data exposure
  DELETE /api/v1/appointments/{id}               – undocumented method on known path
  GET    /api/v1/patients/{id}/insurance-claims  – no rate-limit, excessive exposure
  GET    /api/v1/otp/verify                      – no rate-limit OTP endpoint

Usage:
  python mock_env/mock_server.py            # default port 8000
  python mock_env/mock_server.py --port 9000
"""

import argparse
import json
from flask import Flask, request, jsonify

app = Flask(__name__)
PATIENTS: dict[int, dict] = {
    101: {
        "id": 101,
        "name": "Patient_001",
        "age": 34,
        "gender": "F",
        "abha_id": "ABHA-FAKE-0001",
        "aadhaar_number": "000011110001",
        "dob": "1992-03-15",
        "blood_group": "O+",
        "diagnosis": "Hypertension Stage 1",
        "prescription": ["Amlodipine 5mg", "Lifestyle changes"],
        "insurance_claims": [
            {"claim_id": "CLM-2025-001", "amount": 12000, "status": "approved"},
            {"claim_id": "CLM-2025-002", "amount": 8500, "status": "pending"},
        ],
        "internal_notes": "Patient flagged for follow-up; debt outstanding on account.",
        "ssn": "NOT-APPLICABLE",
    },
    102: {
        "id": 102,
        "name": "Patient_002",
        "age": 45,
        "gender": "M",
        "abha_id": "ABHA-FAKE-0002",
        "aadhaar_number": "000022220002",
        "dob": "1981-07-22",
        "blood_group": "A+",
        "diagnosis": "Type 2 Diabetes",
        "prescription": ["Metformin 500mg", "Dietary counselling"],
        "insurance_claims": [
            {"claim_id": "CLM-2025-003", "amount": 25000, "status": "approved"},
        ],
        "internal_notes": "Regular follow-up every 3 months.",
        "ssn": "NOT-APPLICABLE",
    },
    103: {
        "id": 103,
        "name": "Patient_003",
        "age": 28,
        "gender": "F",
        "abha_id": "ABHA-FAKE-0003",
        "aadhaar_number": "000033330003",
        "dob": "1998-11-05",
        "blood_group": "B-",
        "diagnosis": "Anemia (Iron Deficiency)",
        "prescription": ["Ferrous sulphate 200mg"],
        "insurance_claims": [],
        "internal_notes": "Referred to nutrition specialist.",
        "ssn": "NOT-APPLICABLE",
    },
    104: {
        "id": 104,
        "name": "Patient_004",
        "age": 55,
        "gender": "M",
        "abha_id": "ABHA-FAKE-0004",
        "aadhaar_number": "000044440004",
        "dob": "1971-01-30",
        "blood_group": "AB+",
        "diagnosis": "Chronic Kidney Disease Stage 3",
        "prescription": ["Losartan 50mg", "Phosphate binders"],
        "insurance_claims": [
            {"claim_id": "CLM-2025-004", "amount": 65000, "status": "approved"},
            {"claim_id": "CLM-2025-005", "amount": 42000, "status": "under-review"},
        ],
        "internal_notes": "Nephrologist consultation scheduled.",
        "ssn": "NOT-APPLICABLE",
    },
    105: {
        "id": 105,
        "name": "Patient_005",
        "age": 62,
        "gender": "F",
        "abha_id": "ABHA-FAKE-0005",
        "aadhaar_number": "000055550005",
        "dob": "1964-05-18",
        "blood_group": "O-",
        "diagnosis": "Osteoarthritis (Knee)",
        "prescription": ["Diclofenac gel", "Physiotherapy"],
        "insurance_claims": [
            {"claim_id": "CLM-2025-006", "amount": 18000, "status": "approved"},
        ],
        "internal_notes": "Surgical opinion pending.",
        "ssn": "NOT-APPLICABLE",
    },
    106: {
        "id": 106,
        "name": "Patient_006",
        "age": 19,
        "gender": "M",
        "abha_id": "ABHA-FAKE-0006",
        "aadhaar_number": "000066660006",
        "dob": "2007-09-12",
        "blood_group": "A-",
        "diagnosis": "Asthma (Mild Persistent)",
        "prescription": ["Salbutamol inhaler", "Budesonide inhaler"],
        "insurance_claims": [],
        "internal_notes": "Allergy trigger: dust mites.",
        "ssn": "NOT-APPLICABLE",
    },
    107: {
        "id": 107,
        "name": "Patient_007",
        "age": 38,
        "gender": "F",
        "abha_id": "ABHA-FAKE-0007",
        "aadhaar_number": "000077770007",
        "dob": "1988-02-25",
        "blood_group": "B+",
        "diagnosis": "Polycystic Ovary Syndrome",
        "prescription": ["Metformin 500mg", "Clomifene"],
        "insurance_claims": [
            {"claim_id": "CLM-2025-007", "amount": 9500, "status": "approved"},
        ],
        "internal_notes": "Fertility treatment underway.",
        "ssn": "NOT-APPLICABLE",
    },
    108: {
        "id": 108,
        "name": "Patient_008",
        "age": 71,
        "gender": "M",
        "abha_id": "ABHA-FAKE-0008",
        "aadhaar_number": "000088880008",
        "dob": "1955-12-03",
        "blood_group": "AB-",
        "diagnosis": "Ischemic Heart Disease",
        "prescription": ["Aspirin 75mg", "Atorvastatin 40mg", "Bisoprolol 5mg"],
        "insurance_claims": [
            {"claim_id": "CLM-2025-008", "amount": 120000, "status": "approved"},
            {"claim_id": "CLM-2025-009", "amount": 85000, "status": "approved"},
        ],
        "internal_notes": "Post-MI follow-up; cardiac rehab enrolled.",
        "ssn": "NOT-APPLICABLE",
    },
    109: {
        "id": 109,
        "name": "Patient_009",
        "age": 44,
        "gender": "F",
        "abha_id": "ABHA-FAKE-0009",
        "aadhaar_number": "000099990009",
        "dob": "1982-06-14",
        "blood_group": "O+",
        "diagnosis": "Migraine (Chronic)",
        "prescription": ["Sumatriptan 50mg", "Amitriptyline 10mg"],
        "insurance_claims": [],
        "internal_notes": "Trigger diary recommended.",
        "ssn": "NOT-APPLICABLE",
    },
    110: {
        "id": 110,
        "name": "Patient_010",
        "age": 52,
        "gender": "M",
        "abha_id": "ABHA-FAKE-0010",
        "aadhaar_number": "000010100010",
        "dob": "1974-04-09",
        "blood_group": "A+",
        "diagnosis": "GERD",
        "prescription": ["Omeprazole 20mg", "Antacids"],
        "insurance_claims": [
            {"claim_id": "CLM-2025-010", "amount": 4500, "status": "approved"},
        ],
        "internal_notes": "Endoscopy recommended if no improvement.",
        "ssn": "NOT-APPLICABLE",
    },
    111: {
        "id": 111,
        "name": "Patient_011",
        "age": 30,
        "gender": "F",
        "abha_id": "ABHA-FAKE-0011",
        "aadhaar_number": "000011110011",
        "dob": "1996-08-20",
        "blood_group": "B+",
        "diagnosis": "Hypothyroidism",
        "prescription": ["Levothyroxine 50mcg"],
        "insurance_claims": [],
        "internal_notes": "Annual TSH monitoring.",
        "ssn": "NOT-APPLICABLE",
    },
    112: {
        "id": 112,
        "name": "Patient_012",
        "age": 67,
        "gender": "M",
        "abha_id": "ABHA-FAKE-0012",
        "aadhaar_number": "000012120012",
        "dob": "1959-10-28",
        "blood_group": "O-",
        "diagnosis": "Parkinson's Disease (Early Stage)",
        "prescription": ["Levodopa/Carbidopa"],
        "insurance_claims": [
            {"claim_id": "CLM-2025-011", "amount": 35000, "status": "under-review"},
        ],
        "internal_notes": "Neurology follow-up every 6 months.",
        "ssn": "NOT-APPLICABLE",
    },
    113: {
        "id": 113,
        "name": "Patient_013",
        "age": 23,
        "gender": "F",
        "abha_id": "ABHA-FAKE-0013",
        "aadhaar_number": "000013130013",
        "dob": "2003-03-07",
        "blood_group": "A-",
        "diagnosis": "Anxiety Disorder (Generalised)",
        "prescription": ["Sertraline 50mg", "Cognitive Behavioural Therapy"],
        "insurance_claims": [],
        "internal_notes": "Counsellor referral sent.",
        "ssn": "NOT-APPLICABLE",
    },
    114: {
        "id": 114,
        "name": "Patient_014",
        "age": 49,
        "gender": "M",
        "abha_id": "ABHA-FAKE-0014",
        "aadhaar_number": "000014140014",
        "dob": "1977-07-17",
        "blood_group": "B-",
        "diagnosis": "Psoriasis (Moderate)",
        "prescription": ["Betamethasone cream", "Calcipotriol ointment"],
        "insurance_claims": [
            {"claim_id": "CLM-2025-012", "amount": 7200, "status": "approved"},
        ],
        "internal_notes": "UV therapy option discussed.",
        "ssn": "NOT-APPLICABLE",
    },
    115: {
        "id": 115,
        "name": "Patient_015",
        "age": 58,
        "gender": "F",
        "abha_id": "ABHA-FAKE-0015",
        "aadhaar_number": "000015150015",
        "dob": "1968-11-11",
        "blood_group": "AB+",
        "diagnosis": "Breast Cancer (Stage II, in remission)",
        "prescription": ["Tamoxifen 20mg"],
        "insurance_claims": [
            {"claim_id": "CLM-2025-013", "amount": 280000, "status": "approved"},
            {"claim_id": "CLM-2025-014", "amount": 95000, "status": "approved"},
        ],
        "internal_notes": "Oncology review every 6 months; mammogram annually.",
        "ssn": "NOT-APPLICABLE",
    },
}

DOCTORS: dict[int, dict] = {
    1: {"id": 1, "name": "Dr. Aryan Mehta", "speciality": "Cardiology", "hospital": "Apollo Fictional Hospital"},
    2: {"id": 2, "name": "Dr. Priya Nair", "speciality": "Nephrology", "hospital": "AIIMS Fictional"},
    3: {"id": 3, "name": "Dr. Vikram Singh", "speciality": "Neurology", "hospital": "Fortis Fictional"},
    4: {"id": 4, "name": "Dr. Sunita Reddy", "speciality": "Endocrinology", "hospital": "Max Fictional"},
    5: {"id": 5, "name": "Dr. Rajesh Kumar", "speciality": "General Medicine", "hospital": "City Fictional Clinic"},
}

APPOINTMENTS: dict[int, dict] = {
    1001: {"id": 1001, "patient_id": 101, "doctor_id": 1, "date": "2026-07-10", "slot": "10:00", "status": "confirmed"},
    1002: {"id": 1002, "patient_id": 102, "doctor_id": 4, "date": "2026-07-11", "slot": "14:30", "status": "confirmed"},
    1003: {"id": 1003, "patient_id": 104, "doctor_id": 2, "date": "2026-07-12", "slot": "09:00", "status": "pending"},
}
VALID_TOKENS = {
    "token-patient-101": 101,
    "token-patient-102": 102,
    "token-patient-103": 103,
    "token-patient-104": 104,
    "token-patient-105": 105,
    "token-doctor-1": None,  # doctor tokens have no patient ID
    "token-admin-99": None,
}
OTP_STORE: dict[str, str] = {
    "101": "482915",
    "102": "739204",
    "103": "156837",
    "104": "924561",
    "105": "371082",
}
def _get_token() -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def _require_auth():
    """Returns (token, patient_id_or_None, error_response_or_None)."""
    token = _get_token()
    if not token or token not in VALID_TOKENS:
        return None, None, (jsonify({"error": "Unauthorized", "code": 401}), 401)
    return token, VALID_TOKENS[token], None
@app.route("/api/v1/health", methods=["GET"])
def health_check():
    """Public health check – no auth required."""
    return jsonify({
        "status": "ok",
        "service": "SwasthyaConnect API Gateway",
        "version": "1.0.0",
        "environment": "mock-demo",
    })


@app.route("/api/v1/patients/<int:patient_id>", methods=["GET"])
def get_patient(patient_id: int):
    """
    DOCUMENTED. Requires auth. Returns MINIMAL demographic info only –
    deliberately NO diagnosis/aadhaar (the 'correct' secure version).
    """
    token, token_patient_id, err = _require_auth()
    if err:
        return err

    patient = PATIENTS.get(patient_id)
    if not patient:
        return jsonify({"error": "Patient not found", "code": 404}), 404
    return jsonify({
        "id": patient["id"],
        "name": patient["name"],
        "age": patient["age"],
        "gender": patient["gender"],
        "blood_group": patient["blood_group"],
        "abha_id": patient["abha_id"],
    })


@app.route("/api/v1/appointments", methods=["POST"])
def create_appointment():
    """DOCUMENTED. Requires auth. Create a new appointment."""
    _, _, err = _require_auth()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    if not data.get("patient_id") or not data.get("doctor_id"):
        return jsonify({"error": "patient_id and doctor_id are required", "code": 400}), 400

    new_id = max(APPOINTMENTS.keys(), default=1000) + 1
    appt = {
        "id": new_id,
        "patient_id": data["patient_id"],
        "doctor_id": data["doctor_id"],
        "date": data.get("date", "2026-07-15"),
        "slot": data.get("slot", "10:00"),
        "status": "pending",
    }
    APPOINTMENTS[new_id] = appt
    return jsonify(appt), 201


@app.route("/api/v1/doctors/<int:doctor_id>", methods=["GET"])
def get_doctor(doctor_id: int):
    """DOCUMENTED. Requires auth."""
    _, _, err = _require_auth()
    if err:
        return err

    doctor = DOCTORS.get(doctor_id)
    if not doctor:
        return jsonify({"error": "Doctor not found", "code": 404}), 404
    return jsonify(doctor)
@app.route("/api/v1/patient-records/<int:patient_id>", methods=["GET"])
def get_patient_record_legacy(patient_id: int):
    """
    SHADOW – BOLA-VULNERABLE.
    Legacy endpoint: uses 'patient-records' not 'patients'.
    No ownership check – any valid token (or even the wrong token) gets the
    FULL record including aadhaar_number, diagnosis, prescription.
    This is the flagship BOLA demo endpoint.
    """
    token = _get_token()
    if not token or token not in VALID_TOKENS:
        return jsonify({"error": "Unauthorized", "code": 401}), 401

    patient = PATIENTS.get(patient_id)
    if not patient:
        return jsonify({"error": "Patient record not found", "code": 404}), 404
    return jsonify({
        "id": patient["id"],
        "name": patient["name"],
        "age": patient["age"],
        "gender": patient["gender"],
        "dob": patient["dob"],
        "blood_group": patient["blood_group"],
        "abha_id": patient["abha_id"],
        "aadhaar_number": patient["aadhaar_number"],
        "diagnosis": patient["diagnosis"],
        "prescription": patient["prescription"],
    })


@app.route("/api/v1/internal/debug/patient/<int:patient_id>", methods=["GET"])
def debug_patient(patient_id: int):
    """
    SHADOW – CRITICAL: NO AUTH + EXCESSIVE DATA EXPOSURE.
    Internal debug route left in production. Returns raw 'DB row' including
    internal_notes, aadhaar_number, and all fields. No authentication at all.
    """
    patient = PATIENTS.get(patient_id)
    if not patient:
        return jsonify({"error": "Not found", "code": 404}), 404
    return jsonify(patient)


@app.route("/api/v1/appointments/<int:appt_id>", methods=["DELETE"])
def delete_appointment(appt_id: int):
    """
    SHADOW – IMPROPER INVENTORY MANAGEMENT.
    DELETE method on /appointments/{id} is not in the spec (only POST is documented).
    Requires auth but the method itself is undocumented.
    """
    _, _, err = _require_auth()
    if err:
        return err

    if appt_id not in APPOINTMENTS:
        return jsonify({"error": "Appointment not found", "code": 404}), 404

    del APPOINTMENTS[appt_id]
    return jsonify({"message": f"Appointment {appt_id} deleted", "status": "success"})


@app.route("/api/v1/patients/<int:patient_id>/insurance-claims", methods=["GET"])
def get_insurance_claims(patient_id: int):
    """
    SHADOW – EXCESSIVE DATA EXPOSURE + RATE LIMITING ABSENCE.
    No rate limiting. Returns full claims history with financial amounts.
    Any valid token can access any patient's claims (another ownership-bypass).
    """
    _, _, err = _require_auth()
    if err:
        return err

    patient = PATIENTS.get(patient_id)
    if not patient:
        return jsonify({"error": "Patient not found", "code": 404}), 404

    return jsonify({
        "patient_id": patient_id,
        "patient_name": patient["name"],
        "aadhaar_number": patient["aadhaar_number"],   # unnecessary PII leak
        "total_claims": len(patient["insurance_claims"]),
        "claims": patient["insurance_claims"],
        "diagnosis": patient["diagnosis"],             # unnecessary leak
    })


@app.route("/api/v1/otp/verify", methods=["GET"])
def verify_otp():
    """
    SHADOW – RATE LIMITING ABSENCE (OTP brute-force).
    No rate limiting, no lockout, no account freezing after N attempts.
    Classic real-world vuln: attacker can enumerate OTPs.
    """
    patient_id = request.args.get("patient_id", "")
    otp = request.args.get("otp", "")

    if not patient_id or not otp:
        return jsonify({"error": "patient_id and otp are required", "code": 400}), 400

    correct_otp = OTP_STORE.get(str(patient_id))
    if correct_otp is None:
        return jsonify({"error": "Patient not found", "code": 404}), 404

    if otp == correct_otp:
        return jsonify({
            "status": "verified",
            "patient_id": patient_id,
            "message": "OTP verified successfully. Session token issued.",
            "session_token": f"sess-fake-{patient_id}-ABCD1234",
        })
    else:
        return jsonify({"status": "invalid", "message": "Incorrect OTP"}), 401
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SwasthyaConnect Mock API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║     SwasthyaConnect – Mock API Gateway (Shadow API Scanner)      ║
╠══════════════════════════════════════════════════════════════════╣
║  Listening on: http://{args.host}:{args.port:<38}║
║                                                                  ║
║  DOCUMENTED ENDPOINTS (in openapi_spec.yaml):                    ║
║    GET  /api/v1/health                 (public)                  ║
║    GET  /api/v1/patients/{{id}}          (auth required)           ║
║    POST /api/v1/appointments           (auth required)           ║
║    GET  /api/v1/doctors/{{id}}           (auth required)           ║
║                                                                  ║
║  SHADOW ENDPOINTS (not in spec – scanner should find these):     ║
║    GET    /api/v1/patient-records/{{id}}          [BOLA-vuln]      ║
║    GET    /api/v1/internal/debug/patient/{{id}}   [no-auth]        ║
║    DELETE /api/v1/appointments/{{id}}             [undoc method]   ║
║    GET    /api/v1/patients/{{id}}/insurance-claims [rate-limit]    ║
║    GET    /api/v1/otp/verify                      [OTP brute]     ║
║                                                                  ║
║  Test token: Authorization: Bearer token-patient-101             ║
╚══════════════════════════════════════════════════════════════════╝
""")
    app.run(host=args.host, port=args.port, debug=args.debug)

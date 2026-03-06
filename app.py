from __future__ import annotations

import pickle
from pathlib import Path
from typing import Literal, Optional

import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

import Intrusion.sliding_window.feature_extraction as fex

APP_NAME = "BlackTrace HIDS API"
MODEL_PATH = Path("models") / "IsoForest.pkl"

FEATURE_COLUMNS = [
    "packet_per_sec",
    "syn_ratio",
    "avg_size",
    "unique_ips",
    "unique_ports",
]


def anomaly_tagger(pred: int) -> Literal["ANOMALY", "NORMAL"]:
    return "ANOMALY" if pred == -1 else "NORMAL"


def threat_level(decision_score: float) -> Literal["CATASTROPHIC", "HIGH", "SAFE", "UNKNOWN"]:
    if decision_score < -2.0:
        return "CATASTROPHIC"
    if -2.0 < decision_score < 0:
        return "HIGH"
    if decision_score > 0:
        return "SAFE"
    return "UNKNOWN"


def load_model():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found at: {MODEL_PATH}")
    with MODEL_PATH.open("rb") as f:
        return pickle.load(f)


def latest_feature_row() -> pd.DataFrame:
    if not hasattr(fex, "latest_feature_vector"):
        raise RuntimeError("No feature vector available yet. Traffic capture may not have produced any window.")

    df = fex.latest_feature_vector
    if df is None or df.empty:
        raise RuntimeError("Latest feature vector is empty.")

    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise RuntimeError(f"Missing required feature columns: {missing}")

    return df


def run_inference(model, df: pd.DataFrame):
    X = df[FEATURE_COLUMNS]
    pred = int(model.predict(X)[0])
    score = float(model.decision_function(X)[0])

    level = threat_level(score)

    potential_attacker: Optional[str] = None
    if level in ("HIGH", "CATASTROPHIC") and "top_ip" in df.columns:
        val = df["top_ip"].iloc[0]
        if isinstance(val, str) and val != "None":
            potential_attacker = val

    return {
        "status": anomaly_tagger(pred),
        "threat_level": level,
        "decision_score": score,
        "potential_attacker": potential_attacker,
    }


class InferenceResponse(BaseModel):
    status: Literal["ANOMALY", "NORMAL"]
    threat_level: Literal["CATASTROPHIC", "HIGH", "SAFE", "UNKNOWN"]
    decision_score: float
    potential_attacker: Optional[str] = None


class FeaturesRequest(BaseModel):
    packet_per_sec: float = Field(..., ge=0)
    syn_ratio: float = Field(..., ge=0, le=1)
    avg_size: float = Field(..., ge=0)
    unique_ips: int = Field(..., ge=0)
    unique_ports: int = Field(..., ge=0)
    potential_attacker: Optional[str] = None


app = FastAPI(title=APP_NAME, version="1.0.0")
model = load_model()


@app.get("/health")
def health():
    return {"status": "ok", "model_path": str(MODEL_PATH)}


@app.get("/inference/latest", response_model=InferenceResponse)
def inference_latest():
    try:
        df = latest_feature_row()
        result = run_inference(model, df)
        return result
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference failed: {e}")


@app.post("/inference", response_model=InferenceResponse)
def inference_from_features(body: FeaturesRequest):
    try:
        payload = body.model_dump()
        if payload.get("potential_attacker") is not None:
            payload["top_ip"] = payload["potential_attacker"]

        df = pd.DataFrame([payload])
        result = run_inference(model, df)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference failed: {e}")

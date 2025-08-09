# detection/anomaly_detector.py
import logging
import numpy as np
import pandas as pd
from pyod.models.knn import KNN
from datetime import datetime

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, contamination=0.1, n_neighbors=5):
        self.contamination = contamination
        self.model = KNN(contamination=contamination, n_neighbors=n_neighbors)
        self.is_fitted = False
        self.scaler = None
        self.feature_buffer = []  # Store recent events for batch detection
        logger.info("[ANOMALY] Initialized KNN-based anomaly detector.")

    def extract_features(self, event):
        """
        Convert structured log event into numeric features.
        Example features: time_of_day, login_attempts, IP frequency, etc.
        """
        try:
            # Simulate numeric features from event
            timestamp = datetime.fromisoformat(event.get("timestamp", datetime.utcnow().isoformat()).replace("Z", ""))
            hour = timestamp.hour
            is_failed_login = 1 if event.get("event_type") == "failed_login" else 0
            is_external_ip = 1 if event.get("ip", "").startswith("192.168.") else 0  # Simplified
            severity_score = {"info": 0, "high": 1, "critical": 2}.get(event.get("severity", "info"), 0)

            return [hour, is_failed_login, severity_score, is_external_ip]
        except Exception as e:
            logger.debug(f"[ANOMALY] Feature extraction failed: {e}")
            return [0, 0, 0, 0]

    def add_event(self, event):
        """Add a new structured log event for real-time anomaly checking"""
        features = self.extract_features(event)
        self.feature_buffer.append(features)

        # Retrain every 10 events
        if len(self.feature_buffer) >= 10 and not self.is_fitted:
            self.train()
        elif len(self.feature_buffer) >= 20:
            # Keep buffer size under control
            self.feature_buffer = self.feature_buffer[-10:]
            self.train()

    def train(self):
        """Train KNN model on recent behavior"""
        X = np.array(self.feature_buffer)
        try:
            self.model.fit(X)
            self.is_fitted = True
            logger.info("[ANOMALY] Model trained on recent log patterns.")
        except Exception as e:
            logger.error(f"[ANOMALY] Training failed: {e}")

    def detect(self, event):
        """Check if a single event is anomalous"""
        if not self.is_fitted:
            return None

        features = np.array([self.extract_features(event)])
        pred = self.model.predict(features)[0]
        score = self.model.decision_function(features)[0]

        if pred == 1:
            alert = {
                "anomaly_type": "behavioral_outlier",
                "confidence_score": float(score),
                "event": event,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            logger.warning(f"[ANOMALY] Detected: {alert}")
            return alert
        return None
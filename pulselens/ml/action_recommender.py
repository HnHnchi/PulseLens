#!/usr/bin/env python3
"""
ML-based Action Recommendation System for PulseLens
Integrates machine learning with rule-based logic for IOC action recommendations.
"""

import os
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

class IOCActionRecommender:
    """ML-based IOC action recommendation system."""
    
    def __init__(self, model_dir: Path = None):
        """Initialize the action recommender."""
        if model_dir is None:
            model_dir = Path(__file__).parent.parent.parent / "models"
        
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        
        # Model paths
        self.model_path = self.model_dir / "ioc_action_model.pkl"
        self.ioc_encoder_path = self.model_dir / "ioc_type_encoder.pkl"
        self.action_encoder_path = self.model_dir / "action_encoder.pkl"
        self.feedback_path = self.model_dir / "action_feedback.json"
        
        # Initialize models
        self.model = None
        self.ioc_encoder = None
        self.action_encoder = None
        
        # Load existing models if available
        self._load_models()
        
        # Initialize with default training data if no model exists
        if self.model is None:
            self._train_default_model()
    
    def _load_models(self) -> bool:
        """Load existing trained models."""
        try:
            if (self.model_path.exists() and 
                self.ioc_encoder_path.exists() and 
                self.action_encoder_path.exists()):
                
                self.model = joblib.load(self.model_path)
                self.ioc_encoder = joblib.load(self.ioc_encoder_path)
                self.action_encoder = joblib.load(self.action_encoder_path)
                return True
        except Exception as e:
            print(f"Error loading models: {e}")
        
        return False
    
    def _train_default_model(self):
        """Train model with default IOC dataset."""
        # Default training data based on common security practices
        default_data = [
            # High severity IOCs
            [95, 'hash', 1, True, 'Quarantine'],
            [90, 'hash', 1, True, 'Quarantine'],
            [85, 'url', 1, True, 'Block'],
            [80, 'ip', 1, True, 'Block'],
            [75, 'domain', 1, True, 'Block'],
            [70, 'email', 1, True, 'Block'],
            
            # Medium severity IOCs
            [60, 'domain', 1, False, 'Monitor'],
            [55, 'ip', 0, False, 'Monitor'],
            [50, 'url', 1, False, 'Monitor'],
            [45, 'email', 0, False, 'Monitor'],
            [40, 'hash', 0, False, 'Monitor'],
            
            # Low severity IOCs
            [35, 'domain', 0, False, 'Log'],
            [30, 'ip', 0, False, 'Log'],
            [25, 'url', 0, False, 'Log'],
            [20, 'hash', 0, False, 'Log'],
            [15, 'email', 0, False, 'Log'],
            
            # Info severity IOCs
            [10, 'domain', 0, False, 'Log'],
            [8, 'ip', 0, False, 'Log'],
            [5, 'hash', 0, False, 'Ignore'],
            [3, 'url', 0, False, 'Ignore'],
        ]
        
        df = pd.DataFrame(default_data, columns=[
            'score', 'ioc_type', 'seen_before', 'has_enrichment', 'action'
        ])
        
        self._train_model(df)
    
    def _train_model(self, df: pd.DataFrame):
        """Train the ML model with provided data."""
        # Encode categorical features
        self.ioc_encoder = LabelEncoder()
        df['ioc_type_encoded'] = self.ioc_encoder.fit_transform(df['ioc_type'])
        
        self.action_encoder = LabelEncoder()
        df['action_encoded'] = self.action_encoder.fit_transform(df['action'])
        
        # Prepare features and target
        features = ['score', 'ioc_type_encoded', 'seen_before', 'has_enrichment']
        X = df[features]
        y = df['action_encoded']
        
        # Split and train
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        self.model = RandomForestClassifier(
            n_estimators=100, 
            random_state=42,
            max_depth=10
        )
        self.model.fit(X_train, y_train)
        
        # Evaluate
        train_score = self.model.score(X_train, y_train)
        test_score = self.model.score(X_test, y_test)
        
        print(f"Model trained - Train accuracy: {train_score:.3f}, Test accuracy: {test_score:.3f}")
        
        # Save models
        self._save_models()
    
    def _save_models(self):
        """Save trained models to disk."""
        try:
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.ioc_encoder, self.ioc_encoder_path)
            joblib.dump(self.action_encoder, self.action_encoder_path)
        except Exception as e:
            print(f"Error saving models: {e}")
    
    def get_severity_category(self, score: float) -> str:
        """Get severity category based on score."""
        if score >= 70:
            return "critical"
        elif score >= 45:
            return "high"
        elif score >= 25:
            return "medium"
        elif score >= 15:
            return "low"
        return "info"
    
    def _rule_based_recommendation(self, score: float, ioc_type: str, 
                                 has_enrichment: bool, seen_before: bool) -> str:
        """Rule-based action recommendation."""
        severity = self.get_severity_category(score)
        
        # Critical severity
        if severity == "critical":
            if ioc_type in ['hash', 'url']:
                return "Quarantine"
            else:
                return "Block"
        
        # High severity
        elif severity == "high":
            if ioc_type in ['domain', 'ip', 'email']:
                return "Block"
            else:
                return "Monitor"
        
        # Medium severity
        elif severity == "medium":
            if has_enrichment and seen_before:
                return "Monitor"
            else:
                return "Log"
        
        # Low severity
        elif severity == "low":
            if ioc_type == 'hash' and not has_enrichment:
                return "Ignore"
            else:
                return "Log"
        
        # Info severity
        else:
            return "Ignore"
    
    def _ml_recommendation(self, score: float, ioc_type: str, 
                          has_enrichment: bool, seen_before: bool) -> str:
        """ML-based action recommendation."""
        try:
            # Encode features
            if ioc_type not in self.ioc_encoder.classes_:
                # Handle unknown IOC types
                return self._rule_based_recommendation(score, ioc_type, has_enrichment, seen_before)
            
            ioc_encoded = self.ioc_encoder.transform([ioc_type])[0]
            
            # Predict - use DataFrame with proper column names to match training
            features = pd.DataFrame([{
                'score': score,
                'ioc_type_encoded': ioc_encoded,
                'seen_before': int(seen_before),
                'has_enrichment': int(has_enrichment)
            }])
            pred_encoded = self.model.predict(features)[0]
            
            return self.action_encoder.inverse_transform([pred_encoded])[0]
            
        except Exception as e:
            print(f"ML prediction error: {e}")
            return self._rule_based_recommendation(score, ioc_type, has_enrichment, seen_before)
    
    def recommend_action(self, ioc: Dict) -> Dict:
        """Recommend action for an IOC with confidence scoring."""
        score = ioc.get('severity', {}).get('score', 0)
        ioc_type = ioc.get('ioc_type', 'unknown').lower()
        seen_before = bool(ioc.get('first_seen'))  # Has first seen timestamp
        has_enrichment = bool(ioc.get('enrichment', {}).get('sources'))
        
        # Get both recommendations
        rule_action = self._rule_based_recommendation(score, ioc_type, has_enrichment, seen_before)
        ml_action = self._ml_recommendation(score, ioc_type, has_enrichment, seen_before)
        
        # Confidence calculation
        severity = self.get_severity_category(score)
        confidence = self._calculate_confidence(score, has_enrichment, seen_before)
        
        # Hybrid decision - be more conservative for low severity
        severity = self.get_severity_category(score)
        
        if severity in ["info", "low"]:
            # For low severity IOCs, always use rule-based (more conservative)
            final_action = rule_action
            method = "rule-based"
            confidence = max(confidence, 0.7)  # Increase confidence for conservative choice
        elif confidence > 0.8:
            # High confidence - use rule-based
            final_action = rule_action
            method = "rule-based"
        elif confidence > 0.5:
            # Medium confidence - use ML if different from rules
            if ml_action != rule_action:
                final_action = ml_action
                method = "ml-enhanced"
            else:
                final_action = rule_action
                method = "rule-based"
        else:
            # Low confidence - use ML
            final_action = ml_action
            method = "ml-predictive"
        
        return {
            'recommended_action': final_action,
            'confidence': confidence,
            'method': method,
            'severity': severity,
            'rule_based_action': rule_action,
            'ml_action': ml_action,
            'reasoning': self._generate_reasoning(score, ioc_type, has_enrichment, seen_before, final_action)
        }
    
    def _calculate_confidence(self, score: float, has_enrichment: bool, seen_before: bool) -> float:
        """Calculate confidence score for the recommendation."""
        confidence = 0.5  # Base confidence
        
        # Score-based confidence - penalize low scores more heavily
        if score >= 70:
            confidence += 0.3
        elif score >= 45:
            confidence += 0.2
        elif score >= 25:
            confidence += 0.1
        elif score >= 15:
            confidence += 0.05  # Low score, minimal confidence boost
        else:
            confidence -= 0.2  # Very low score, reduce confidence
        
        # Enrichment-based confidence
        if has_enrichment:
            confidence += 0.2
        else:
            confidence -= 0.1  # No enrichment reduces confidence
        
        # Historical data confidence
        if seen_before:
            confidence += 0.1
        
        # Ensure confidence doesn't go below 0.1 or above 1.0
        return max(0.1, min(confidence, 1.0))
    
    def _generate_reasoning(self, score: float, ioc_type: str, has_enrichment: bool, 
                          seen_before: bool, action: str) -> str:
        """Generate human-readable reasoning for the recommendation."""
        severity = self.get_severity_category(score)
        
        reasoning_parts = []
        reasoning_parts.append(f"Severity: {severity} (score: {score})")
        reasoning_parts.append(f"IOC type: {ioc_type}")
        
        if has_enrichment:
            reasoning_parts.append("Has threat intelligence enrichment")
        else:
            reasoning_parts.append("No enrichment data available")
        
        if seen_before:
            reasoning_parts.append("Previously observed IOC")
        else:
            reasoning_parts.append("New IOC")
        
        # Action-specific reasoning
        if action == "Quarantine":
            reasoning_parts.append("High-risk file detected - immediate quarantine recommended")
        elif action == "Block":
            reasoning_parts.append("Network/host blocking recommended")
        elif action == "Monitor":
            reasoning_parts.append("Continuous monitoring advised")
        elif action == "Log":
            reasoning_parts.append("Log for awareness and correlation")
        elif action == "Ignore":
            reasoning_parts.append("Low risk - no action required")
        
        return ". ".join(reasoning_parts)
    
    def record_feedback(self, ioc: Dict, action_taken: str, outcome: str = None):
        """Record feedback for model improvement."""
        feedback_entry = {
            'timestamp': datetime.now().isoformat(),
            'ioc_value': ioc.get('ioc_value'),
            'ioc_type': ioc.get('ioc_type'),
            'score': ioc.get('severity', {}).get('score', 0),
            'recommended_action': ioc.get('recommended_action'),
            'action_taken': action_taken,
            'outcome': outcome,
            'has_enrichment': bool(ioc.get('enrichment', {}).get('sources')),
            'seen_before': bool(ioc.get('first_seen'))
        }
        
        # Load existing feedback
        feedback_data = []
        if self.feedback_path.exists():
            try:
                with open(self.feedback_path, 'r') as f:
                    feedback_data = json.load(f)
            except:
                feedback_data = []
        
        # Add new feedback
        feedback_data.append(feedback_entry)
        
        # Save feedback
        try:
            with open(self.feedback_path, 'w') as f:
                json.dump(feedback_data, f, indent=2)
        except Exception as e:
            print(f"Error saving feedback: {e}")
        
        # Retrain model periodically (every 10 feedback entries)
        if len(feedback_data) % 10 == 0:
            self._retrain_with_feedback()
    
    def _retrain_with_feedback(self):
        """Retrain model with feedback data."""
        try:
            with open(self.feedback_path, 'r') as f:
                feedback_data = json.load(f)
            
            # Convert feedback to training data
            training_data = []
            for entry in feedback_data:
                if entry.get('outcome') == 'successful':
                    training_data.append([
                        entry['score'],
                        entry['ioc_type'],
                        int(entry['seen_before']),
                        int(entry['has_enrichment']),
                        entry['action_taken']
                    ])
            
            if len(training_data) >= 20:  # Minimum samples for retraining
                df = pd.DataFrame(training_data, columns=[
                    'score', 'ioc_type', 'seen_before', 'has_enrichment', 'action'
                ])
                self._train_model(df)
                print(f"Model retrained with {len(training_data)} feedback samples")
                
        except Exception as e:
            print(f"Error retraining model: {e}")
    
    def get_model_stats(self) -> Dict:
        """Get model statistics and performance metrics."""
        stats = {
            'model_trained': self.model is not None,
            'model_path': str(self.model_path),
            'supported_ioc_types': list(self.ioc_encoder.classes_) if self.ioc_encoder else [],
            'supported_actions': list(self.action_encoder.classes_) if self.action_encoder else [],
            'feedback_count': 0
        }
        
        if self.feedback_path.exists():
            try:
                with open(self.feedback_path, 'r') as f:
                    feedback_data = json.load(f)
                    stats['feedback_count'] = len(feedback_data)
            except:
                pass
        
        return stats

# This code does binary classification and logistic regression to determine if a brute force attack occurred
# It doesn't learn anything. Bias, weights and other parameters are hardcoded, not learned
# I'll kindly call it a pseudo-AI then :)

from datetime import datetime
import numpy as np

class ai_bruteforce:
    def __init__(self):
        self.W = np.array([[4.0], [3.5], [3.5], [4.5]]) # weights hardcored, not learned (volume, speed, time concentration, persistence)
        self.b = -4.0 # biased towards non-attack, to avoid false positives
        self.threshold = 0.7 # above this probability, it's considered an attack

        self.detections = []
        self.ip_history = {}
        self.last_detection = {}

    def extract_features(self, ip_logs): # There're multiple logs for a same IP, this function extracts features from them (single IP)
        if not ip_logs: return None

        fails = [log for log in ip_logs if not log.get('success', True)]

        if len(fails) < 2:
            return None # not enough data to make a decision
        
        timestamps = [
            datetime.fromisoformat(l['timestamp']) for l in fails
        ]

        total_attempts = len(fails)
        time_span = (max(timestamps) - min(timestamps)).total_seconds()
        time_span = max(time_span, 1)

        attempts_per_sec = total_attempts / time_span

        # Normalization
        # heuristic but it could be learned from data
        attempts_feature = min(total_attempts / 20, 1.0)      # number of failed attempts (20+ = strong attack)
        rate_feature = min(attempts_per_sec / 2, 1.0)         # rate of failed attempts (2+ per second = strong attack)
        spread_feature = 1.0 if time_span < 30 else 0.0       # short time window / burst behavior (activity concentrated in a short interval)
        persistence_feature = min((time_span / 60) / 10, 1.0) # attack duration over time (longer duration increases confidence)

        # Normalization: if there are 20 or more failed attempts, it's considered a strong attack, otherwise it's scaled down
        # It's important for logistic regression because inputs should be in similar ranges, otherwise weights won't work properly
        # Think of a student grading system where one subject is out of 1000 points and another is out of 10 points
        # The 1000 points subject would dominate the final grade if not normalized, even if it' the same level of importance as the 10 points subject
        # Here we use a simple approach to normalize by defining thresholds

        return np.array([
            [attempts_feature],
            [rate_feature],
            [spread_feature],
            [persistence_feature]
        ])
    
    def predict(self, ip_logs):

        X = self.extract_features(ip_logs)
        if X is None: 
            return {'is_attack': False, 'probability': 0.0}
    
        Z = np.dot(self.W.T, X) + self.b # np.dot = matrix multiplication
        # T = transpose, so W (column vector, 4x1) is transposed to row vector (1x4) to multiply with X (column vector, 4x1) + b (bias, scalar)
        # This is exactly what Andrew Ng explains mathematically in the Binary Classification class
        probability = float(1 / (1 + np.exp(-Z.item()))) # sigmoid function to convert to probability between 0 and 1
        # this still isn't the probability of being and attack tho, because it needs to be compared to a threshold

        is_attack = probability >= self.threshold # this is the probability (above or equal threshold)

        return {
            'is_attack': is_attack,
            'probability': probability,
            'features': X.flatten().tolist(), # flatten to 1D for readability
            'ip': ip_logs[0].get('ip', 'unknown'),
            'failed_attempts': len([l for l in ip_logs if not l.get('success', True)]),
            'timestamp': datetime.now().isoformat()
        }

    def analyze_all_logs(self, all_logs):
        results = []
        for log in all_logs:
            ip = log.get('ip', 'unknown')
            self.ip_history.setdefault(ip, []).append(log)

            result = self.predict(self.ip_history[ip])

            if result['is_attack']:
                last = self.last_detection.get(ip)
                now = datetime.now()

                if not last or (now - last).seconds > 300:
                    self.detections.append({
                        **result, # unpack all fields from result
                        'action_taken': 'alert',
                        'detected_at': datetime.now().isoformat()
                    })
                    self.last_detection[ip] = now

            results.append(result)

        return results


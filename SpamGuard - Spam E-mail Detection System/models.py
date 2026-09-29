from sklearn.linear_model import LogisticRegression
import joblib
import os

class SpamDetectionModels:
    """
    Lightweight spam detection model wrapper.
    Uses a single Logistic Regression classifier for stable predictions.
    """

    def __init__(self):
        """
        Initialize the classifier.
        """
        self.model = LogisticRegression(
            random_state=42,
            max_iter=2000,
            class_weight='balanced'
        )
        self.models_trained = False

    def train_models(self, X_train, y_train):
        """
        Train the classifier.

        Args:
            X_train: Training features (TF-IDF matrix)
            y_train: Training labels
        """
        print("Training Logistic Regression model...")
        self.model.fit(X_train, y_train)

        self.models_trained = True
        print("Model trained successfully!")

    def predict(self, X):
        """
        Make predictions using the classifier.

        Args:
            X: Input features (TF-IDF matrix)

        Returns:
            array: Predictions (0 for ham, 1 for spam)
        """
        if not self.models_trained:
            raise ValueError("Models must be trained before making predictions")
        return self.model.predict(X)

    def save_models(self, models_dir='models'):
        """
        Save trained models to disk.

        Args:
            models_dir (str): Directory to save models
        """
        if not self.models_trained:
            raise ValueError("Models must be trained before saving")

        os.makedirs(models_dir, exist_ok=True)

        joblib.dump(self.model, os.path.join(models_dir, 'spam_model.pkl'))

        print(f"Models saved to {models_dir}")

    def load_models(self, models_dir='models'):
        """
        Load trained models from disk.

        Args:
            models_dir (str): Directory containing saved models
        """
        try:
            self.model = joblib.load(os.path.join(models_dir, 'spam_model.pkl'))

            self.models_trained = True
            print(f"Models loaded from {models_dir}")

        except FileNotFoundError as e:
            raise FileNotFoundError(f"Model file not found: {e}")

    def get_individual_predictions(self, X):
        """
        Keep response structure consistent with the API.

        Args:
            X: Input features (TF-IDF matrix)

        Returns:
            dict: Predictions from active model(s)
        """
        if not self.models_trained:
            raise ValueError("Models must be trained before making predictions")

        return {
            'lr': self.model.predict(X)
        }
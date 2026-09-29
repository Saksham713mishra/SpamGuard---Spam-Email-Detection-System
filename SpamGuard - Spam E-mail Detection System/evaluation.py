from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
import pandas as pd

class ModelEvaluator:
    """
    Evaluation module for spam detection models.
    Calculates accuracy, precision, recall, F1 score, and confusion matrix.
    """

    def __init__(self):
        self.metrics = {}

    def evaluate_model(self, y_true, y_pred, model_name="Model"):
        """
        Evaluate a single model's performance.

        Args:
            y_true: True labels
            y_pred: Predicted labels
            model_name (str): Name of the model for reporting

        Returns:
            dict: Evaluation metrics
        """
        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, average='binary')
        recall = recall_score(y_true, y_pred, average='binary')
        f1 = f1_score(y_true, y_pred, average='binary')

        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)

        metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': cm,
            'classification_report': classification_report(y_true, y_pred, target_names=['Ham', 'Spam'])
        }

        self.metrics[model_name] = metrics
        return metrics

    def evaluate_all_models(self, X_test, y_test, models):
        """
        Evaluate all active models.

        Args:
            X_test: Test features
            y_test: Test labels
            models (SpamDetectionModels): Trained models instance

        Returns:
            dict: Metrics for all models
        """
        predictions = models.get_individual_predictions(X_test)

        all_metrics = {}
        for model_name, y_pred in predictions.items():
            all_metrics[model_name] = self.evaluate_model(y_test, y_pred, model_name)

        return all_metrics

    def print_metrics(self, metrics, model_name="Model"):
        """
        Print evaluation metrics in a formatted way.

        Args:
            metrics (dict): Evaluation metrics
            model_name (str): Name of the model
        """
        print(f"\n{'='*50}")
        print(f"Evaluation Metrics for {model_name}")
        print(f"{'='*50}")
        print(f"Accuracy:  {metrics['accuracy']:.4f}")
        print(f"Precision: {metrics['precision']:.4f}")
        print(f"Recall:    {metrics['recall']:.4f}")
        print(f"F1-Score:  {metrics['f1_score']:.4f}")
        print(f"\nConfusion Matrix:")
        print(metrics['confusion_matrix'])
        print(f"\nClassification Report:")
        print(metrics['classification_report'])

    def create_comparison_table(self, all_metrics):
        """
        Create a comparison table of all models.

        Args:
            all_metrics (dict): Metrics for all models

        Returns:
            pd.DataFrame: Comparison table
        """
        comparison_data = []
        for model_name, metrics in all_metrics.items():
            comparison_data.append({
                'Model': model_name.upper(),
                'Accuracy': f"{metrics['accuracy']:.4f}",
                'Precision': f"{metrics['precision']:.4f}",
                'Recall': f"{metrics['recall']:.4f}",
                'F1 Score': f"{metrics['f1_score']:.4f}"
            })

        df = pd.DataFrame(comparison_data)
        return df

    def get_model_characteristics(self):
        """
        Get characteristics of the active model.

        Returns:
            dict: Model characteristics
        """
        return {
            'lr': {
                'speed': 'Balanced',
                'description': 'Logistic Regression offers stable, interpretable decision boundaries.'
            }
        }

    def generate_performance_report(self, all_metrics, save_path=None):
        """
        Generate a comprehensive performance report.

        Args:
            all_metrics (dict): Metrics for all models
            save_path (str): Path to save the report (optional)

        Returns:
            str: Performance report
        """
        report = []
        report.append("MACHINE LEARNING EMAIL SPAM DETECTION - PERFORMANCE REPORT")
        report.append("="*70)
        report.append("")

        # Model comparison table
        comparison_df = self.create_comparison_table(all_metrics)
        report.append("MODEL COMPARISON TABLE:")
        report.append("-" * 70)
        report.append(comparison_df.to_string(index=False))
        report.append("")

        # Detailed metrics
        for model_name, metrics in all_metrics.items():
            report.append(f"DETAILED METRICS FOR {model_name.upper()}:")
            report.append("-" * 50)
            report.append(f"Accuracy:  {metrics['accuracy']:.4f}")
            report.append(f"Precision: {metrics['precision']:.4f}")
            report.append(f"Recall:    {metrics['recall']:.4f}")
            report.append(f"F1-Score:  {metrics['f1_score']:.4f}")
            report.append("")
            report.append("CONFUSION MATRIX:")
            report.append(str(metrics['confusion_matrix']))
            report.append("")
            report.append("CLASSIFICATION REPORT:")
            report.append(metrics['classification_report'])
            report.append("")

        # Model characteristics
        characteristics = self.get_model_characteristics()
        report.append("MODEL CHARACTERISTICS:")
        report.append("-" * 70)
        for model, chars in characteristics.items():
            report.append(f"{model}:")
            for key, value in chars.items():
                report.append(f"  {key}: {value}")
            report.append("")

        full_report = "\n".join(report)

        if save_path:
            with open(save_path, 'w') as f:
                f.write(full_report)
            print(f"Performance report saved to {save_path}")

        return full_report
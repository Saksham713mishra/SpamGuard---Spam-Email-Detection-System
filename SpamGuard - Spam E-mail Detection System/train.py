import json
import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from preprocess import TextPreprocessor, FeatureExtractor
from models import SpamDetectionModels
from evaluation import ModelEvaluator

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
DEFAULT_DATA_PATH = os.path.join(BASE_DIR, 'dataset', 'emails.csv')
DEFAULT_FEEDBACK_PATH = os.path.join(BASE_DIR, 'dataset', 'feedback_retraining.csv')

LABEL_MAP = {
    'ham': 0,
    'safe': 0,
    'legit': 0,
    'not_spam': 0,
    'non_spam': 0,
    'spam': 1,
    'junk': 1,
    'phishing': 1
}

TEXT_COLUMN_CANDIDATES = ['email_text', 'text', 'message', 'body', 'content']
LABEL_COLUMN_CANDIDATES = ['label', 'class', 'category', 'target']

def load_dataset(data_path=DEFAULT_DATA_PATH):
    """
    Load email dataset from CSV file.

    Args:
        data_path (str): Path to the CSV file

    Returns:
        pd.DataFrame: Loaded dataset
    """
    try:
        df = pd.read_csv(data_path)
        df.columns = [str(col).strip().lower() for col in df.columns]

        text_column = next((col for col in TEXT_COLUMN_CANDIDATES if col in df.columns), None)
        label_column = next((col for col in LABEL_COLUMN_CANDIDATES if col in df.columns), None)

        if not text_column or not label_column:
            raise ValueError(
                "Dataset must include text and label columns. "
                f"Found columns: {list(df.columns)}"
            )

        dataset = df[[text_column, label_column]].copy()
        dataset.columns = ['email_text', 'label']

        dataset['email_text'] = dataset['email_text'].fillna('').astype(str).str.strip()
        dataset['label'] = (
            dataset['label']
            .fillna('')
            .astype(str)
            .str.strip()
            .str.lower()
            .str.replace('-', '_', regex=False)
            .str.replace(' ', '_', regex=False)
        )

        dataset = dataset[dataset['email_text'] != '']
        dataset['label_num'] = dataset['label'].map(LABEL_MAP)
        dataset = dataset.dropna(subset=['label_num'])
        dataset['label'] = dataset['label_num'].map({1: 'spam', 0: 'ham'})
        dataset = dataset.drop(columns=['label_num'])

        dataset = dataset.drop_duplicates(subset=['email_text', 'label']).reset_index(drop=True)

        label_counts = dataset['label'].value_counts()
        if len(label_counts) < 2:
            raise ValueError("Dataset must contain both spam and ham labels.")

        if label_counts.min() < 20:
            raise ValueError(
                "Each class needs at least 20 examples for reliable training. "
                f"Current distribution: {label_counts.to_dict()}"
            )

        print(f"Dataset loaded successfully. Shape: {dataset.shape}")
        print(f"Columns used: ['email_text', 'label']")
        print(f"Label distribution:\n{label_counts}")
        return dataset
    except FileNotFoundError:
        raise FileNotFoundError(f"Dataset file not found at {data_path}")
    except Exception as e:
        raise Exception(f"Error loading dataset: {e}")


def load_feedback_dataset(feedback_path=DEFAULT_FEEDBACK_PATH):
    """
    Load optional feedback dataset exported from app feedback loop.

    Args:
        feedback_path (str): Path to feedback CSV file

    Returns:
        pd.DataFrame: Normalized feedback dataset with email_text and label
    """
    if not os.path.exists(feedback_path):
        print(f"No feedback dataset found at {feedback_path}. Skipping feedback merge.")
        return pd.DataFrame(columns=['email_text', 'label'])

    try:
        df = pd.read_csv(feedback_path)
        if df.empty:
            print("Feedback dataset is empty. Skipping feedback merge.")
            return pd.DataFrame(columns=['email_text', 'label'])

        df.columns = [str(col).strip().lower() for col in df.columns]

        text_column = next((col for col in TEXT_COLUMN_CANDIDATES if col in df.columns), None)
        if text_column is None and 'email_text' in df.columns:
            text_column = 'email_text'

        label_column = next((col for col in LABEL_COLUMN_CANDIDATES if col in df.columns), None)
        if label_column is None and 'feedback_label' in df.columns:
            label_column = 'feedback_label'

        if not text_column or not label_column:
            print("Feedback dataset missing required columns. Skipping feedback merge.")
            return pd.DataFrame(columns=['email_text', 'label'])

        feedback_df = df[[text_column, label_column]].copy()
        feedback_df.columns = ['email_text', 'label']

        feedback_df['email_text'] = feedback_df['email_text'].fillna('').astype(str).str.strip()
        feedback_df['label'] = (
            feedback_df['label']
            .fillna('')
            .astype(str)
            .str.strip()
            .str.lower()
            .str.replace('-', '_', regex=False)
            .str.replace(' ', '_', regex=False)
        )

        feedback_df['label'] = feedback_df['label'].map({
            'safe': 'ham',
            'ham': 'ham',
            'legit': 'ham',
            'not_spam': 'ham',
            'non_spam': 'ham',
            'scam': 'spam',
            'spam': 'spam',
            'phishing': 'spam',
            'junk': 'spam'
        })

        feedback_df = feedback_df.dropna(subset=['label'])
        feedback_df = feedback_df[feedback_df['email_text'] != '']
        feedback_df = feedback_df.drop_duplicates(subset=['email_text', 'label']).reset_index(drop=True)

        print(f"Feedback dataset loaded. Shape: {feedback_df.shape}")
        return feedback_df
    except Exception as e:
        print(f"Failed to load feedback dataset: {e}. Skipping feedback merge.")
        return pd.DataFrame(columns=['email_text', 'label'])


def merge_datasets(base_df, feedback_df):
    """
    Merge base training dataset with optional feedback samples.

    Args:
        base_df (pd.DataFrame): Primary training dataset
        feedback_df (pd.DataFrame): Feedback-based samples

    Returns:
        pd.DataFrame: Merged and deduplicated dataset
    """
    if feedback_df is None or feedback_df.empty:
        return base_df

    merged = pd.concat([base_df, feedback_df], ignore_index=True)
    merged = merged.drop_duplicates(subset=['email_text', 'label']).reset_index(drop=True)

    print(f"Merged dataset shape: {merged.shape} (base={len(base_df)}, feedback={len(feedback_df)})")
    print(f"Merged label distribution:\n{merged['label'].value_counts()}")
    return merged

def prepare_data(df):
    """
    Prepare data for training by preprocessing and feature extraction.

    Args:
        df (pd.DataFrame): Raw dataset

    Returns:
        tuple: X_train, X_test, y_train, y_test, vectorizer
    """
    # Initialize preprocessor and feature extractor
    preprocessor = TextPreprocessor()
    feature_extractor = FeatureExtractor(max_features=8000, ngram_range=(1, 2))

    # Extract texts and labels
    texts = df['email_text'].fillna('').tolist()
    labels = df['label'].map({'spam': 1, 'ham': 0}).astype(int).tolist()

    # Preprocess texts
    print("Preprocessing texts...")
    processed_texts = preprocessor.preprocess_batch(texts)

    # Extract features
    print("Extracting TF-IDF features...")
    X = feature_extractor.fit_transform(processed_texts)

    # Split data
    print("Splitting data into train/test sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, labels, test_size=0.2, random_state=42, stratify=labels
    )

    print(f"Training set size: {X_train.shape[0]}")
    print(f"Test set size: {X_test.shape[0]}")

    return X_train, X_test, y_train, y_test, feature_extractor


def serialize_metrics(all_metrics):
    """
    Serialize key metrics so the Flask app can load actual scores.

    Args:
        all_metrics (dict): Raw metrics from evaluator

    Returns:
        dict: JSON-friendly metrics dictionary
    """
    metrics_payload = {}
    for model_name, metrics in all_metrics.items():
        metrics_payload[model_name] = {
            'accuracy': float(metrics['accuracy']),
            'precision': float(metrics['precision']),
            'recall': float(metrics['recall']),
            'f1_score': float(metrics['f1_score'])
        }
    return metrics_payload


def train_and_evaluate(data_path=DEFAULT_DATA_PATH):
    """
    Main training function that orchestrates the entire ML pipeline.
    """
    print("Starting Email Spam Detection Training Pipeline")
    print("=" * 60)

    # Load dataset
    df = load_dataset(data_path=data_path)

    # Merge feedback samples if available
    feedback_df = load_feedback_dataset()
    training_df = merge_datasets(df, feedback_df)

    # Prepare data
    X_train, X_test, y_train, y_test, feature_extractor = prepare_data(training_df)

    # Initialize and train models
    models = SpamDetectionModels()
    print("\nTraining models...")
    models.train_models(X_train, y_train)

    # Evaluate models
    evaluator = ModelEvaluator()
    print("\nEvaluating models...")
    all_metrics = evaluator.evaluate_all_models(X_test, y_test, models)

    # Print results
    for model_name, metrics in all_metrics.items():
        evaluator.print_metrics(metrics, model_name)

    # Save models and vectorizer
    print("\nSaving models and vectorizer...")
    os.makedirs(MODELS_DIR, exist_ok=True)
    models.save_models(MODELS_DIR)
    joblib.dump(feature_extractor, os.path.join(MODELS_DIR, 'vectorizer.pkl'))

    metrics_payload = serialize_metrics(all_metrics)
    with open(os.path.join(MODELS_DIR, 'metrics.json'), 'w', encoding='utf-8') as metrics_file:
        json.dump(metrics_payload, metrics_file, indent=2)

    # Generate performance report
    print("\nGenerating performance report...")
    evaluator.generate_performance_report(all_metrics, os.path.join(MODELS_DIR, 'performance_report.txt'))

    print("\nTraining completed successfully!")
    print("Models saved in 'models/' directory")
    print("Metrics saved as 'models/metrics.json'")
    print("Performance report saved as 'models/performance_report.txt'")

    return models, feature_extractor, all_metrics

if __name__ == "__main__":
    # Create models directory if it doesn't exist
    os.makedirs(MODELS_DIR, exist_ok=True)

    # Run training
    train_and_evaluate()
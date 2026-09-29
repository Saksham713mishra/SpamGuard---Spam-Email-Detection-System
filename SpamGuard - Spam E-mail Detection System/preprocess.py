import re
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from sklearn.feature_extraction.text import TfidfVectorizer

# Download NLTK data if not already downloaded
nltk.download('punkt', quiet=True)
nltk.download('stopwords', quiet=True)

class TextPreprocessor:
    """
    Text preprocessing module for email spam detection.
    Implements NLP cleaning pipeline: lowercasing, tokenization,
    stopword removal, punctuation removal, HTML tag removal, noise cleaning.
    """

    def __init__(self):
        self.stop_words = set(stopwords.words('english'))

    def preprocess_text(self, text):
        """
        Apply complete preprocessing pipeline to input text.

        Args:
            text (str): Raw email text

        Returns:
            str: Preprocessed text
        """
        if not isinstance(text, str):
            return ""

        # Lowercasing
        text = text.lower()

        # HTML tag removal
        text = re.sub(r'<[^>]+>', '', text)

        # Punctuation removal
        text = re.sub(r'[^\w\s]', '', text)

        # Tokenization
        tokens = word_tokenize(text)

        # Stopword removal
        tokens = [token for token in tokens if token not in self.stop_words]

        # Join tokens back to string
        processed_text = ' '.join(tokens)

        # Additional noise cleaning (remove extra whitespaces)
        processed_text = re.sub(r'\s+', ' ', processed_text).strip()

        return processed_text

    def preprocess_batch(self, texts):
        """
        Preprocess a batch of texts.

        Args:
            texts (list): List of raw email texts

        Returns:
            list: List of preprocessed texts
        """
        return [self.preprocess_text(text) for text in texts]

class FeatureExtractor:
    """
    Feature engineering module using TF-IDF vectorization.
    """

    def __init__(self, max_features=5000, ngram_range=(1, 2)):
        """
        Initialize TF-IDF vectorizer.

        Args:
            max_features (int): Maximum number of features
            ngram_range (tuple): N-gram range for vectorization
        """
        self.vectorizer = TfidfVectorizer(
            max_features=max_features,
            ngram_range=ngram_range,
            stop_words='english'
        )
        self.is_fitted = False

    def fit_transform(self, texts):
        """
        Fit the vectorizer and transform texts to TF-IDF features.

        Args:
            texts (list): List of preprocessed texts

        Returns:
            sparse matrix: TF-IDF feature matrix
        """
        features = self.vectorizer.fit_transform(texts)
        self.is_fitted = True
        return features

    def transform(self, texts):
        """
        Transform texts to TF-IDF features using fitted vectorizer.

        Args:
            texts (list): List of preprocessed texts

        Returns:
            sparse matrix: TF-IDF feature matrix
        """
        if not self.is_fitted:
            raise ValueError("Vectorizer must be fitted before transform")
        return self.vectorizer.transform(texts)

    def get_feature_names(self):
        """
        Get feature names from the vectorizer.

        Returns:
            list: Feature names
        """
        if not self.is_fitted:
            raise ValueError("Vectorizer must be fitted before getting feature names")
        return self.vectorizer.get_feature_names_out()
# Email Spam Detection System - Professional Dashboard

## Advanced Machine Learning Email Spam Detection with Modern Web Dashboard

A comprehensive machine learning web application for email spam detection featuring a professional admin dashboard, advanced NLP preprocessing, TF-IDF feature engineering, and ensemble machine learning techniques.

## 🎯 Key Features

### Professional Dashboard Interface
- **Modern Sidebar Navigation**: Fixed left menu with gradient theme
- **Dashboard Overview**: Real-time statistics and analytics cards
- **Interactive Charts**: Chart.js visualizations for performance metrics
- **Responsive Design**: Bootstrap 5 with mobile-first approach
- **Professional UI**: Admin panel style with shadows and animations

### Multi-Page Application
- **Dashboard**: System overview with key metrics
- **Spam Detection**: Advanced email analysis tool
- **Model Performance**: Detailed ML model comparison
- **Dataset Statistics**: Data visualization and insights
- **About Project**: System information and architecture

### Browser Extension Beta + Feedback Loop
- **Chrome Extension Beta**: Quick page + selected text scanning from browser popup
- **Feedback Capture**: Mark scan result as safe/scam for retraining signals
- **Retraining Export**: Convert feedback to `dataset/feedback_retraining.csv`

### Advanced ML Pipeline
- **Hybrid Feature Engineering**: TF-IDF with n-gram analysis
- **Ensemble Classification**: Multiple algorithms with voting
- **Real-time Processing**: Instant spam detection
- **Model Comparison**: Performance metrics across all classifiers

## 🏗️ System Architecture

```
Dataset → Preprocessing → TF-IDF Features → ML Models → Ensemble → Dashboard Output
```

## 🚀 Technology Stack

### Backend
- **Python 3.x**: Core application logic
- **Flask**: Web framework with routing
- **scikit-learn**: Machine learning algorithms
- **NLTK**: Natural language processing
- **pandas/numpy**: Data manipulation

### Frontend
- **Bootstrap 5**: Responsive UI framework
- **Chart.js**: Interactive data visualizations
- **Font Awesome**: Professional icons
- **Custom CSS**: Modern dashboard styling
- **JavaScript**: Dynamic interactions

## 📊 Dashboard Features

### 1. Dashboard Page
- Total emails analyzed counter
- Spam/Ham detection statistics
- Model accuracy display
- Recent activity feed
- Quick action buttons

### 2. Spam Detection Page
- Email text input with validation
- Real-time analysis with loading animation
- Individual model predictions
- Result export functionality
- Confidence scoring

### 3. Model Performance Page
- Accuracy comparison charts
- Precision vs Recall analysis
- F1-Score metrics table
- Model characteristics overview

### 4. Dataset Statistics Page
- Spam vs Ham distribution pie chart
- Dataset overview bar chart
- Statistical summaries
- Sample data preview

## 🗂️ Project Structure

```
spam_detection_project/
├── app.py                      # Flask application with dashboard routes
├── templates/
│   ├── base.html              # Base template with sidebar
│   ├── dashboard.html         # Dashboard overview page
│   ├── detection.html         # Spam detection interface
│   ├── performance.html       # Model performance analysis
│   ├── statistics.html        # Dataset statistics
│   └── about.html             # Project information
├── static/
│   ├── css/style.css          # Professional dashboard styles
│   ├── js/dashboard.js        # Interactive JavaScript
│   └── images/                # Dashboard assets
├── models/                    # Trained ML models
├── browser_extension_beta/    # Chrome extension beta (manifest v3)
├── dataset/
│   └── emails.csv            # Training dataset
└── requirements.txt           # Python dependencies
```

## 🚀 Quick Start

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Train Models** (if needed)
   ```bash
   python train.py
   ```

3. **Run Application**
   ```bash
   python app.py
   ```

4. **Access Dashboard**
   - Open browser: `http://127.0.0.1:5000`
   - Navigate through sidebar menu

## 📈 ML Performance

- **Ensemble Model**: ~90% accuracy
- **Individual Models**: 85-89% accuracy range
- **Real-time Processing**: <1 second analysis time
- **Scalable Architecture**: Ready for production deployment

## 🎨 UI/UX Features

- **Professional Design**: Admin dashboard aesthetics
- **Responsive Layout**: Works on all devices
- **Interactive Charts**: Dynamic data visualizations
- **Smooth Animations**: Loading states and transitions
- **Accessibility**: WCAG compliant design
- **Dark/Light Themes**: Configurable color schemes

## 🔧 API Endpoints

- `GET /` - Dashboard homepage
- `GET /detection` - Spam detection page
- `GET /performance` - Model performance page
- `GET /statistics` - Dataset statistics page
- `GET /about` - About page
- `GET /register` - Create user account
- `GET /login` - User login page
- `GET /history` - Authenticated scan history page
- `GET /developer` - API key dashboard for developers
- `POST /logout` - Sign out current user
- `POST /developer/keys/create` - Generate API key
- `POST /developer/keys/<id>/revoke` - Revoke active API key
- `POST /developer/keys/<id>/regenerate` - Rotate API key
- `POST /developer/feedback/export` - Export feedback CSV for retraining
- `POST /scan` - Unified threat scan for email text + URL with risk score
- `POST /feedback` - Submit safe/scam feedback for model improvement
- `POST /predict` - Spam detection API
- `POST /predict/bulk` - Bulk JSON spam prediction
- `POST /predict/bulk-upload` - Bulk CSV/TXT spam prediction

## 📝 Usage Examples

### Web Interface
1. Create an account or sign in (optional but required for personal history)
2. Navigate to Spam Detection page
3. Enter message text and optional URL
4. Click "Run Threat Scan"
5. Review verdict, risk score, and recommendations

### API Usage
```python
import requests

api_key = "YOUR_API_KEY"
payload = {
   'email_text': 'Your email content here',
   'url': 'https://example.com/login'
}

response = requests.post(
   'http://localhost:5000/scan',
   json=payload,
   headers={'X-API-Key': api_key}
)

result = response.json()
print(f"Verdict: {result['verdict']}, Risk: {result['risk_score']}")
```

### Feedback Submission Example
```python
import requests

api_key = "YOUR_API_KEY"
payload = {
   'feedback_label': 'scam',
   'email_text': 'Urgent verify your account now',
   'url': 'http://secure-login.top/confirm',
   'original_scan': {
      'verdict': 'suspicious',
      'risk_level': 'medium',
      'risk_score': 64
   },
   'source': 'automation_script'
}

response = requests.post(
   'http://localhost:5000/feedback',
   json=payload,
   headers={'X-API-Key': api_key}
)

print(response.json())
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Developer

Built with ❤️ by Machine Learning Engineer specializing in NLP and Classification systems.
├── models.py                  # ML models and ensemble
├── evaluation.py              # Model evaluation metrics
├── train.py                   # Model training script
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone or download the project**
   ```bash
   cd spam_detection_project
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Train the models** (optional - pre-trained models included)
   ```bash
   python train.py
   ```

4. **Run the web application**
   ```bash
   python app.py
   ```

5. **Open your browser**
   ```
   http://localhost:5000
   ```

## 📈 Usage

### Web Interface

1. **Home Page**: Access the spam detection interface
2. **Sign In / Register**: Create an account to save scan history
3. **Spam Checker**: Paste email content + URL for combined threat analysis
4. **History**: Review your previous scans and outcomes
5. **Performance**: View detailed model metrics and comparisons
6. **About**: Learn about the project architecture and features

### API Endpoints

- `GET /` - Homepage
- `GET /login` - Login page
- `GET /register` - Registration page
- `GET /history` - User scan history (requires login)
- `GET /developer` - API key dashboard (requires login)
- `POST /logout` - Logout endpoint
- `POST /developer/keys/create` - Create API key (requires login)
- `POST /developer/keys/<id>/revoke` - Revoke API key (requires login)
- `POST /developer/keys/<id>/regenerate` - Regenerate API key (requires login)
- `POST /developer/feedback/export` - Export feedback dataset (requires login)
- `POST /scan` - Unified threat scan API (email + URL)
- `POST /feedback` - Feedback capture endpoint
- `POST /predict` - Email spam prediction API
- `GET /metrics` - Model performance metrics

## 🧩 Browser Extension Beta

1. Open `chrome://extensions`
2. Enable Developer mode
3. Load unpacked: `browser_extension_beta`
4. Configure API URL and key in extension settings
5. Run scans and submit feedback from popup

## 🔁 Feedback Retraining Loop

1. Collect feedback via web app or extension (`POST /feedback`)
2. Export feedback dataset from Developer API dashboard (`POST /developer/feedback/export`)
3. Run training (`python train.py`)
4. Training pipeline auto-merges `dataset/feedback_retraining.csv` with base dataset

### Sample API Usage

```python
import requests

# Predict spam
response = requests.post('http://localhost:5000/predict',
                        json={'email_text': 'Your email content here'})
result = response.json()
print(result['prediction'])  # 'spam' or 'ham'
```

## 🎯 Model Performance

| Model | Accuracy | Precision | Recall | F1 Score |
|-------|----------|-----------|--------|----------|
| Naive Bayes | 0.85 | 0.82 | 0.88 | 0.85 |
| Logistic Regression | 0.87 | 0.85 | 0.89 | 0.87 |
| SVM | 0.89 | 0.87 | 0.91 | 0.89 |
| **Ensemble (Voting)** | **0.90** | **0.88** | **0.92** | **0.90** |

## 🔧 Configuration

### TF-IDF Parameters
- `max_features`: 5000
- `ngram_range`: (1, 2)
- `stop_words`: 'english'

### Train/Test Split
- `test_size`: 0.2
- `random_state`: 42
- `stratify`: labels

### Model Hyperparameters
- **Naive Bayes**: Default MultinomialNB
- **Logistic Regression**: max_iter=1000
- **SVM**: LinearSVC with max_iter=10000

## 📊 Mathematical Foundation

**TF-IDF Formula:**
```
TF-IDF(t,d) = TF(t,d) × log(N/DF(t))
```

Where:
- TF(t,d) = Term Frequency in document d
- N = Total number of documents
- DF(t) = Document Frequency of term t

**Ensemble Prediction:**
```
y = argmax ∑ P(y|x_i) for i in models
```

## 🧪 Testing

### Sample Emails

**Spam Example:**
```
"Congratulations! You've won a free iPhone. Click here to claim your prize."
```

**Ham Example:**
```
"Hi, how are you doing today? Let's catch up soon."
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is for educational and research purposes.

## 📚 Research Background

This implementation follows the research methodology for email spam detection using:
- Hybrid feature engineering approaches
- Ensemble classification techniques
- Comprehensive evaluation metrics
- Production-ready web deployment

## 🆘 Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed
   ```bash
   pip install -r requirements.txt
   ```

2. **Model Loading**: Check if models directory exists and contains trained models

3. **Port Already in Use**: Change port in app.py
   ```python
   app.run(port=5001)
   ```

4. **Memory Issues**: Reduce max_features in TF-IDF vectorizer

## 🔄 Future Enhancements

- [ ] BERT-based text embeddings
- [ ] Deep learning models (LSTM, CNN)
- [ ] Real-time model updates
- [ ] User feedback integration
- [ ] Multi-language support
- [ ] Model A/B testing

## 📞 Contact

For questions or feedback about this research project, please refer to the academic documentation.

---

**Note**: This is a research-oriented implementation following machine learning best practices for email spam detection.
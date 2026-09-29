# SpamGuard Browser Extension Beta

This beta extension connects to the local SpamGuard backend and provides:

- Quick scan of selected text and current URL
- Optional API key authentication
- One-click feedback submission (`safe` / `scam`) to improve retraining data

## Load in Chrome

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select this folder: `browser_extension_beta`

## Configure

1. Open extension Settings page
2. Set API base URL (default: `http://127.0.0.1:5000`)
3. Add API key from Developer API dashboard if needed

## Usage

1. Open any webpage
2. Select suspicious text (optional)
3. Click extension icon
4. Review autofilled text + URL
5. Click **Run Scan**
6. Submit feedback using **Mark Safe** or **Mark Scam**

## Notes

- Backend app must be running locally.
- Feedback is sent to `/feedback` and can be exported via Developer API dashboard for retraining.

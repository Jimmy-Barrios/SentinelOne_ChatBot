# SentinelOne Chatbot

A Streamlit-based chatbot that integrates with the SentinelOne API to provide interactive security event querying and analysis.

## Features

- Natural language querying of SentinelOne events
- Quick example queries for common security scenarios
- Rate limiting and session management
- Interactive chat interface
- Secure API key management

## Setup

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/sentinelone-chatbot.git
cd sentinelone-chatbot
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file with your API keys:
```
OPENAI_API_KEY=your_openai_api_key_here
SENTINELONE_API_KEY=your_sentinelone_api_key_here
SENTINELONE_API_URL=https://usea1-018.sentinelone.net
```

4. Run the application:
```bash
streamlit run app.py
```

## Usage

1. Start the application using the command above
2. Access the chatbot through your web browser
3. Use the quick examples or type your own queries
4. View and analyze SentinelOne security events

## Rate Limits

- Maximum 10 messages per minute
- Session expires after 1 hour
- Maximum 50 messages per session

## Security

- API keys are stored securely in environment variables
- Rate limiting prevents abuse
- Input validation and sanitization
- Secure API communication

## License

MIT License 
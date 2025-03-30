import streamlit as st
import openai
from dotenv import load_dotenv
import os
import re
from datetime import datetime, timedelta
import hashlib
import secrets

# Set page config with dark theme (must be the first Streamlit command)
st.set_page_config(
    page_title="SentinelOne PowerQuery Assistant",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add security headers
st.markdown("""
    <style>
        /* Prevent clickjacking */
        iframe {
            display: none;
        }
        /* Prevent text selection */
        * {
            -webkit-user-select: none;
            -moz-user-select: none;
            -ms-user-select: none;
            user-select: none;
        }
    </style>
""", unsafe_allow_html=True)

# Load environment variables
load_dotenv()

# Security configurations
MAX_REQUESTS_PER_MINUTE = 10  # Rate limiting for OpenAI
MAX_INPUT_LENGTH = 1000  # Maximum length for user input
MAX_SESSION_DURATION = timedelta(hours=1)  # Maximum session duration
MAX_MESSAGES_PER_SESSION = 50  # Maximum number of messages per session
MIN_API_KEY_LENGTH = 32  # Minimum length for API keys
ALLOWED_QUERY_FIELDS = {
    'timestamp', 'endpoint.name', 'src.endpoint.ip.address',
    'event.login.loginIsSuccessful', 'event.login.userName', 'event.login.type',
    'event.login.failureReason', 'event.login.accountName', 'event.login.sessionId',
    'event.login.isAdministratorEquivalent', 'event.login.accountDomain',
    'event.login.accountSid', 'event.login.baseType', 'event.login.tgt.domainName',
    'event.login.tgt.user.name', 'event.login.tgt.userSid',
    'indicator.category', 'indicator.name', 'indicator.description',
    'indicator.identifier', 'indicator.metadata', 'indicator.confidence',
    'indicator.risk_level_id', 'tgt.file.name', 'tgt.file.path',
    'tgt.file.md5', 'tgt.file.sha1', 'tgt.file.sha256', 'tgt.file.size',
    'tgt.file.type', 'tgt.file.signature.isValid', 'tgt.file.owner.name',
    'tgt.file.owner.userSid', 'src.process.name', 'src.process.cmdline',
    'src.process.pid', 'src.process.ppid', 'src.process.userName',
    'src.process.signedStatus'
}

# Initialize session state for security
if "session_id" not in st.session_state:
    st.session_state.session_id = secrets.token_hex(16)
if "session_start_time" not in st.session_state:
    st.session_state.session_start_time = datetime.now()
if "request_count" not in st.session_state:
    st.session_state.request_count = 0
if "last_request_time" not in st.session_state:
    st.session_state.last_request_time = datetime.now()
if "message_count" not in st.session_state:
    st.session_state.message_count = 0

def check_session_validity():
    """Check if the current session is valid."""
    current_time = datetime.now()
    if (current_time - st.session_state.session_start_time) > MAX_SESSION_DURATION:
        st.error("Session expired. Please start a new chat.")
        st.session_state.messages = [st.session_state.messages[0]]  # Keep only system message
        st.session_state.message_count = 0
        st.session_state.session_start_time = current_time
        st.session_state.session_id = secrets.token_hex(16)
        return False
    return True

def check_message_limit():
    """Check if the message limit has been reached."""
    if st.session_state.message_count >= MAX_MESSAGES_PER_SESSION:
        st.error("Message limit reached. Please start a new chat.")
        st.session_state.messages = [st.session_state.messages[0]]  # Keep only system message
        st.session_state.message_count = 0
        st.session_state.session_start_time = datetime.now()
        st.session_state.session_id = secrets.token_hex(16)
        return False
    return True

def sanitize_input(text):
    """Sanitize user input to prevent XSS and injection attacks."""
    if not isinstance(text, str):
        return ""
    
    # Block requests for source code and markdown files
    blocked_terms = [
        'source code', 'app.py', 'sourcecode', 'source-code',
        'markdown', '.md', 'readme', 'readme.md', 'readme.txt',
        'show me the code', 'show the code', 'display the code',
        'give me the code', 'share the code', 'code inside',
        'code in app.py', 'code in the file', 'code from the file'
    ]
    
    text_lower = text.lower()
    if any(term in text_lower for term in blocked_terms):
        return "I apologize, but I cannot provide access to source code or internal files."
    
    # Remove any HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    # Remove any script tags and their content
    text = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', text, flags=re.IGNORECASE)
    # Remove any potentially dangerous characters
    text = re.sub(r'[<>]', '', text)
    # Remove any control characters
    text = ''.join(char for char in text if ord(char) >= 32)
    # Limit length
    text = text[:MAX_INPUT_LENGTH]
    return text

def validate_query_fields(query):
    """Validate that the query only contains allowed fields."""
    try:
        # Split the query into parts (before and after the pipe operator)
        parts = query.split('|')
        
        # Extract fields from the main query part
        main_query = parts[0].strip()
        
        # Extract fields from the columns clause if it exists
        columns_part = None
        if len(parts) > 1:
            columns_part = parts[1].strip()
        
        # Extract field names from the main query
        # Match field names that appear before operators
        fields = re.findall(r'([a-zA-Z0-9._]+)\s*(?:=|!=|>|<|>=|<=|contains|matches|in)', main_query)
        
        # Extract fields from columns clause if it exists
        if columns_part and 'columns' in columns_part.lower():
            # Remove 'columns' keyword and split by comma
            columns = columns_part.lower().replace('columns', '').strip()
            fields.extend([f.strip() for f in columns.split(',')])
        
        # Remove any empty strings and duplicates
        fields = set(f.strip() for f in fields if f.strip())
        
        # For quick examples, be more lenient
        if any(example in query.lower() for example in ['login', 'risk', 'file', 'process']):
            return True
            
        # Check if all fields are in the allowed set
        return all(field in ALLOWED_QUERY_FIELDS for field in fields)
    except Exception as e:
        return False  # Be strict on errors

def check_rate_limit():
    """Check if the user has exceeded the rate limit."""
    current_time = datetime.now()
    if (current_time - st.session_state.last_request_time) > timedelta(minutes=1):
        st.session_state.request_count = 0
        st.session_state.last_request_time = current_time
    
    if st.session_state.request_count >= MAX_REQUESTS_PER_MINUTE:
        return False
    
    st.session_state.request_count += 1
    return True

def process_chat_message(prompt):
    """Process a chat message with security checks."""
    # Check session validity
    if not check_session_validity():
        return "Session expired. Please start a new chat."
    
    # Check message limit
    if not check_message_limit():
        return "Message limit reached. Please start a new chat."
    
    # Sanitize input
    prompt = sanitize_input(prompt)
    
    # Check input length
    if len(prompt) > MAX_INPUT_LENGTH:
        return "Error: Input too long. Please keep your query under 1000 characters."
    
    # Check rate limit
    if not check_rate_limit():
        return "Error: Rate limit exceeded. Please wait a minute before trying again."
    
    try:
        # Get chatbot response
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": m["role"], "content": m["content"]}
                for m in st.session_state.messages
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        return "Error: Failed to process your request. Please try again later."

def validate_api_keys():
    """Validate API keys are present and meet minimum security requirements."""
    openai_key = os.getenv("OPENAI_API_KEY")
    
    if not openai_key or len(openai_key) < MIN_API_KEY_LENGTH:
        st.error("Invalid OpenAI API key configuration")
        return False
    
    return True

# Initialize OpenAI API
try:
    if not validate_api_keys():
        st.stop()
    api_key = os.getenv("OPENAI_API_KEY")
    openai.api_key = api_key
except Exception as e:
    st.error("Failed to initialize API. Please check your configuration.")
    st.stop()

# Initialize session state for chat history
if "messages" not in st.session_state:
    st.session_state.messages = [
        {
            "role": "system",
            "content": """You are a specialized assistant for creating PowerQueries in SentinelOne EDR Data Lake. 
            Your role is to help users create effective queries by:
            1. Understanding their requirements
            2. Suggesting appropriate fields and operators based on the SentinelOne data model
            3. Providing examples and explanations
            4. Validating query syntax
            5. Explaining the results they can expect
            
            IMPORTANT SYNTAX RULES:
            - All queries are case-sensitive
            - Use single quotes for string values (e.g., 'InfoStealer')
            - Use proper field names exactly as shown in the documentation
            - Use correct operators: contains, matches, in, =, !=, >, <, >=, <=
            - Combine terms with AND, OR, and NOT (or &&, ||, !)
            - Format queries in code blocks and explain each component
            
            QUERY DETAIL REQUIREMENTS:
            Always include these context fields in your queries:
            1. timestamp - For time-based context
            2. endpoint.name - For endpoint identification
            3. src.endpoint.ip.address - For source IP
            4. Relevant fields specific to the query type
            
            Example of a detailed query:
            ```sql
            event.login.userName = 'username'
            | columns timestamp, endpoint.name, src.endpoint.ip.address, event.login.type, event.login.loginIsSuccessful, event.login.failureReason
            ```
            
            Key field categories with exact syntax:
            1. Login Events:
               - event.login.loginIsSuccessful (Boolean)
               - event.login.userName (String)
               - event.login.type (Enum)
               - event.login.accountName (String)
               - event.login.failureReason (String)
               - event.login.sessionId (Numeric)
               - event.login.isAdministratorEquivalent (Boolean)
               - event.login.accountDomain (String)
               - event.login.accountSid (String)
               - event.login.baseType (String)
               - event.login.tgt.domainName (String)
               - event.login.tgt.user.name (String)
               - event.login.tgt.userSid (String)
               - src.endpoint.ip.address (String)
            
            2. Indicators:
               - indicator.category (Enum)
               - indicator.name (String)
               - indicator.description (String)
               - indicator.identifier (String)
               - indicator.metadata (String)
               - indicator.confidence (Numeric)
               - indicator.risk_level_id (Enum)
            
            3. File Events:
               - tgt.file.name (String)
               - tgt.file.path (String)
               - tgt.file.md5 (String)
               - tgt.file.sha1 (String)
               - tgt.file.sha256 (String)
               - tgt.file.size (Numeric)
               - tgt.file.type (Enum)
               - tgt.file.signature.isValid (Boolean)
               - tgt.file.owner.name (String)
               - tgt.file.owner.userSid (String)
            
            4. Process Events:
               - src.process.name (String)
               - src.process.cmdline (String)
               - src.process.pid (Numeric)
               - src.process.ppid (Numeric)
               - src.process.userName (String)
               - src.process.signedStatus (Enum)
            
            Always use the exact field names and syntax from the documentation."""
        }
    ]

# Initialize session state for quick example
if "quick_example" not in st.session_state:
    st.session_state.quick_example = None

# Create a sidebar for controls and reference
with st.sidebar:
    st.title("🔍 PowerQuery Assistant")
    st.markdown("---")
    
    # Chat Control Buttons
    col1, col2 = st.columns(2)
    
    with col1:
        # Clear Chat button (keeps system message)
        if st.button("🗑️ Clear Chat", use_container_width=True):
            st.session_state.messages = [st.session_state.messages[0]]  # Keep only the system message
            st.session_state.quick_example = None
            st.session_state.message_count = 0
            st.rerun()
    
    with col2:
        # New Chat button (completely fresh start)
        if st.button("🔄 New Chat", type="primary", use_container_width=True):
            st.session_state.messages = [st.session_state.messages[0]]
            st.session_state.quick_example = None
            st.session_state.message_count = 0
            st.session_state.session_start_time = datetime.now()
            st.session_state.session_id = secrets.token_hex(16)
            st.rerun()
    
    st.markdown("---")
    
    # Quick Examples
    st.markdown("### Quick Examples")
    examples = [
        "Show me failed login attempts",
        "Find high-risk events",
        "List suspicious file modifications",
        "Show network login attempts"
    ]
    
    for example in examples:
        if st.button(example, use_container_width=True):
            st.session_state.quick_example = example
            st.rerun()
    
    st.markdown("---")
    
    # Reference Section
    with st.expander("📚 Field Reference", expanded=False):
        st.markdown("""
        ### Context Fields
        - `timestamp`: Event timestamp
        - `endpoint.name`: Endpoint name
        - `src.endpoint.ip.address`: Source IP
        
        ### Login Events
        - `event.login.loginIsSuccessful`: Login success status
        - `event.login.userName`: Username
        - `event.login.type`: Login type
        - `event.login.failureReason`: Failure reason
        
        ### Indicators
        - `indicator.category`: Indicator category
        - `indicator.name`: Indicator name
        - `indicator.confidence`: Confidence score
        - `indicator.risk_level_id`: Risk level
        
        ### File Events
        - `tgt.file.name`: File name
        - `tgt.file.path`: File path
        - `tgt.file.signature.isValid`: Signature validity
        
        ### Process Events
        - `src.process.name`: Process name
        - `src.process.cmdline`: Command line
        - `src.process.signedStatus`: Signature status
        """)

# Add custom CSS for ChatGPT-like styling
st.markdown("""
    <style>
        /* Center the main content and limit width */
        .main > div {
            max-width: 800px !important;
            margin-left: auto !important;
            margin-right: auto !important;
            padding-left: 20px !important;
            padding-right: 20px !important;
        }
        
        /* Style the chat messages */
        .stChatMessage {
            background-color: transparent !important;
            padding: 1rem 0 !important;
        }
        
        /* Style user messages */
        .stChatMessage[data-testid="user-message"] {
            background-color: rgba(247, 247, 248, 0.1) !important;
        }
        
        /* Style assistant messages */
        .stChatMessage[data-testid="assistant-message"] {
            background-color: transparent !important;
        }
        
        /* Style the chat input box */
        .stChatInputContainer {
            position: fixed !important;
            bottom: 0 !important;
            left: 50% !important;
            transform: translateX(-50%) !important;
            max-width: 800px !important;
            width: 100% !important;
            padding: 1rem !important;
            background-color: #0E1117 !important;
            border-top: 1px solid rgba(255,255,255,0.1) !important;
        }
        
        /* Add padding at the bottom for the fixed chat input */
        .main {
            padding-bottom: 100px !important;
        }
        
        /* Make code blocks look more like ChatGPT */
        .stCodeBlock {
            background-color: rgba(68, 70, 84, 0.3) !important;
            border: 1px solid rgba(255,255,255,0.1) !important;
            border-radius: 6px !important;
        }
        
        /* Hide the Streamlit branding */
        #MainMenu, footer, header {
            visibility: hidden;
        }
        
        /* Adjust the title styling */
        h1 {
            font-size: 2rem !important;
            margin-bottom: 2rem !important;
            font-weight: 600 !important;
        }
    </style>
""", unsafe_allow_html=True)

# Main chat area with updated title styling
st.markdown("<h1 style='text-align: center; margin-bottom: 2rem;'>SentinelOne PowerQuery Assistant</h1>", unsafe_allow_html=True)

# Display chat messages
for message in st.session_state.messages:
    if message["role"] != "system":  # Don't display system message
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

# Handle quick example
if st.session_state.quick_example:
    prompt = st.session_state.quick_example
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.session_state.message_count += 1
    with st.chat_message("user"):
        st.markdown(prompt)

    # Get chatbot response
    with st.chat_message("assistant"):
        with st.spinner("Creating your PowerQuery..."):
            response_content = process_chat_message(prompt)
            st.markdown(response_content)
            
            # Add assistant response to chat history
            st.session_state.messages.append({"role": "assistant", "content": response_content})
            st.session_state.message_count += 1
    
    # Clear quick example
    st.session_state.quick_example = None
    st.rerun()

# Chat input at the bottom
if prompt := st.chat_input("Ask me to create a PowerQuery..."):
    # Add user message to chat history
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.session_state.message_count += 1
    with st.chat_message("user"):
        st.markdown(prompt)

    # Get chatbot response
    with st.chat_message("assistant"):
        with st.spinner("Creating your PowerQuery..."):
            response_content = process_chat_message(prompt)
            st.markdown(response_content)
            
            # Add assistant response to chat history
            st.session_state.messages.append({"role": "assistant", "content": response_content})
            st.session_state.message_count += 1 
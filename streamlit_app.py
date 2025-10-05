"""
Secure Streamlit App with Authentication and Role-Based Access Control

Features:
- User login with hashed passwords
- Account lockout after 3 failed attempts (5 minutes)
- Session timeout after 10 minutes of inactivity
- Role-based module access (Admin vs User)
- Audit logging to text file
- Last login tracking

File: streamlit_app.py
"""

import streamlit as st
import bcrypt
import time
from datetime import datetime, timedelta
import os

# ============================================================================
# CONFIGURATION
# ============================================================================

LOCKOUT_DURATION = 300  # 5 minutes in seconds
SESSION_TIMEOUT = 600   # 10 minutes in seconds
MAX_LOGIN_ATTEMPTS = 3
AUDIT_LOG_FILE = "auth_audit_log.txt"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def log_audit_event(event_type, username, details=""):
    """Log authentication events to audit file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {event_type} | User: {username} | {details}\n"
    
    try:
        with open(AUDIT_LOG_FILE, "a") as f:
            f.write(log_entry)
    except Exception as e:
        st.error(f"Failed to write audit log: {e}")

def verify_password(stored_hash, provided_password):
    """Verify a password against its hash"""
    try:
        return bcrypt.checkpw(
            provided_password.encode('utf-8'),
            stored_hash.encode('utf-8')
        )
    except Exception:
        return False

def get_user_data(username):
    """Retrieve user data from Streamlit secrets"""
    try:
        if username in st.secrets["users"]:
            user = st.secrets["users"][username]
            return {
                "password_hash": user["password_hash"],
                "role": user["role"],
                "modules": user.get("modules", [])
            }
    except Exception:
        pass
    return None

def is_account_locked(username):
    """Check if account is locked due to failed attempts"""
    if username not in st.session_state.failed_attempts:
        return False, 0
    
    attempts, lockout_time = st.session_state.failed_attempts[username]
    
    if attempts >= MAX_LOGIN_ATTEMPTS:
        time_since_lockout = time.time() - lockout_time
        if time_since_lockout < LOCKOUT_DURATION:
            remaining = LOCKOUT_DURATION - time_since_lockout
            return True, remaining
        else:
            # Lockout period expired, reset attempts
            del st.session_state.failed_attempts[username]
            log_audit_event("UNLOCK", username, "Account auto-unlocked after lockout period")
            return False, 0
    
    return False, 0

def record_failed_attempt(username):
    """Record a failed login attempt"""
    if username not in st.session_state.failed_attempts:
        st.session_state.failed_attempts[username] = [1, time.time()]
    else:
        attempts, _ = st.session_state.failed_attempts[username]
        attempts += 1
        st.session_state.failed_attempts[username] = [attempts, time.time()]
        
        if attempts >= MAX_LOGIN_ATTEMPTS:
            log_audit_event("LOCKOUT", username, f"Account locked after {MAX_LOGIN_ATTEMPTS} failed attempts")

def reset_failed_attempts(username):
    """Reset failed login attempts after successful login"""
    if username in st.session_state.failed_attempts:
        del st.session_state.failed_attempts[username]

def check_session_timeout():
    """Check if session has timed out due to inactivity"""
    if 'last_activity' in st.session_state:
        inactive_time = time.time() - st.session_state.last_activity
        if inactive_time > SESSION_TIMEOUT:
            username = st.session_state.get('username', 'Unknown')
            log_audit_event("TIMEOUT", username, f"Session timed out after {SESSION_TIMEOUT//60} minutes")
            logout()
            return True
    return False

def update_activity():
    """Update last activity timestamp"""
    st.session_state.last_activity = time.time()

def logout():
    """Clear session and logout user"""
    username = st.session_state.get('username', 'Unknown')
    log_audit_event("LOGOUT", username, "User logged out")
    
    # Clear session state
    for key in ['authenticated', 'username', 'role', 'modules', 'last_activity', 'last_login']:
        if key in st.session_state:
            del st.session_state[key]

# ============================================================================
# INITIALIZATION
# ============================================================================

def initialize_session_state():
    """Initialize session state variables"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'role' not in st.session_state:
        st.session_state.role = None
    if 'modules' not in st.session_state:
        st.session_state.modules = []
    if 'failed_attempts' not in st.session_state:
        st.session_state.failed_attempts = {}
    if 'last_activity' not in st.session_state:
        st.session_state.last_activity = time.time()
    if 'last_login' not in st.session_state:
        st.session_state.last_login = None

# ============================================================================
# LOGIN PAGE
# ============================================================================

def show_login_page():
    """Display login page"""
    st.title("🔐 Secure Login")
    st.markdown("---")
    
    # Login form
    with st.form("login_form"):
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        submit = st.form_submit_button("Login", use_container_width=True)
        
        if submit:
            if not username or not password:
                st.error("❌ Please enter both username and password")
                return
            
            # Check if account is locked
            locked, remaining = is_account_locked(username)
            if locked:
                minutes = int(remaining // 60)
                seconds = int(remaining % 60)
                st.error(f"🔒 Account locked! Try again in {minutes}m {seconds}s")
                log_audit_event("ATTEMPT_LOCKED", username, "Login attempt while account locked")
                return
            
            # Verify credentials
            user_data = get_user_data(username)
            
            if user_data and verify_password(user_data["password_hash"], password):
                # Successful login
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.role = user_data["role"]
                st.session_state.modules = user_data["modules"]
                st.session_state.last_activity = time.time()
                st.session_state.last_login = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                reset_failed_attempts(username)
                log_audit_event("LOGIN_SUCCESS", username, f"Role: {user_data['role']}")
                
                st.success("✅ Login successful!")
                st.rerun()
            else:
                # Failed login
                record_failed_attempt(username)
                
                # Check attempts remaining
                if username in st.session_state.failed_attempts:
                    attempts, _ = st.session_state.failed_attempts[username]
                    remaining_attempts = MAX_LOGIN_ATTEMPTS - attempts
                    
                    if remaining_attempts > 0:
                        st.error(f"❌ Invalid credentials! {remaining_attempts} attempt(s) remaining")
                        log_audit_event("LOGIN_FAILED", username, f"Attempts: {attempts}/{MAX_LOGIN_ATTEMPTS}")
                    else:
                        st.error(f"🔒 Account locked for {LOCKOUT_DURATION//60} minutes!")
                else:
                    st.error("❌ Invalid credentials!")
                    log_audit_event("LOGIN_FAILED", username, "Attempts: 1/3")
    
    # Instructions
    st.markdown("---")
    with st.expander("ℹ️ Security Information"):
        st.info(f"""
        **Security Features:**
        - 🔒 Account locks after {MAX_LOGIN_ATTEMPTS} failed attempts
        - ⏱️ Lockout duration: {LOCKOUT_DURATION//60} minutes
        - ⏰ Session timeout: {SESSION_TIMEOUT//60} minutes of inactivity
        - 🔐 Passwords are encrypted using bcrypt
        - 📝 All login attempts are logged
        """)

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def show_main_app():
    """Display main application after authentication"""
    
    # Check for session timeout
    if check_session_timeout():
        st.warning("⏰ Session timed out due to inactivity. Please login again.")
        st.rerun()
        return
    
    # Update activity timestamp
    update_activity()
    
    # Header with user info
    col1, col2, col3 = st.columns([3, 1, 1])
    
    with col1:
        st.title("🚀 Secure Streamlit App")
    
    with col2:
        st.write(f"**User:** {st.session_state.username}")
        st.write(f"**Role:** {st.session_state.role.upper()}")
    
    with col3:
        if st.button("🚪 Logout", use_container_width=True):
            logout()
            st.rerun()
    
    # Last login info
    if st.session_state.last_login:
        st.caption(f"Last login: {st.session_state.last_login}")
    
    st.markdown("---")
    
    # Module selection based on role
    available_modules = get_available_modules()
    
    if not available_modules:
        st.warning("⚠️ No modules assigned to your account. Contact administrator.")
        return
    
    # Sidebar for module selection
    with st.sidebar:
        st.header("📋 Navigation")
        selected_module = st.selectbox(
            "Select Module",
            available_modules,
            key="module_selector"
        )
        
        st.markdown("---")
        st.subheader("👤 Account Info")
        st.write(f"**Username:** {st.session_state.username}")
        st.write(f"**Role:** {st.session_state.role}")
        st.write(f"**Modules:** {len(available_modules)}")
    
    # Display selected module
    display_module(selected_module)

def get_available_modules():
    """Get list of modules available to current user"""
    if st.session_state.role == "admin":
        # Admin has access to all modules
        return ["Dashboard", "Data Upload", "Analytics", "Reports", "Settings", "User Management"]
    else:
        # Regular user - check their specific permissions
        user_modules = st.session_state.modules
        if "all" in user_modules:
            # If somehow a user has "all", give them standard modules (not Settings/User Management)
            return ["Dashboard", "Data Upload", "Analytics", "Reports"]
        else:
            return user_modules

def display_module(module_name):
    """Display the selected module content"""
    st.header(f"📄 {module_name}")
    
    # This is where you integrate your existing app modules
    # Replace the content below with your actual module code
    
    if module_name == "Dashboard":
        st.subheader("Welcome to the Dashboard")
        st.write("This is the main dashboard view.")
        st.info("🔧 Replace this with your actual dashboard content.")
        
        # Example: Show some metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Users", "42", "+5")
        col2.metric("Active Sessions", "12", "-2")
        col3.metric("Data Points", "1,234", "+89")
    
    elif module_name == "Data Upload":
        st.subheader("Data Upload Module")
        uploaded_file = st.file_uploader("Upload your data file", type=["csv", "xlsx", "json"])
        if uploaded_file:
            st.success(f"File '{uploaded_file.name}' uploaded successfully!")
            st.info("🔧 Add your file processing code here.")
    
    elif module_name == "Analytics":
        st.subheader("Analytics Module")
        st.write("Advanced analytics and visualizations go here.")
        st.info("🔧 Replace with your analytics code.")
        
        # Example chart
        import pandas as pd
        import numpy as np
        
        chart_data = pd.DataFrame(
            np.random.randn(20, 3),
            columns=['A', 'B', 'C']
        )
        st.line_chart(chart_data)
    
    elif module_name == "Reports":
        st.subheader("Reports Module")
        st.write("Generate and view reports here.")
        
        report_type = st.selectbox("Select Report Type", 
                                   ["Monthly Summary", "Quarterly Analysis", "Annual Report"])
        if st.button("Generate Report"):
            st.success(f"Generating {report_type}...")
            st.info("🔧 Add your report generation code here.")
    
    elif module_name == "Settings":
        st.subheader("⚙️ Settings (Admin Only)")
        st.write("Application configuration and settings.")
        
        st.checkbox("Enable notifications")
        st.checkbox("Dark mode")
        st.slider("Data retention (days)", 30, 365, 90)
        st.info("🔧 Add your settings management code here.")
    
    elif module_name == "User Management":
        st.subheader("👥 User Management (Admin Only)")
        st.write("Manage users and permissions.")
        
        st.info("📝 To add new users, use the password generator script and update secrets.toml")
        
        # Show audit log
        if st.checkbox("Show Recent Audit Logs"):
            show_audit_logs()
    
    else:
        # For your custom modules
        st.subheader(f"{module_name}")
        st.write(f"Content for {module_name} goes here.")
        st.info("🔧 Replace this section with your actual module code.")
        
        st.code(f"""
# Example integration:
# Import your module
import {module_name.lower().replace(' ', '_')}

# Run your module
{module_name.lower().replace(' ', '_')}.run()
        """)

def show_audit_logs(lines=20):
    """Display recent audit log entries"""
    try:
        if os.path.exists(AUDIT_LOG_FILE):
            with open(AUDIT_LOG_FILE, "r") as f:
                logs = f.readlines()
            
            recent_logs = logs[-lines:] if len(logs) > lines else logs
            
            st.code("".join(recent_logs), language="log")
        else:
            st.warning("No audit logs found yet.")
    except Exception as e:
        st.error(f"Error reading audit logs: {e}")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main application entry point"""
    
    # Page config
    st.set_page_config(
        page_title="Secure Streamlit App",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Initialize session state
    initialize_session_state()
    
    # Show appropriate page based on authentication status
    if st.session_state.authenticated:
        show_main_app()
    else:
        show_login_page()

if __name__ == "__main__":
    main()

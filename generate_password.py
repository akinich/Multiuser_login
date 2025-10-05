"""
Password Hash Generator for Streamlit App
Run this script locally to generate password hashes for new users

Usage:
    python generate_password.py

Then copy the output to your Streamlit secrets.toml file
"""

import bcrypt
import sys

def generate_password_hash(password):
    """Generate a bcrypt hash for a password"""
    # Convert password to bytes
    password_bytes = password.encode('utf-8')
    # Generate salt and hash
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    # Return as string
    return hashed.decode('utf-8')

def get_input(prompt):
    """Get input with compatibility for different Python versions"""
    try:
        return input(prompt)
    except EOFError:
        return ""

def main():
    print("=" * 60)
    print("Streamlit App - Password Hash Generator")
    print("=" * 60)
    print()
    
    # Get username
    username = get_input("Enter username: ").strip()
    if not username:
        print("❌ Username cannot be empty!")
        return
    
    # Get password
    print("\nNote: Password will be visible as you type")
    password = get_input("Enter password: ").strip()
    if not password:
        print("❌ Password cannot be empty!")
        return
    
    # Confirm password
    password_confirm = get_input("Confirm password: ").strip()
    if password != password_confirm:
        print("❌ Passwords do not match!")
        return
    
    # Get role
    print("\nAvailable roles:")
    print("  1. admin (full access)")
    print("  2. user (restricted access)")
    role_choice = get_input("Select role (1 or 2): ").strip()
    
    role = "admin" if role_choice == "1" else "user"
    
    # Get modules (if user role)
    if role == "user":
        print("\nEnter allowed modules (comma-separated)")
        print("Example: App1, App3, Dashboard")
        modules_input = get_input("Allowed modules: ").strip()
        if modules_input:
            modules = [m.strip() for m in modules_input.split(",") if m.strip()]
            modules_str = str(modules)
        else:
            modules_str = '["Dashboard"]'
    else:
        modules_str = '["all"]'
    
    # Generate hash
    print("\n⏳ Generating secure password hash...")
    password_hash = generate_password_hash(password)
    
    # Display output
    print("\n" + "=" * 60)
    print("✅ SUCCESS! Copy the following to your secrets.toml:")
    print("=" * 60)
    print(f"\n[users.{username}]")
    print(f'password_hash = "{password_hash}"')
    print(f'role = "{role}"')
    print(f'modules = {modules_str}')
    print("\n" + "=" * 60)
    print("\n📝 Instructions:")
    print("1. Copy the above configuration")
    print("2. Add it to .streamlit/secrets.toml")
    print("3. For Streamlit Cloud: Add to app secrets in dashboard")
    print("4. Restart your Streamlit app")
    print("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

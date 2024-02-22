import os
import ctypes
import json
import base64
from datetime import datetime
import csv

#find the path of profiles.ini on windows
profiles_ini_path = os.path.join(os.environ['APPDATA'], 'Mozilla', 'Firefox', 'profiles.ini')
#Extract your first profile form profile.ini
with open(profiles_ini_path, 'r') as f:
    profiles_ini = f.read()
    profiles_ini = profiles_ini.split('\n')
    profilePath = None
    for line in profiles_ini:
        if line.startswith('Path='):
            profilePath = line.split('=')[1]
            break
# the path of firefox on windows
firefoxPath = r'C:\Program Files\Mozilla Firefox'
#extract the full path of profile file
profile_dir = os.path.join(os.environ['APPDATA'], 'Mozilla', 'Firefox', profilePath)
#extract the path if logins.json
JsonConfigPath = os.path.join(profile_dir, 'logins.json')
#define the structure of the item to be used for dll functions
class SECItem(ctypes.Structure):
    _fields_ = [
    ('type', ctypes.c_int),
    ('data', ctypes.c_char_p),
    ('len', ctypes.c_uint),
    ]
#function to load encrypted login data stored on your profile 
def LoadJsonPwdData():
    entries = []
    with open(JsonConfigPath, "r") as o:
        js = json.load(o)
        for i in range(len(js['logins'])):
            entries.append({
            'username':js['logins'][i]['encryptedUsername'],
            'pwd':js['logins'][i]['encryptedPassword'],
            'timeCreated':js['logins'][i]['timeCreated'],
            'timeLastUsed':js['logins'][i]['timeLastUsed'],
            'timePasswordChanged':js['logins'][i]['timePasswordChanged'],
            'url':js['logins'][i]['hostname']})
        return entries

#function to decode encrypted data from b64
def Decode(cipher):
    
    data = base64.b64decode(cipher)
    secItem = SECItem()
    cipherItem = SECItem()
    cipherItem.type = 0
    cipherItem.data = data
    cipherItem.len = len(data)
    if NssDll.PK11SDR_Decrypt(ctypes.byref(cipherItem), ctypes.byref(secItem), 0) != 0:
        print('PK11SDR_Decrypt failed')
        raise

    result = ctypes.string_at(secItem.data, secItem.len).decode('utf8')
    return result
#function to decode time format to humain readable
def DocodeEntry(entry):
    try:
        entry['timeCreated'] = timestamp_to_strtime(entry['timeCreated'])
        entry['timeLastUsed'] = timestamp_to_strtime(entry['timeLastUsed'])
        entry['timePasswordChanged'] = timestamp_to_strtime(entry['timePasswordChanged'])


        entry['username'] = Decode(entry['username'])
        entry['pwd'] = Decode(entry['pwd'])
    except:
        print('Error when decode [ ' + entry['url'] + ' ]')
        entry['username'] = '<Error>'
        entry['pwd'] = '<Error>'
#function to print decrypted data    
def print_decrypted_data(data):
    for item in data:
        print(json.dumps(item))
#function to convert timestamp to time
def timestamp_to_strtime(timestamp):
    return datetime.fromtimestamp(timestamp / 1000.0).strftime('%Y-%m-%d %H:%M:%S')
#function to save the decrypted data into csv file
def save_to_csv(data):

    # Specify the CSV file path
    csv_file_path = 'decrypted_data.csv'

# Write data to CSV file
    with open(csv_file_path, 'w', newline='') as csvfile:
    # Define fieldnames based on keys in the first dictionary
       fieldnames = list(data[0].keys())
    
    # Create a CSV writer object
       writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    
    # Write header
       writer.writeheader()
    
    # Write data
       for item in data:
           writer.writerow(item)

    print("Data has been saved to", csv_file_path)
#function to decrypt and export data
def ExtractData():

    nss3_path = os.path.join(firefoxPath, 'nss3.dll')
    global NssDll
    try:
        NssDll = ctypes.CDLL(nss3_path)
    except OSError as e:
        print (e)
        return False

 
    if NssDll.NSS_Init(str.encode(profile_dir)) != 0:
        print("[!] NSS_Init failed")
        return False

    keySlot = NssDll.PK11_GetInternalKeySlot()
    if keySlot == 0:
        print("[!] PK11_GetInternalKeySlot failed")
        return False


    entries = LoadJsonPwdData()
    for i in range(len(entries)):
        DocodeEntry(entries[i])
        
    print("[+] Success to export the data: ")
    print_decrypted_data(entries)
    save_to_csv(entries)
    return True
    

if __name__ == '__main__':
    
    ExtractData()









    
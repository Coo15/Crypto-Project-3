import crypto_utils
import requests
import os
import base64
import json
from colorama import Fore, Back, Style

SERVER_URL = "http://127.0.0.1:5000"  # Replace with your server URL

def create_storage_on_server(storage_id):
    try:
        response = requests.post(f"{SERVER_URL}/create_storage", json={"storage_id": storage_id})
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error creating storage: {e}" + Style.RESET_ALL)
        return None

def create_new_storage():
    master_key, storage_id = crypto_utils.generate_storage_id()
    print(f"Master Key: {master_key}")
    print(f"Storage ID: {storage_id}")

    # Create storage on server
    result = create_storage_on_server(storage_id)
    if result and result["status"] == "created":
        print(Fore.GREEN + "Storage created successfully on server." + Style.RESET_ALL)
    elif result and result["status"] == "exists":
        print(Fore.YELLOW + "Storage already exists on server." + Style.RESET_ALL)
    return master_key, storage_id

def access_existing_storage():
    master_key = input("Enter your master key: ")
    storage_id = crypto_utils.hmac.new(
        base64.b64decode(master_key), b"my-app-storage", crypto_utils.hashlib.sha256
    ).hexdigest()
    print(f"Storage ID: {storage_id}")

    # Check if storage exists on server
    result = create_storage_on_server(storage_id)
    if result is None:
        return None, None  # Indicate error
    if result["status"] == "exists":
        print(Fore.GREEN + "Accessing Storage successfully." + Style.RESET_ALL)
        return master_key, storage_id
    else:
        print(Fore.RED + "Storage not found on server." + Style.RESET_ALL)
        return None, None

def upload_file(master_key, storage_id):
    file_path = input("Enter the path to the file to upload: ")
    if not os.path.exists(file_path):
        print(Fore.RED + "File not found!" + Style.RESET_ALL)
        return

    filename = os.path.basename(file_path)

    with open(file_path, "rb") as f:
        file_contents = f.read()

    (
        ciphertext,
        file_nonce,
        file_tag,
        encrypted_fek,
        fek_nonce,
        fek_tag,
    ) = crypto_utils.encrypt_file(file_path, master_key)

    metadata = {
        "encrypted_fek": base64.b64encode(encrypted_fek).decode("utf-8"),
        "fek_nonce": base64.b64encode(fek_nonce).decode("utf-8"),
        "fek_tag": base64.b64encode(fek_tag).decode("utf-8"),
        "file_nonce": base64.b64encode(file_nonce).decode("utf-8"),
        "file_tag": base64.b64encode(file_tag).decode("utf-8"),
    }

    files = {"encrypted_file": (filename, ciphertext, "application/octet-stream")}
    data = {"storage_id": storage_id, "metadata": json.dumps(metadata)}

    try:
        response = requests.post(f"{SERVER_URL}/upload", files=files, data=data)
        response.raise_for_status()
        print(response.text)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error uploading file: {e}" + Style.RESET_ALL)

def list_files(master_key, storage_id):
    data = {"storage_id": storage_id}
    try:
        response = requests.post(f"{SERVER_URL}/list", data=data)
        response.raise_for_status()
        files = response.json()
        print("Files in storage:")
        print("********************")
        for file in files:
            if file.endswith(".enc"):
                print("* " + file)
        print("********************")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error listing files: {e}" + Style.RESET_ALL)

def delete_file(master_key, storage_id):
    filename = input("Enter the name of the file to delete: ")
    data = {"storage_id": storage_id, "filename": filename}
    try:
        response = requests.post(f"{SERVER_URL}/delete", data=data)
        response.raise_for_status()
        print(response.text)
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error deleting file: {e}" + Style.RESET_ALL)

def download_file(master_key, storage_id):
    filename = input("Enter the name of the file to download: ")
    data = {"storage_id": storage_id, "filename": filename}
    try:
        response = requests.post(f"{SERVER_URL}/download", data=data)
        response.raise_for_status()
        response_data = response.json()
        encrypted_file = base64.b64decode(response_data["encrypted_file"])
        metadata = eval(response_data["metadata"])

        encrypted_fek = base64.b64decode(metadata["encrypted_fek"])
        fek_nonce = base64.b64decode(metadata["fek_nonce"])
        fek_tag = base64.b64decode(metadata["fek_tag"])
        file_nonce = base64.b64decode(metadata["file_nonce"])
        file_tag = base64.b64decode(metadata["file_tag"])

        decrypted_contents = crypto_utils.decrypt_file(
            encrypted_file,
            file_nonce,
            file_tag,
            encrypted_fek,
            fek_nonce,
            fek_tag,
            master_key,
        )

        download_path = os.path.join(".", "download")
        os.makedirs(download_path, exist_ok=True)
        filepath = os.path.join(download_path, filename)

        with open(filepath, "wb") as f:
            f.write(decrypted_contents)

        print(f"File downloaded and decrypted as {filepath}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error downloading file: {e}" + Style.RESET_ALL)

# CLI entry point for the user
if __name__ == "__main__":
    while True:
        print("\n------------------")
        print("Options:")
        print("[1] Create New Storage")
        print("[2] Access Existing Storage")
        print("[3] Exit")

        choice = input("Enter your choice: ")
        print("------------------\n")

        if choice == "1":
            master_key, storage_id = create_new_storage()
            if not master_key:
                continue # Back to main menu if create fails
        elif choice == "2":
            master_key, storage_id = access_existing_storage()
            if not master_key:
                continue  # Back to main menu if access fails
            if not master_key or not storage_id:
                continue
        elif choice == "3":
            break
        else:
            print("Invalid choice.")
            continue

        while True:
            print("\n------------------")
            print("Storage:")
            print("[a] Upload File")
            print("[b] List Files")
            print("[c] Download File")
            print("[d] Delete File")
            print("[x] Back to Main Menu")
            sub_choice = input("Enter your choice: ")
            print("------------------\n")
            if sub_choice == "a":
                upload_file(master_key, storage_id)
            elif sub_choice == "b":
                list_files(master_key, storage_id)
            elif sub_choice == "c":
                download_file(master_key, storage_id)
            elif sub_choice == "d":
                delete_file(master_key, storage_id)
            elif sub_choice == "x":
                break
            else:
                print("Invalid choice.")

from flask import Flask, request, jsonify
import os
import json
import base64

def ensure_storage_dir(storage_id):
    path = os.path.join(STORAGE_DIR, storage_id)
    if not os.path.exists(path):
        os.makedirs(path)

app = Flask(__name__)

@app.route("/create_storage", methods=["POST"])
def create_storage():
    data = request.get_json()
    storage_id = data["storage_id"]
    path = os.path.join(STORAGE_DIR, storage_id)
    if os.path.exists(path):
        return jsonify({"message": "Already exists", "status": "exists"}), 200
    else:
        os.makedirs(path)
        return jsonify({"message": "Storage created", "status": "created"}), 201

STORAGE_DIR = os.path.join(".", "storage")

@app.route("/upload", methods=["POST"])
def upload():
    storage_id = request.form["storage_id"]
    encrypted_file = request.files["encrypted_file"]
    metadata = request.form["metadata"]

    storage_path = os.path.join(STORAGE_DIR, storage_id)

    # Save the encrypted file
    filename = encrypted_file.filename
    encrypted_file.save(os.path.join(storage_path, filename + ".enc"))

    # Save metadata
    metadata_filename = filename + ".meta.json"
    metadata_path = os.path.join(storage_path, metadata_filename)
    with open(metadata_path, "w") as f:
        f.write(metadata)

    return "File uploaded successfully"

@app.route("/list", methods=["POST"])
def list_files():
    storage_id = request.form["storage_id"]
    storage_path = os.path.join(STORAGE_DIR, storage_id)

    if not os.path.exists(storage_path):
        return jsonify({"error": "Storage not found"}), 404

    files = os.listdir(storage_path)
    return jsonify(files), 200

@app.route("/delete", methods=["POST"])
def delete():
    storage_id = request.form["storage_id"]
    filename = request.form["filename"]
    storage_path = os.path.join(STORAGE_DIR, storage_id)
    file_path = os.path.join(storage_path, filename + ".enc")
    metadata_filename = filename + ".meta.json"
    metadata_path = os.path.join(storage_path, metadata_filename)

    if not os.path.exists(file_path):
        return "File not found", 404

    # Delete encrypted file
    os.remove(file_path)

    # Delete metadata
    os.remove(metadata_path)

    return "File deleted successfully", 200

@app.route("/download", methods=["POST"])
def download():
    storage_id = request.form["storage_id"]
    filename = request.form["filename"]
    storage_path = os.path.join(STORAGE_DIR, storage_id)
    file_path = os.path.join(storage_path, filename + ".enc")
    metadata_filename = filename + ".meta.json"
    metadata_path = os.path.join(storage_path, metadata_filename)

    if not os.path.exists(file_path):
        return "File not found", 404

    # Read encrypted file
    with open(file_path, "rb") as f:
        encrypted_file = f.read()

    # Read metadata
    with open(metadata_path, "r") as f:
        metadata = f.read()

    return jsonify({
        "encrypted_file": base64.b64encode(encrypted_file).decode("utf-8"),
        "metadata": metadata
    }), 200

if __name__ == "__main__":
    app.run(debug=True)

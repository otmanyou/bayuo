from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import data_pb2
import os

app = Flask(__name__)

# مفاتيح التشفير
key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    """واجهة API للتشفير"""
    try:
        data = request.get_json()
        if not data or 'text' not in data:
            return jsonify({'error': 'النص المطلوب تشفيره مطلوب'}), 400

        # إنشاء رسالة protobuf
        pb_data = data_pb2.Data()
        pb_data.field_2 = 17
        pb_data.field_8 = data['text']
        pb_data.field_9 = 1

        # التشفير
        serialized = pb_data.SerializeToString()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(serialized, AES.block_size))

        # تحويل إلى HEX
        encrypted_hex = ' '.join(f"{b:02X}" for b in encrypted)

        return jsonify({
            'status': 'success',
            'encrypted_data': encrypted_hex
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    """واجهة API لفك التشفير"""
    try:
        data = request.get_json()
        if not data or 'text' not in data:
            return jsonify({'error': 'النص المشفر مطلوب'}), 400

        # تحويل HEX إلى bytes
        encrypted_bytes = bytes.fromhex(data['text'].replace(' ', ''))

        # فك التشفير
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)

        # تحليل protobuf
        pb_data = data_pb2.Data()
        pb_data.ParseFromString(decrypted)

        return jsonify({
            'status': 'success',
            'decrypted_data': pb_data.field_8
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)

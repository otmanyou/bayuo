import os
import json
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import data_pb2
import logging

# تهيئة التطبيق
app = Flask(__name__)

# تكوين التسجيل
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# مفاتيح التشفير (يجب أن تكون متطابقة مع ما تستخدمه محلياً)
key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

@app.route('/')
def home():
    """الصفحة الرئيسية مع واجهة المستخدم"""
    return """
    <!DOCTYPE html>
    <html dir="rtl">
    <head>
        <meta charset="UTF-8">
        <title>نظام التشفير</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #2c3e50; text-align: center; }
            textarea { width: 100%; height: 120px; padding: 12px; border: 1px solid #ddd; border-radius: 5px; margin: 10px 0; }
            button { background-color: #3498db; color: white; border: none; padding: 12px 20px; border-radius: 5px; cursor: pointer; }
            .result { margin-top: 20px; padding: 15px; background: #f9f9f9; border-radius: 5px; border: 1px solid #eee; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>نظام التشفير المتقدم</h1>
            
            <div>
                <h2>تشفير النص</h2>
                <textarea id="textToEncrypt" placeholder="أدخل النص المراد تشفيره هنا..."></textarea>
                <button onclick="encryptText()">تشفير النص</button>
                <div class="result" id="encryptionResult"></div>
            </div>
            
            <div>
                <h2>فك التشفير</h2>
                <textarea id="textToDecrypt" placeholder="أدخل النص المشفر هنا (HEX)..."></textarea>
                <button onclick="decryptText()">فك التشفير</button>
                <div class="result" id="decryptionResult"></div>
            </div>
        </div>
        
        <script>
            async function encryptText() {
                const text = document.getElementById('textToEncrypt').value;
                if (!text) return alert('الرجاء إدخال نص للتشفير');
                
                try {
                    const response = await fetch('/api/encrypt', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ text: text })
                    });
                    const result = await response.json();
                    
                    if (result.status === 'success') {
                        document.getElementById('encryptionResult').innerHTML = 
                            `<strong>النص المشفر:</strong><br>${result.encrypted_data}`;
                    } else {
                        document.getElementById('encryptionResult').innerHTML = 
                            `<strong>خطأ:</strong> ${result.error}`;
                    }
                } catch (error) {
                    document.getElementById('encryptionResult').innerHTML = 
                        `<strong>خطأ في الاتصال:</strong> ${error.message}`;
                }
            }
            
            async function decryptText() {
                const text = document.getElementById('textToDecrypt').value;
                if (!text) return alert('الرجاء إدخال نص مشفر');
                
                try {
                    const response = await fetch('/api/decrypt', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ text: text })
                    });
                    const result = await response.json();
                    
                    if (result.status === 'success') {
                        document.getElementById('decryptionResult').innerHTML = 
                            `<strong>النص الأصلي:</strong><br>${result.decrypted_data}`;
                    } else {
                        document.getElementById('decryptionResult').innerHTML = 
                            `<strong>خطأ:</strong> ${result.error}`;
                    }
                } catch (error) {
                    document.getElementById('decryptionResult').innerHTML = 
                        `<strong>خطأ في الاتصال:</strong> ${error.message}`;
                }
            }
        </script>
    </body>
    </html>
    """

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    """واجهة API للتشفير"""
    try:
        # التحقق من صحة الطلب
        if not request.is_json:
            return jsonify({'status': 'error', 'error': 'يجب أن يكون الطلب بصيغة JSON'}), 400
            
        data = request.get_json()
        if 'text' not in data:
            return jsonify({'status': 'error', 'error': 'النص المطلوب تشفيره غير موجود'}), 400
        
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
        logger.error(f"Encryption error: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': f"خطأ في التشفير: {str(e)}"
        }), 500

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    """واجهة API لفك التشفير"""
    try:
        # التحقق من صحة الطلب
        if not request.is_json:
            return jsonify({'status': 'error', 'error': 'يجب أن يكون الطلب بصيغة JSON'}), 400
            
        data = request.get_json()
        if 'text' not in data:
            return jsonify({'status': 'error', 'error': 'النص المشفر مطلوب'}), 400
        
        # تحويل HEX إلى bytes
        try:
            encrypted_bytes = bytes.fromhex(data['text'].replace(' ', ''))
        except ValueError as e:
            return jsonify({'status': 'error', 'error': 'تنسيق HEX غير صالح'}), 400
        
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
        logger.error(f"Decryption error: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': f"خطأ في فك التشفير: {str(e)}"
        }), 500

@app.route('/health')
def health_check():
    """نقطة فحص الصحة للتأكد من عمل الخادم"""
    return jsonify({'status': 'healthy', 'message': 'الخادم يعمل بشكل صحيح'})

if __name__ == '__main__':
    app.run()

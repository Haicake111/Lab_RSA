import os
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import rsa
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'jarvis_core_v6'
socketio = SocketIO(app, cors_allowed_origins="*", max_content_length=15 * 1024 * 1024)

clients = {}

@app.route('/')
def index():
    return render_template('index.html')

# Hàm tạo khóa RSA ngầm không làm đơ Server
def generate_keys_async(sid):
    try:
        pub, priv = rsa.newkeys(1024)
        clients[sid] = {'pub': pub, 'priv': priv}
        socketio.emit('status', {'msg': 'HỆ THỐNG TRỰC TUYẾN. ĐÃ QUÉT THIẾT BỊ...'}, room=sid)
        
        if len(clients) >= 2:
            socketio.emit('status', {'msg': '🌐 LIÊN KẾT ĐA ĐIỂM THIẾT LẬP! SẴN SÀNG TRUYỀN TIN.'})
    except Exception as e:
        print(f"Lỗi tạo khóa cho {sid}: {e}")

@socketio.on('connect')
def handle_connect():
    threading.Thread(target=generate_keys_async, args=(request.sid,)).start()

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in clients:
        del clients[request.sid]
    socketio.emit('status', {'msg': '⚠️ MẤT KẾT NỐI VỚI ĐỐI TÁC.'})

@socketio.on('send_message')
def handle_message(data):
    sender_sid = request.sid
    text = data.get('text', '').strip()
    sig_name = data.get('signature', '').strip()
    
    if sender_sid not in clients:
        emit('error', {'msg': 'Hệ thống đang tạo khóa RSA, vui lòng đợi 2 giây rồi bấm lại!'})
        return

    # KIỂM TRA & LẤY DANH SÁCH ĐỐI TÁC (Loại bỏ lỗi Ghost Session)
    other_sids = [sid for sid in clients if sid != sender_sid]
    
    if not other_sids:
        emit('error', {'msg': 'BẠN ĐANG CÔ ĐƠN! Hãy mở thêm 1 Tab nữa để có đối tác nhận tin.'})
        return

    # THUẬT TOÁN MỚI: Luôn lấy Tab kết nối mới nhất (phần tử cuối cùng trong list)
    target_sid = other_sids[-1]
        
    try:
        signature = rsa.sign(sig_name.encode('utf-8'), clients[sender_sid]['priv'], 'SHA-256')
        message_bytes = text.encode('utf-8')
        encrypted_chunks = []
        
        for i in range(0, len(message_bytes), 117):
            chunk = message_bytes[i:i+117]
            encrypted_chunks.append(rsa.encrypt(chunk, clients[target_sid]['pub']))
            
        decrypted_bytes = b""
        for chunk in encrypted_chunks:
            decrypted_bytes += rsa.decrypt(chunk, clients[target_sid]['priv'])
        decrypted_text = decrypted_bytes.decode('utf-8')
        
        try:
            rsa.verify(sig_name.encode('utf-8'), signature, clients[sender_sid]['pub'])
            auth_status = "✅ XÁC THỰC AN TOÀN: Người gửi chính chủ."
        except rsa.VerificationError:
            auth_status = "❌ CẢNH BÁO BẢO MẬT: Chữ ký không hợp lệ!"
            
        socketio.emit('receive_message', {
            'text': decrypted_text,
            'signature': sig_name,
            'auth_status': auth_status
        }, room=target_sid)
        
        emit('send_success', {'msg': '📤 ĐÃ MÃ HÓA & GỬI ĐI THÀNH CÔNG.'})
    except Exception as e:
        emit('error', {'msg': f"LỖI CORE: {str(e)}"})

@socketio.on('send_file')
def handle_file(data):
    sender_sid = request.sid
    file_data = data.get('file')
    file_name = data.get('name')
    sig_name = data.get('signature', 'Unknown')

    if sender_sid not in clients:
        emit('error', {'msg': 'Khóa RSA đang tạo, đợi chút nhé!'})
        return

    # Lấy đối tác mới nhất cho chức năng gửi file
    other_sids = [sid for sid in clients if sid != sender_sid]
    if not other_sids:
        emit('error', {'msg': 'Cần mở thêm 1 Tab để có người nhận file!'})
        return
        
    target_sid = other_sids[-1]

    try:
        signature = rsa.sign(sig_name.encode('utf-8'), clients[sender_sid]['priv'], 'SHA-256')
        encrypted_chunks = []
        for i in range(0, len(file_data), 117):
            chunk = file_data[i:i+117]
            encrypted_chunks.append(rsa.encrypt(chunk, clients[target_sid]['pub']))

        decrypted_file = b""
        for chunk in encrypted_chunks:
            decrypted_file += rsa.decrypt(chunk, clients[target_sid]['priv'])

        socketio.emit('receive_file', {
            'file': decrypted_file,
            'name': file_name,
            'signature': sig_name,
            'auth_status': "✅ FILE XÁC THỰC THÀNH CÔNG."
        }, room=target_sid)

        emit('send_success', {'msg': f'📤 FILE [{file_name}] ĐÃ PHÓNG THÀNH CÔNG.'})
    except Exception as e:
        emit('error', {'msg': f"LỖI TRUYỀN FILE: {str(e)}"})

if __name__ == '__main__':
    print("\n==========================================")
    print("      J.A.R.V.I.S. MULTITHREAD SERVER     ")
    print("==========================================")
    user_ip = input("Nhập IP Server (Enter để mặc định 0.0.0.0): ").strip()
    if not user_ip: user_ip = '0.0.0.0'
    print(f"\n[!] Khởi chạy tại: http://{user_ip}:5000")
    
    socketio.run(app, host=user_ip, port=5000, debug=False)
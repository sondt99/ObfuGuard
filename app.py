from flask import Flask, render_template, request, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
import subprocess

app = Flask(__name__)
app.secret_key = 'binary-obfucation-sondt'

# Cấu hình thư mục upload và giới hạn kích thước file (ví dụ 16MB)
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'test_binaries')
ALLOWED_EXTENSIONS = {'bin', 'exe'}  # Các loại file cho phép upload

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

def allowed_file(filename):
    # Kiểm tra file có phần mở rộng hợp lệ không
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    result = None
    if request.method == 'POST':
        # Kiểm tra xem có file nào được gửi kèm không
        if 'file' not in request.files:
            flash('Không có file nào trong yêu cầu.')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('Không có file nào được chọn.')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            # Lấy tên file an toàn
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Chạy disassembler.exe với file vừa upload
            try:
                disassembler_path = os.path.join(os.getcwd(), 'core', 'disassembler.exe')
                subprocess.run([disassembler_path, file_path], check=True)
            except subprocess.CalledProcessError as e:
                flash('Đã có lỗi xảy ra trong quá trình giải mã.')
                return redirect(request.url)

            # Đọc kết quả từ file output/data.txt
            output_file = os.path.join(os.getcwd(), 'output', 'data.txt')
            if os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as f:
                    result = f.read()
            else:
                result = 'Không có kết quả nào được tạo ra từ disassembler.'
        else:
            flash('Chỉ cho phép các loại file: ' + ", ".join(ALLOWED_EXTENSIONS))
            return redirect(request.url)
    return render_template('upload.html', result=result)

if __name__ == '__main__':
    # Tạo thư mục upload nếu chưa tồn tại
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)

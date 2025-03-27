import os
import platform
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
import subprocess

app = Flask(__name__)
app.secret_key = 'binary-obfucation-sondt'

# Kiểm tra nếu đang chạy trên Vercel
if os.getenv('VERCEL') or os.getenv('NOW_REGION'):
    UPLOAD_FOLDER = '/tmp'
else:
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'test')

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

ALLOWED_EXTENSIONS = {'bin', 'exe'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    result = None
    if request.method == 'POST':
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

            # Đảm bảo thư mục tồn tại
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

            # Lưu file
            file.save(file_path)

            # Đường dẫn đến disassembler
            disassembler_path = os.path.abspath('./core/disassembler.exe')
            relative_path_to_file = os.path.abspath(file_path)

            # Chạy disassembler
            try:
                subprocess.run(
                    [disassembler_path, relative_path_to_file],
                    cwd=os.path.abspath('./core'),
                    check=True
                )
                flash(f'Đã chạy thành công disassembler trên {filename}')
            except subprocess.CalledProcessError as e:
                flash(f'Đã có lỗi xảy ra khi chạy disassembler: {e}')
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
    app.run(debug=True)

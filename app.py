from flask import Flask, render_template, request, redirect, flash
import os
from werkzeug.utils import secure_filename
import subprocess

app = Flask(__name__)
app.secret_key = 'binary-obfucation-sondt'

# Các định nghĩa cho file được upload
ALLOWED_EXTENSIONS = {'bin', 'exe'}

# Sử dụng thư mục /tmp cho Vercel vì đây là nơi có quyền ghi tạm thời
UPLOAD_FOLDER = os.path.join('/tmp', 'test')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Giới hạn dung lượng file

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    result = None
    if request.method == 'POST':
        # Kiểm tra xem file có trong request không
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
            
            # Tạo thư mục upload nếu chưa tồn tại
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            # Lưu file vào /tmp
            file.save(file_path)
            
            # Chạy disassembler - lưu ý: đảm bảo file disassembler chạy được trên Linux (không sử dụng .exe nếu không phù hợp)
            try:
                # Ví dụ: nếu bạn có file disassembler Linux ở thư mục core
                disassembler_path = os.path.join(os.getcwd(), 'core', 'disassembler')
                subprocess.run([disassembler_path, file_path], check=True)
            except subprocess.CalledProcessError as e:
                flash('Đã có lỗi xảy ra trong quá trình giải mã.')
                return redirect(request.url)
            
            # Đọc kết quả từ file output (ví dụ: file data.txt được tạo trong /tmp)
            output_file = os.path.join('/tmp', 'data.txt')
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
    # Tạo thư mục upload ngay khi khởi động ứng dụng
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)

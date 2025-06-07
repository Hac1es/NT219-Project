HƯỚNG DẪN SỬ DỤNG HỆ THỐNG TÍNH ĐIỂM TÍN DỤNG SỬ DỤNG MÃ HÓA ĐỒNG CẤU
====================================================================

1. TỔNG QUAN
-----------
Hệ thống này triển khai mô hình tính điểm tín dụng sử dụng mã hóa đồng cấu (homomorphic encryption) 
theo mô hình P2P - Server, trong đó:
- Các ngân hàng (clients) tham gia vào quá trình tạo khóa và mã hóa dữ liệu
- Server thực hiện tính toán điểm tín dụng trên dữ liệu đã mã hóa
- Kết quả được giải mã thông qua cơ chế giải mã ngưỡng (threshold decryption)

2. CẤU TRÚC VÀ HƯỚNG DẪN CHI TIẾT
---------------------------------
2.1. keyGenerator.py
    - Mục đích: Tạo cặp khóa ban đầu cho ngân hàng
    - Cách sử dụng:
      1. Chạy file: python keyGenerator.py
      2. Nhập tên ngân hàng (ví dụ: MSB, ACB, TCB)
      3. Hệ thống sẽ tự động:
         - Tạo thư mục keys_[TÊN_NGÂN_HÀNG]
         - Tạo cặp khóa công khai/riêng tư
         - Tạo khóa đánh giá phép nhân
         - Lưu tất cả vào thư mục tương ứng
    - Output: Thư mục keys_[TÊN_NGÂN_HÀNG] chứa:
      + publicKey.txt: Khóa công khai
      + privateKey.txt: Khóa riêng tư
      + eval-mult-key.txt: Khóa đánh giá phép nhân

2.2. calculateJointKey.py
    - Mục đích: Tạo khóa công khai chung từ các khóa của các ngân hàng
    - Cách sử dụng:
      1. Chạy file: python calculateJointKey.py
      2. Nếu là ngân hàng đầu tiên:
         - Chọn file privateKey.txt của mình
         - Hệ thống sẽ tạo khóa công khai chung mới
      3. Nếu là ngân hàng tiếp theo:
         - Chọn file khóa công khai chung hiện tại
         - Chọn file privateKey.txt của mình
         - Hệ thống sẽ tạo khóa công khai chung mới
    - Output: File joint_public_key.txt

2.3. evalMultKey1.py
    - Mục đích: Tạo phần đóng góp cho khóa đánh giá phép nhân
    - Cách sử dụng:
      1. Chạy file: python evalMultKey1.py
      2. Chọn file privateKey.txt của ngân hàng
      3. Nếu có khóa đánh giá phép nhân trước đó:
         - Chọn file eval-mult-key.txt
      4. Hệ thống sẽ tạo phần đóng góp mới
    - Output: File eval_mult_key_contribution.txt

2.4. evalMultKey2.py
    - Mục đích: Tổng hợp các phần đóng góp thành khóa đánh giá phép nhân cuối cùng
    - Cách sử dụng:
      1. Chạy file: python evalMultKey2.py
      2. Nếu là ngân hàng đầu tiên:
         - Chọn file eval_mult_key_contribution.txt của mình
         - Chọn file joint_public_key.txt
      3. Nếu là ngân hàng tiếp theo:
         - Chọn file eval-mult-key.txt hiện tại
         - Chọn file eval_mult_key_contribution.txt của mình
         - Chọn file joint_public_key.txt
      4. Nếu là ngân hàng cuối cùng (aggregator):
         - Chọn tất cả các file eval_mult_key_contribution.txt
         - Chọn file joint_public_key.txt
    - Output: File eval-mult-key.txt mới

2.5. SerializeData.py
    - Mục đích: Nhập và mã hóa dữ liệu khách hàng
    - Cách sử dụng:
      1. Chạy file: python SerializeData.py
      2. Nhập các thông số (0.0 - 1.0):
         - Lịch sử thanh toán (S_payment)
         - Dư nợ/Hạn mức (S_util)
         - Tuổi tín dụng (S_length)
         - Loại tín dụng (S_creditmix)
         - Yêu cầu tín dụng (S_inquiries)
         - Ổn định thu nhập (S_incomestability)
         - Hành vi tài chính (S_behavioral)
      3. Chọn ngân hàng từ dropdown
      4. Nhập tên khách hàng
      5. Load khóa:
         - Nhấn "Chọn file khóa công khai" để chọn joint_public_key.txt
         - Nhấn "Chọn file khóa nhân đánh giá" để chọn eval-mult-key.txt
      6. Nếu là ngân hàng cuối cùng:
         - Tick vào "Là bên mã hóa cuối cùng"
         - Chọn các file ciphertext cần gộp
      7. Nhấn "Mã hóa" để tạo file dữ liệu
    - Output: 
      + ciphertext_[TÊN_NGÂN_HÀNG].bin: File dữ liệu đã mã hóa
      + ciphertext_[TÊN_NGÂN_HÀNG].bin.sig: Chữ ký số của file

2.6. decryptEncryptedText.py
    - Mục đích: Giải mã kết quả tính điểm
    - Cách sử dụng:
      1. Chạy file: python decryptEncryptedText.py
      2. Chọn file kết quả đã mã hóa (ciphertext_[TÊN_NGÂN_HÀNG].bin)
      3. Chọn file privateKey.txt của ngân hàng
      4. Nhập mã ngân hàng
      5. Nếu là bên tổng hợp kết quả:
         - Tick vào "Là bên tổng hợp kết quả"
         - Chọn các file giải mã một phần
      6. Nhấn "Giải mã" để xem kết quả
    - Output: Điểm tín dụng của khách hàng (300-850)

3. QUY TRÌNH LÀM VIỆC
--------------------
3.1. Khởi tạo hệ thống
    a) Mỗi ngân hàng chạy keyGenerator.py để tạo cặp khóa riêng
    b) Lưu khóa vào thư mục keys_[TÊN_NGÂN_HÀNG]

3.2. Tạo khóa công khai chung
    a) Ngân hàng đầu tiên chạy calculateJointKey.py
    b) Các ngân hàng tiếp theo lần lượt tham gia
    c) Lưu khóa công khai chung cuối cùng

3.3. Tạo khóa đánh giá phép nhân
    a) Mỗi ngân hàng chạy evalMultKey1.py để tạo phần đóng góp
    b) Các ngân hàng lần lượt chạy evalMultKey2.py để tổng hợp
    c) Ngân hàng cuối cùng tổng hợp thành khóa đánh giá phép nhân cuối cùng

3.4. Mã hóa dữ liệu
    a) Mỗi ngân hàng chạy SerializeData.py để mã hóa dữ liệu khách hàng
    b) Ngân hàng cuối cùng gộp các file dữ liệu đã mã hóa

3.5. Giải mã kết quả
    a) Mỗi ngân hàng chạy decryptEncryptedText.py để tạo phần giải mã
    b) Ngân hàng cuối cùng tổng hợp các phần giải mã để có kết quả cuối cùng

4. LƯU Ý QUAN TRỌNG
------------------
- Đảm bảo tất cả các file khóa được lưu an toàn
- Không chia sẻ khóa riêng với bất kỳ ai
- Kiểm tra chữ ký số trước khi sử dụng các file
- Đảm bảo các giá trị nhập vào nằm trong khoảng 0.0 - 1.0
- Backup dữ liệu thường xuyên
- Tuân thủ đúng thứ tự các bước trong quy trình
- Kiểm tra tính toàn vẹn của các file trước khi sử dụng

5. XỬ LÝ LỖI THƯỜNG GẶP
-----------------------
5.1. Lỗi "Cannot load public key"
    - Kiểm tra file khóa có tồn tại
    - Kiểm tra định dạng file khóa
    - Thử tạo lại cặp khóa

5.2. Lỗi "Cannot load eval mult key"
    - Kiểm tra quá trình tạo khóa đánh giá phép nhân
    - Đảm bảo đã chạy đủ các bước evalMultKey1.py và evalMultKey2.py
    - Kiểm tra thứ tự các bước tổng hợp khóa

5.3. Lỗi "Invalid input value"
    - Kiểm tra các giá trị nhập vào có nằm trong khoảng 0.0 - 1.0
    - Đảm bảo định dạng số thập phân đúng
    - Kiểm tra không có ký tự đặc biệt

5.4. Lỗi "Signature verification failed"
    - Kiểm tra file chữ ký có tồn tại
    - Kiểm tra file dữ liệu có bị thay đổi
    - Thử tạo lại chữ ký

6. BẢO MẬT
---------
- Sử dụng chữ ký số để xác thực tính toàn vẹn của dữ liệu
- Không lưu trữ khóa riêng trên máy tính dùng chung
- Sử dụng mật khẩu mạnh cho các file khóa
- Thường xuyên cập nhật các module bảo mật
- Kiểm tra chữ ký số trước khi sử dụng file
- Backup dữ liệu thường xuyên
- Sử dụng kết nối an toàn khi truyền file

7. LIÊN HỆ HỖ TRỢ
----------------
Nếu gặp vấn đề trong quá trình sử dụng, vui lòng liên hệ:
- Email: [EMAIL_HỖ_TRỢ]
- Hotline: [SỐ_ĐIỆN_THOẠI]
- Website: [WEBSITE_HỖ_TRỢ] 
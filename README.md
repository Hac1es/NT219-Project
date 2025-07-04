# HỆ THỐNG ĐÁNH GIÁ ĐIỂM TÍN DỤNG LIÊN NGÂN HÀNG & TỔ CHỨC TÀI CHÍNH ỨNG DỤNG HOMOMORPHIC ENCRYPTION
Đồ án môn Mật mã học (NT219), Trường Đại học Công nghệ Thông tin

## MÔ TẢ DỰ ÁN

Hệ thống tính toán điểm tín dụng bảo mật sử dụng Multiparty CKKS cho phép nhiều bên cùng nhau hợp tác
để tính toán trên dữ liệu đã mã hóa mà không cần giải mã, đảm bảo tính riêng tư và bảo mật dữ liệu tuyệt đối.

## KIẾN TRÚC HỆ THỐNG (Ấn vào hình để xem video demo)

[![Xem demo](diagram.png)](https://www.youtube.com/watch?v=zf33MT_4sFw)
[Kịch bản demo](Kịch%20bản.txt)

---

## CÀI ĐẶT

### 1. Yêu cầu hệ thống:

- Python 3.12
- 4 máy ảo/thật với network isolation
- Ubuntu 24.04 (không được là Windows, vì openfhe-python không chạy được trên đó)

### 2. Xem các hướng dẫn kèm theo repo

- [Kiến trúc hệ thống](diagram.png)
- [Sơ đồ tài sản](Assets%20Diagram.png)
- [Luồng mã hóa](Encrypt%20Flow.png)
- [Luồng giải mã](Decrypt%20Flow.png)
- [Setup Client](Setup%20Client.txt)
- [Cài PostgreSQL hỗ trợ TDE](Setup%20Postgres%20TDE%20trên%20Ubuntu.txt)

---

## QUY TRÌNH HOẠT ĐỘNG

### 1. Tạo chứng chỉ:

- Banks và FinanceOrg gửi yêu cầu đến CA
- CA ký và trả lại certificate

### 2. Tạo khóa FHE:

- Các ngân hàng phối hợp tạo khóa CKKS (public chung, private riêng)
- Sinh các evaluation key phục vụ tính toán

### 3. Lưu trữ dữ liệu:

- Lưu tại PostgreSQL đã bật TDE
- Đảm bảo dữ liệu được mã hóa trên ổ đĩa

### 4. Mã hóa dữ liệu và xác thực:

- Trích xuất dữ liệu từ DB, mã hóa bằng Multiparty CKKS
- Gửi ciphertext + chữ ký số

### 5. Tính toán điểm tín dụng:

- Tổ chức tín dụng nhận dữ liệu mã hóa
- Tính toán điểm số trực tiếp bằng FHE
- Gửi lại kết quả (mã hóa) + chữ ký số

### 6. Giải mã kết quả:

- Kiểm tra chữ ký, xác minh tính toàn vẹn
- Các ngân hàng phối hợp giải mã kết quả

---

## BẢO MẬT HỆ THỐNG

### 1. Mã hóa:

- Multiparty CKKS (FHE) cho tính toán bảo mật
- ECDSA cho chữ ký số
- HTTPS/TLSv1.3 cho truyền tải
- PostgreSQL TDE cho dữ liệu at-rest

### 2. Xác thực & quyền truy cập:

- Xác thực dựa trên chứng chỉ (Certificate-based Auth)
- Whitelist IP
- Kiểm tra chữ ký số, phân quyền truy cập DB

### 3. Bảo vệ dữ liệu:

- Dữ liệu luôn ở dạng mã hóa khi xử lý & lưu trữ
- Không giải mã tại server trung gian
- Multi-party decryption đảm bảo không ai đơn lẻ giải mã được

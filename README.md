## HỆ THỐNG ĐÁNH GIÁ ĐIỂM TÍN DỤNG LIÊN NGÂN HÀNG & TỔ CHỨC TÀI CHÍNH
Đồ án môn Mật mã học (NT219), Trường Đại học Công nghệ Thông tin

### MÔ TẢ DỰ ÁN

Hệ thống tính toán điểm tín dụng bảo mật sử dụng Multiparty CKKS cho phép nhiều bên cùng nhau hợp tác
để tính toán trên dữ liệu đã mã hóa mà không cần giải mã, đảm bảo tính riêng tư và bảo mật dữ liệu tuyệt đối.

### KIẾN TRÚC HỆ THỐNG (Ấn vào hình để xem video demo)

[![Xem demo](diagram.png)](https://www.youtube.com/watch?v=zf33MT_4sFw)
[Kịch bản demo](Kịch%20bản.txt)

---

### CÀI ĐẶT

#### 1. Yêu cầu hệ thống:

- Python 3.12
- 4 máy ảo/thật với network isolation
- Ubuntu 24.04 (không được là Windows, vì openfhe-python không chạy được trên đó)

#### 2. Xem các hướng dẫn kèm theo repo

- [Kiến trúc hệ thống](diagram.png)
- [Sơ đồ tài sản](Assets%20Diagram.png)
- [Luồng mã hóa](Encrypt%20Flow.png)
- [Luồng giải mã](Decrypt%20Flow.png)
- [Setup Client](Setup%20Client.txt)
- [Cài PostgreSQL hỗ trợ TDE](Setup%20Postgres%20TDE%20trên%20Ubuntu.txt)
 
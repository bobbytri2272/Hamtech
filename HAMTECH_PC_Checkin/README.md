# HAMTECH | PC Check-in - Phần mềm kiểm tra máy trước khi sửa

Phần mềm chuyên dụng dành riêng cho cửa hàng sửa chữa máy tính **HAMTECH**, hỗ trợ kỹ thuật viên kiểm tra phần cứng tự động, test lỗi thủ công chuyên sâu, quản lý thông tin tiếp nhận máy, định giá dịch vụ và xuất phiếu báo cáo kiêm mã QR bảo hành điện tử hoạt động **100% ngoại tuyến (Offline)**.

---

## 📂 1. Cấu trúc thư mục dự án
Để phần mềm hoạt động ổn định và build thành công file `.exe` bằng bộ script đóng gói, cấu trúc thư mục làm việc được sắp xếp như sau:

```text
📁 HAMTECH_PC_Checkin/
│
├── 📄 pc_checkin.py          # Mã nguồn chính của phần mềm (Python + Tkinter)
├── 📄 build_exe.bat          # Script tự động đóng gói ứng dụng bằng PyInstaller
├── 🖼️ hamtech.ico            # File biểu tượng (Icon) của phần mềm
│
├── 📁 tools/                 # Thư mục chứa các công cụ phần cứng bổ trợ
│   ├── 📁 Core Temp/         # Thư mục chứa Core Temp.exe (đọc nhiệt độ CPU thực tế)
│   ├── 📁 smartctl.exe/       # Công cụ đọc sức khỏe ổ cứng S.M.A.R.T (Hỗ trợ NVMe/SSD/HDD)
│   └── 📄 qrious.min.js      # Thư viện JavaScript nhúng ngầm để tạo mã QR Offline
│
└── 📁 BaoCao/                # (Tự động tạo) Thư mục lưu các phiếu báo cáo HTML và công cụ so sánh
```

---

## ⚙️ 2. Chuẩn bị trước khi Chạy hoặc Build App
Trước khi chạy mã nguồn hoặc đóng gói thành file `.exe`, hãy đảm bảo các công cụ hỗ trợ đã nằm đúng vị trí trong thư mục `tools/`:
1. **Core Temp:** Đặt thư mục `Core Temp` (có chứa file `Core Temp.exe`) vào trong `tools\`.
2. **Smartctl:** Đặt thư mục `smartctl` (có chứa file `smartctl.exe` hoặc `smartctl-nc.exe`) vào trong `tools\`.
3. **Qrious JS:** Đặt file `qrious.min.js` vào trong `tools\` để phục vụ tính năng vẽ mã QR ngoại tuyến.
4. **Icon:** Đặt file `hamtech.ico` ngang hàng với file `.py` (nếu không có, ứng dụng sẽ dùng icon mặc định của hệ thống).

---

## 🚀 3. Hướng dẫn Chạy ứng dụng trực tiếp (Chế độ phát triển)
1. Yêu cầu máy tính đã cài đặt **Python 3.11** hoặc **Python 3.12** (Nhớ tích chọn *"Add python.exe to PATH"* khi cài đặt).
2. Mở cửa sổ dòng lệnh tại thư mục chứa mã nguồn và chạy lệnh:
   ```bash
   python pc_checkin.py
   ```

---

## 📦 4. Hướng dẫn Build App ra file `.exe` (Đóng gói toàn diện)
Bộ công cụ đã tích hợp sẵn script tự động hóa `build_exe.bat`. Bạn chỉ cần thực hiện:
1. Nhấp đúp chuột vào file **`build_exe.bat`**.
2. Script sẽ tự động thực hiện các bước sau:
   - Kiểm tra môi trường Python.
   - Cài đặt/Nâng cấp các gói phụ thuộc (`PyInstaller`, `Pillow`).
   - Đóng gói toàn bộ mã nguồn, kèm theo `Core Temp`, `smartctl`, thư viện `qrious.min.js` và Icon vào bên trong **một file `.exe` duy nhất** nhờ cờ `--add-data`.
3. Sau khi hoàn tất, file thực thi thành phẩm sẽ nằm tại:
   `📁 dist\HAMTECH_PC_Checkin.exe`

---

## 📋 5. Các tính năng nổi bật & Đặc điểm kỹ thuật
* **Quét cấu hình phần cứng tự động:** Đọc chi tiết thông tin Mainboard, BIOS, CPU, RAM (phân biệt rõ RAM rời hay Onboard hàn chết trên main), GPU (tự động nhận diện card tích hợp và card rời, theo dõi trực tiếp nhiệt độ/xung qua `nvidia-smi`), ổ cứng (SMART chi tiết qua `smartctl`), pin và thiết bị ngoại vi.
* **Trung tâm Test lỗi thủ công tách biệt:** Cho phép kỹ thuật viên mở một cửa sổ test riêng biệt để kiểm tra bàn phím (sáng xanh từng phím), màn hình (test điểm chết/hở sáng), touchpad, loa (trái/phải/cả hai), micro (ghi âm và phát lại), webcam và chạy tải 100% CPU (Stress Test) có giám sát nhiệt độ Realtime qua Core Temp.
* **Báo cáo HTML ngoại tuyến kiêm Mã QR Tình Trạng Máy:**
  - Xuất file báo cáo HTML giao diện đẹp mắt, chuyên nghiệp.
  - Tích hợp **Mã QR Offline kích thước lớn (260px)** hiển thị đầy đủ các thông tin cốt lõi ngay trên phiếu:
    - Tiêu đề: `HAMTECH - Tiep Nhan May`
    - Hotline: `0888 123 223`
    - Tên khách hàng (`KH`), Số điện thoại (`SDT`), Model Máy, Phụ kiện kèm theo (`Accessories`), Kỹ thuật viên (`KTV`), Báo giá dịch vụ (`Bao gia`), Thống kê lỗi/cảnh báo (`Error`/`Warning`) và Ngày giờ (`Date`).
  - Toàn bộ mã nguồn tạo mã QR đã được nhúng cục bộ bằng `qrious.min.js`, giúp điện thoại của khách hàng quét mã **nhận diện và hiển thị bình thường ngay cả khi hoàn toàn không có kết nối Internet**.
* **So sánh báo cáo thông minh:** Hỗ trợ tính năng đối chiếu nhanh giữa hai phiếu báo cáo cũ và mới để kiểm tra sự thay đổi về linh kiện hoặc tình trạng lỗi của máy.
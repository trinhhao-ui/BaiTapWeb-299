$(document).ready(function() {
    // 1. Hiển thị thông tin người dùng nếu đang ở trang profile
    if ($('#profile').length > 0) {
        if (!localStorage.token) {
            alert("Sorry, you are not logged in.");
            window.location.href = "/login";
            return;
        }

        $.ajax({
            type: 'GET',
            url: '/users/me',
            dataType: 'json',
            contentType: 'application/json; charset=utf-8',
            beforeSend: function(xhr) {
                if (localStorage.token) {
                    xhr.setRequestHeader('Authorization', 'Bearer ' + localStorage.token);
                }
            },
            success: function(data) {
                $('#profile').html('Xin chào: <strong>' + data.fullName + '</strong> (Email: ' + data.email + ')');
                if (data.images) {
                    $('#images').attr('src', data.images).show();
                }
            },
            error: function(xhr) {
                alert("Phiên đăng nhập đã hết hạn hoặc không hợp lệ.");
                localStorage.clear();
                window.location.href = "/login";
            }
        });
    }

    // 2. Hàm đăng xuất
    $('#logout').click(function() {
        localStorage.clear();
        window.location.href = "/login";
    });

    // 3. Hàm Login
    function doLogin() {
        var email = $.trim($('#email').val());
        var password = $('#password').val();

        if (!email || !password) {
            alert('Vui lòng nhập đầy đủ Email và Password');
            return;
        }

        var basicInfo = JSON.stringify({
            email: email,
            password: password
        });

        $.ajax({
            type: 'POST',
            url: '/auth/login',
            dataType: 'json',
            contentType: 'application/json; charset=utf-8',
            data: basicInfo,
            success: function(data) {
                localStorage.token = data.token;
                window.location.href = "/user/profile";
            },
            error: function(xhr) {
                var msg = "Login Failed";
                if (xhr.responseJSON && xhr.responseJSON.description) {
                    msg += ": " + xhr.responseJSON.description;
                } else if (xhr.status === 401) {
                    msg += ": Email hoặc mật khẩu không chính xác";
                }
                alert(msg);
            }
        });
    }

    $('#login').click(function(e) {
        e.preventDefault();
        doLogin();
    });

    $('#loginForm').submit(function(e) {
        e.preventDefault();
        doLogin();
    });
});

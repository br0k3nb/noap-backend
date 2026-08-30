pub fn mail_html(otp: &str, user_name: &str) -> String {
    format!(
        r#"
        <!DOCTYPE html>
        <html><head><meta charset="UTF-8"><title>Noap OTP</title></head>
        <body style="font-family:Arial,sans-serif;background:#FFFFFF;padding:0;margin:0">
        <div style="max-width:600px;margin:0 auto;background:#EFEFEF;border-radius:20px;padding:40px">
        <h3 style="color:#2D3142">Hi, {user_name}!</h3>
        <p>Here is your OTP code, please <strong>DO NOT SHARE WITH ANYONE</strong></p>
        <div style="background:#e71e0a;border-radius:50px;padding:20px;text-align:center;color:#fff;font-size:39px;font-family:monospace">{otp}</div>
        <p>Thanks,<br>Noap team</p>
        <p style="font-size:14px;color:#2D3142">This code expire in 1 hour.</p>
        </div></body></html>
    "#,
        user_name = user_name,
        otp = otp
    )
}

const nodemailer = require('nodemailer');

module.exports = async (email, subject, text) => {
	try {
		const transporter = nodemailer.createTransport({
			service: 'gmail',
			host: 'smtp.gmail.com',
			port: 465,
			secure: true, // use SSL
			auth: {
				user: process.env.EMAIL_USER,
				pass: process.env.EMAIL_PASS,
			},
		});

		// Verify connection configuration
		await transporter.verify();
		console.log('SMTP connection verified');

		const mailOptions = {
			from: `"HiMe Chat" <${process.env.EMAIL_USER}>`,
			to: email,
			subject: subject,
			html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="text-align: center; background-color: #0078D7; padding: 20px; color: white; border-radius: 8px 8px 0 0;">
                <h1 style="margin: 0; font-size: 24px;">HiMe Chat</h1>
            </div>
            <div style="padding: 20px; background-color: #f9f9f9; border-radius: 0 0 8px 8px;">
                <p style="font-size: 16px;">Dear User,</p>
                <p style="font-size: 16px;">${text}</p>
                
                <p style="font-size: 16px;">If you have any questions, feel free to reach out to our support team.</p>
                <p style="font-size: 16px;">Best regards,<br/>HiMe Chat Team</p>
                <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;" />
                <p style="font-size: 12px; color: #666; text-align: center;">
                    Please do not reply to this email. This mailbox is not monitored.<br/>
                    &copy; ${new Date().getFullYear()} HiMe Chat. All rights reserved.
                </p>
            </div>
        </div>
    `,
			priority: 'high',
		};

		const info = await transporter.sendMail(mailOptions);
		// console.log('Email sent successfully:', info.messageId);
		return info;
	} catch (error) {
		console.error('Email sending failed:', {
			errorCode: error.code,
			errorMessage: error.message,
			response: error.response,
		});
		throw error;
	}
};

import nodemailer from 'nodemailer';

interface SendEmailParams {
  to: string;
  subject: string;
  html: string;
  replyTo?: string;
  senderName?: string;
  attachments?: any[];
}

export async function sendEmail({
  to,
  subject,
  html,
  replyTo,
  senderName,
  attachments
}: SendEmailParams) {
  try {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    const finalSenderName = senderName ? senderName : "CredCheck System";

    const info = await transporter.sendMail({
      from: `"${finalSenderName}" <${process.env.SMTP_USER}>`,
      to,
      subject,
      html,
      replyTo,
      attachments,
    });

    console.log("Email sent successfully: %s", info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error("Error sending email:", error);
    return { success: false, error };
  }
}

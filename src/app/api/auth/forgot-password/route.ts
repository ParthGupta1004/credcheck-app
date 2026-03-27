import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { v4 as uuidv4 } from "uuid";

// POST - Request password reset
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { email } = body;

    if (!email) {
      return NextResponse.json(
        { error: "Email is required" },
        { status: 400 }
      );
    }

    const normalizedEmail = email.toLowerCase();

    // Find user by email
    const user = await db.user.findUnique({
      where: { email: normalizedEmail },
    });

    // Always return success even if user doesn't exist (security best practice)
    // This prevents email enumeration
    if (!user) {
      return NextResponse.json({
        message: "If an account with that email exists, we've sent a reset link.",
      });
    }

    // Check if user has password (might be OAuth-only user)
    if (!user.password) {
      return NextResponse.json({
        message: "If an account with that email exists, we've sent a reset link.",
      });
    }

    // Delete any existing reset tokens for this user
    await db.verificationToken.deleteMany({
      where: { identifier: normalizedEmail },
    });

    // Generate new reset token
    const token = uuidv4();
    const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Store token in database
    await db.verificationToken.create({
      data: {
        identifier: normalizedEmail,
        token,
        expires,
      },
    });

    const resetUrl = `${process.env.NEXTAUTH_URL || "http://localhost:3000"}/reset-password?token=${token}`;

    // Send reset email
    const html = `
      <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px;">
        <h2 style="color: #10b981; text-align: center;">Reset Your Password</h2>
        <p>Hello,</p>
        <p>We received a request to reset your password for your <strong>CredCheck</strong> account. Click the button below to set a new password:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}" style="display:inline-block; padding: 12px 24px; background-color: #10b981; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">Reset Password</a>
        </div>
        <p style="color: #6b7280; font-size: 14px;">If you didn't request this, you can safely ignore this email. This link will expire in 1 hour.</p>
        <hr style="border: 0; border-top: 1px solid #e5e7eb; margin: 20px 0;">
        <p style="font-size: 12px; color: #9ca3af; text-align: center;">
          Thanks,<br>
          <strong>CredCheck Team</strong>
        </p>
      </div>
    `;

    // Send email in background
    const { sendEmail } = await import("@/backend/lib/mail");
    sendEmail({
      to: normalizedEmail,
      subject: "Reset Your Password - CredCheck",
      html,
    }).catch(err => console.error("Failed to send reset email:", err));

    return NextResponse.json({
      message: "If an account with that email exists, we've sent a reset link.",
    });
  } catch (error) {
    console.error("Error in forgot password:", error);
    return NextResponse.json(
      { error: "An unexpected error occurred" },
      { status: 500 }
    );
  }
}

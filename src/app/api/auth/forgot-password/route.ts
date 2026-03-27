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

    // In a production app, you would send an email here
    // For now, we'll just return the token in development
    const resetUrl = `${process.env.NEXTAUTH_URL || "http://localhost:3000"}/reset-password?token=${token}`;

    // Log the reset URL for development purposes
    console.log(`Password reset URL for ${normalizedEmail}: ${resetUrl}`);

    return NextResponse.json({
      message: "If an account with that email exists, we've sent a reset link.",
      // Only include reset URL in development
      ...(process.env.NODE_ENV === "development" && { resetUrl }),
    });
  } catch (error) {
    console.error("Error in forgot password:", error);
    return NextResponse.json(
      { error: "An unexpected error occurred" },
      { status: 500 }
    );
  }
}

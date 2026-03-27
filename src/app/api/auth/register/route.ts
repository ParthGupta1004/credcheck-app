import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { db } from "@/lib/db";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { name, email, password, role } = body;

    // Validate input
    if (!email || !password || !name) {
      return NextResponse.json(
        { error: "Missing required fields" },
        { status: 400 }
      );
    }

    // Validate role
    const validRoles = ["student", "verifier", "admin"];
    let userRole = validRoles.includes(role) ? role : "student";

    // If attempting to be an admin, check if ANY user already exists
    if (userRole === "admin") {
      const userCount = await db.user.count();
      if (userCount > 0) {
        // Not the first user! Downgrade to student for security
        userRole = "student";
      }
    }

    // Check if user already exists
    const existingUser = await db.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (existingUser) {
      return NextResponse.json(
        { error: "User with this email already exists" },
        { status: 400 }
      );
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = await db.user.create({
      data: {
        name,
        email: email.toLowerCase(),
        password: hashedPassword,
        role: userRole,
      },
    });

    // Return success (don't include password)
    const response = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    };

    // Notify all admins of new registration
    try {
      const admins = await db.user.findMany({
        where: { role: 'admin' }
      });
      
      if (admins.length > 0) {
        await Promise.all(admins.map(admin => 
          db.notification.create({
            data: {
              userId: admin.id,
              title: "New User Registered",
              message: `${user.name || user.email} has joined as a ${user.role}.`,
              type: "SYSTEM",
              link: "/dashboard/admin"
            }
          })
        ));
      }
    } catch (notifyError) {
      console.error("Failed to send admin notifications:", notifyError);
      // Don't fail registration if notifications fail
    }

    return NextResponse.json(response, { status: 201 });

  } catch (error) {
    console.error("Registration error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";

// POST - Create a new verifier request
export async function POST(request: NextRequest) {
  try {
    // Check if user is authenticated
    const session = await getServerSession(authOptions);
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: "You must be logged in to submit a verifier request" },
        { status: 401 }
      );
    }

    const body = await request.json();
    const { organizationName, organizationEmail, website, description, logoUrl } = body;

    // Validate required fields
    if (!organizationName || !organizationEmail || !description) {
      return NextResponse.json(
        { error: "Organization name, email, and description are required" },
        { status: 400 }
      );
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(organizationEmail)) {
      return NextResponse.json(
        { error: "Please provide a valid email address" },
        { status: 400 }
      );
    }

    // Validate organization email domain (not a public email)
    const publicDomains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"];
    const domain = organizationEmail.split("@")[1]?.toLowerCase();
    if (publicDomains.includes(domain)) {
      return NextResponse.json(
        { error: "Please use your organization email (not a personal email)" },
        { status: 400 }
      );
    }

    // Validate description length
    if (description.length < 50) {
      return NextResponse.json(
        { error: "Description must be at least 50 characters" },
        { status: 400 }
      );
    }

    // Check if user already has a pending request
    const existingPendingRequest = await db.verifierRequest.findFirst({
      where: {
        userId: session.user.id,
        status: "pending",
      },
    });

    if (existingPendingRequest) {
      return NextResponse.json(
        { error: "You already have a pending verifier request. Please wait for it to be reviewed." },
        { status: 400 }
      );
    }

    // Check if user is already a verifier
    if (session.user.role === "verifier") {
      return NextResponse.json(
        { error: "You are already a verifier" },
        { status: 400 }
      );
    }

    // Create the verifier request
    const verifierRequest = await db.verifierRequest.create({
      data: {
        userId: session.user.id,
        organizationName,
        organizationEmail,
        website: website || null,
        description,
        logoUrl: logoUrl || null,
        status: "pending",
      },
    });

    return NextResponse.json(
      {
        message: "Verifier request submitted successfully",
        request: {
          id: verifierRequest.id,
          organizationName: verifierRequest.organizationName,
          status: verifierRequest.status,
          requestedAt: verifierRequest.requestedAt,
        },
      },
      { status: 201 }
    );
  } catch (error) {
    console.error("Error creating verifier request:", error);
    return NextResponse.json(
      { error: "An unexpected error occurred. Please try again." },
      { status: 500 }
    );
  }
}

// GET - Get all verifier requests (admin only)
export async function GET() {
  try {
    const session = await getServerSession(authOptions);
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: "You must be logged in to view verifier requests" },
        { status: 401 }
      );
    }

    // Only admins can view all requests
    if (session.user.role !== "admin") {
      return NextResponse.json(
        { error: "You don't have permission to view all verifier requests" },
        { status: 403 }
      );
    }

    const requests = await db.verifierRequest.findMany({
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            image: true,
          },
        },
      },
      orderBy: {
        requestedAt: "desc",
      },
    });

    return NextResponse.json({ requests });
  } catch (error) {
    console.error("Error fetching verifier requests:", error);
    return NextResponse.json(
      { error: "An unexpected error occurred. Please try again." },
      { status: 500 }
    );
  }
}

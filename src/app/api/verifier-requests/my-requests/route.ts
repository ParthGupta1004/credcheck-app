import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";

// GET - Get the current user's verifier requests
export async function GET() {
  try {
    const session = await getServerSession(authOptions);
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: "You must be logged in to view your requests" },
        { status: 401 }
      );
    }

    const requests = await db.verifierRequest.findMany({
      where: {
        userId: session.user.id,
      },
      orderBy: {
        requestedAt: "desc",
      },
      select: {
        id: true,
        organizationName: true,
        organizationEmail: true,
        status: true,
        website: true,
        description: true,
        logoUrl: true,
        requestedAt: true,
        reviewedAt: true,
      },
    });

    return NextResponse.json({ requests });
  } catch (error) {
    console.error("Error fetching user verifier requests:", error);
    return NextResponse.json(
      { error: "An unexpected error occurred. Please try again." },
      { status: 500 }
    );
  }
}

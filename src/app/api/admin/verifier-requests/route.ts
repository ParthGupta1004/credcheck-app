import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET() {
  try {
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

    return NextResponse.json(requests);
  } catch (error) {
    console.error("Failed to fetch verifier requests:", error);
    return NextResponse.json(
      { error: "Failed to fetch verifier requests" },
      { status: 500 }
    );
  }
}

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;

    const verifierRequest = await db.verifierRequest.findUnique({
      where: { id },
      include: { user: true },
    });

    if (!verifierRequest) {
      return NextResponse.json(
        { error: "Verifier request not found" },
        { status: 404 }
      );
    }

    if (verifierRequest.status !== "pending") {
      return NextResponse.json(
        { error: "Request has already been processed" },
        { status: 400 }
      );
    }

    // Update the request status and user role
    const [updatedRequest] = await db.$transaction([
      db.verifierRequest.update({
        where: { id },
        data: {
          status: "approved",
          reviewedAt: new Date(),
        },
      }),
      db.user.update({
        where: { id: verifierRequest.userId },
        data: { role: "verifier" },
      }),
    ]);

    return NextResponse.json(updatedRequest);
  } catch (error) {
    console.error("Failed to approve verifier request:", error);
    return NextResponse.json(
      { error: "Failed to approve verifier request" },
      { status: 500 }
    );
  }
}

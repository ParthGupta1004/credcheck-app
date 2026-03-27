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

    const updatedRequest = await db.verifierRequest.update({
      where: { id },
      data: {
        status: "rejected",
        reviewedAt: new Date(),
      },
    });

    return NextResponse.json(updatedRequest);
  } catch (error) {
    console.error("Failed to reject verifier request:", error);
    return NextResponse.json(
      { error: "Failed to reject verifier request" },
      { status: 500 }
    );
  }
}

import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const body = await request.json();
    const { note } = body;

    const report = await db.abuseReport.findUnique({
      where: { id },
    });

    if (!report) {
      return NextResponse.json(
        { error: "Abuse report not found" },
        { status: 404 }
      );
    }

    if (report.status === "resolved") {
      return NextResponse.json(
        { error: "Report has already been resolved" },
        { status: 400 }
      );
    }

    const updatedReport = await db.abuseReport.update({
      where: { id },
      data: {
        status: "resolved",
        reviewedAt: new Date(),
      },
    });

    return NextResponse.json(updatedReport);
  } catch (error) {
    console.error("Failed to resolve abuse report:", error);
    return NextResponse.json(
      { error: "Failed to resolve abuse report" },
      { status: 500 }
    );
  }
}

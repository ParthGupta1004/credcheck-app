import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET() {
  try {
    const reports = await db.abuseReport.findMany({
      include: {
        reporter: {
          select: {
            id: true,
            name: true,
            email: true,
            image: true,
          },
        },
        certificate: {
          select: {
            id: true,
            title: true,
            organization: true,
            publicLinkId: true,
            student: {
              select: {
                name: true,
                email: true,
              },
            },
          },
        },
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    return NextResponse.json(reports);
  } catch (error) {
    console.error("Failed to fetch abuse reports:", error);
    return NextResponse.json(
      { error: "Failed to fetch abuse reports" },
      { status: 500 }
    );
  }
}

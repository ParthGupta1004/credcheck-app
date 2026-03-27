import { NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET() {
  try {
    const [
      totalUsers,
      totalCertificates,
      totalVerifiers,
      pendingVerifierRequests,
      pendingAbuseReports,
    ] = await Promise.all([
      db.user.count(),
      db.certificate.count(),
      db.user.count({
        where: { role: "verifier" },
      }),
      db.verifierRequest.count({
        where: { status: "pending" },
      }),
      db.abuseReport.count({
        where: { status: "pending" },
      }),
    ]);

    return NextResponse.json({
      totalUsers,
      totalCertificates,
      totalVerifiers,
      pendingRequests: pendingVerifierRequests + pendingAbuseReports,
    });
  } catch (error) {
    console.error("Failed to fetch stats:", error);
    return NextResponse.json(
      { error: "Failed to fetch statistics" },
      { status: 500 }
    );
  }
}

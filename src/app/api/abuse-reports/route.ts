import { NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { db } from "@/lib/db";

export async function POST(req: Request) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await req.json();
    const { certificateId, reason } = body;

    if (!certificateId || !reason) {
      return NextResponse.json(
        { error: "Missing required fields" },
        { status: 400 }
      );
    }

    const report = await db.abuseReport.create({
      data: {
        certificateId,
        reporterId: session.user.id,
        reason,
        status: "pending",
      },
      include: {
        certificate: {
          select: { title: true }
        }
      }
    });

    // Notify all admins of new abuse report
    try {
      const admins = await db.user.findMany({
        where: { role: 'admin' }
      });
      
      if (admins.length > 0) {
        await Promise.all(admins.map(admin => 
          db.notification.create({
            data: {
              userId: admin.id,
              title: "Abuse Report Filed",
              message: `A new abuse report has been filed for "${report.certificate.title}".`,
              type: "SYSTEM",
              link: "/dashboard/admin"
            }
          })
        ));
      }
    } catch (notifyError) {
      console.error("Failed to send admin notifications for abuse report:", notifyError);
    }

    return NextResponse.json(report, { status: 201 });
  } catch (error) {
    console.error("Failed to create abuse report:", error);
    return NextResponse.json(
      { error: "Failed to create abuse report" },
      { status: 500 }
    );
  }
}
